kube-apiserver bootstrap-controller
===================================

Table of Contents
=================

* [bootstrap-controller概述](#bootstrap-controller概述)
* [代码分析](#代码分析)
  * [NewBootstrapController](#newbootstrapcontroller)
  * [BootstrapController.PostStartHook](#bootstrapcontrollerpoststarthook)
    * [RunKubernetesNamespaces](#runkubernetesnamespaces)
    * [RunKubernetesService](#runkubernetesservice)
    * [repairClusterIPs.RunUntil](#repairclusteripsrununtil)
    * [repairNodePorts.RunUntil](#repairnodeportsrununtil)
  * [BootstrapController.PreShutdownHook](#bootstrapcontrollerpreshutdownhook)
* [总结](#总结)
* [Refs](#refs)
      
## bootstrap-controller概述

在 kubernetes，可以从集群外部和内部两种方式访问 kubernetes API，在集群外直接访问 apiserver 提供的 API，在集群内即 pod 中可以通过访问 service 为 kubernetes 的 ClusterIP。kubernetes 集群在初始化完成后就会创建一个 kubernetes service，该 service 是 kube-apiserver 创建并进行维护的，如下所示：

```bash
$ kubectl get svc
NAME             TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)           AGE
kubernetes       ClusterIP   10.96.0.1      <none>        443/TCP           36d

$ kubectl get ep kubernetes
NAME         ENDPOINTS                                                  AGE
kubernetes   192.168.60.21:6443,192.168.60.22:6443,192.168.60.23:6443   36d
```

内置的 kubernetes service 无法删除，其 ClusterIP 为通过 `--service-cluster-ip-range` 参数指定的 ip 段中的首个 ip，kubernetes endpoints 中的 ip 以及 port 可以通过 `--advertise-address` 和 `--secure-port` 启动参数来指定

```yaml
# /etc/kubernetes/manifests/kube-apiserver.yaml 
spec:
  containers:
  - command:
    - kube-apiserver
    - --advertise-address=192.168.60.21
    ...
    - --secure-port=6443
    - --service-cluster-ip-range=10.96.0.0/12
    - --service-node-port-range=80-32767
```

kubernetes service 是由 kube-apiserver 中的 bootstrap-controller 进行控制的，其主要以下几个功能：

- 创建 kubernetes service；
- 创建 default、kube-system 和 kube-public 以及 kube-node-lease 命名空间；
- 提供基于 Service ClusterIP 的修复及检查功能；
- 提供基于 Service NodePort 的修复及检查功能；

kubernetes service 默认使用 ClusterIP 对外暴露服务，若要使用 NodePort 的方式可在 kube-apiserver 启动时通过 `--kubernetes-service-node-port` 参数指定对应的端口

## 代码分析

bootstrap controller 的初始化以及启动是在 `CreateKubeAPIServer` 调用链的 `InstallLegacyAPI` 方法中完成的，bootstrap controller 的启停是由 apiserver 的 `PostStartHook` 和 `PreShutdownHook` 进行控制的

```go
// k8s.io/kubernetes/pkg/master/master.go:487
// InstallLegacyAPI will install the legacy APIs for the restStorageProviders if they are enabled.
func (m *Master) InstallLegacyAPI(c *completedConfig, restOptionsGetter generic.RESTOptionsGetter, legacyRESTStorageProvider corerest.LegacyRESTStorageProvider) error {
	legacyRESTStorage, apiGroupInfo, err := legacyRESTStorageProvider.NewLegacyRESTStorage(restOptionsGetter)
	if err != nil {
		return fmt.Errorf("error building core storage: %v", err)
	}

	controllerName := "bootstrap-controller"
	coreClient := corev1client.NewForConfigOrDie(c.GenericConfig.LoopbackClientConfig)
	bootstrapController := c.NewBootstrapController(legacyRESTStorage, coreClient, coreClient, coreClient, coreClient.RESTClient())
	m.GenericAPIServer.AddPostStartHookOrDie(controllerName, bootstrapController.PostStartHook)
	m.GenericAPIServer.AddPreShutdownHookOrDie(controllerName, bootstrapController.PreShutdownHook)

	if err := m.GenericAPIServer.InstallLegacyAPIGroup(genericapiserver.DefaultLegacyAPIPrefix, &apiGroupInfo); err != nil {
		return fmt.Errorf("error in registering group versions: %v", err)
	}
	return nil
}
```

postStartHooks 会在 kube-apiserver 的启动方法 `prepared.Run` 中调用 `RunPostStartHooks` 启动所有 Hook

```go
// NonBlockingRun spawns the secure http server. An error is
// returned if the secure port cannot be listened on.
func (s preparedGenericAPIServer) NonBlockingRun(stopCh <-chan struct{}) error {
	// Use an stop channel to allow graceful shutdown without dropping audit events
	// after http server shutdown.
	auditStopCh := make(chan struct{})

	// Start the audit backend before any request comes in. This means we must call Backend.Run
	// before http server start serving. Otherwise the Backend.ProcessEvents call might block.
	if s.AuditBackend != nil {
		if err := s.AuditBackend.Run(auditStopCh); err != nil {
			return fmt.Errorf("failed to run the audit backend: %v", err)
		}
	}

	// Use an internal stop channel to allow cleanup of the listeners on error.
	internalStopCh := make(chan struct{})
	var stoppedCh <-chan struct{}
	if s.SecureServingInfo != nil && s.Handler != nil {
		var err error
		stoppedCh, err = s.SecureServingInfo.Serve(s.Handler, s.ShutdownTimeout, internalStopCh)
		if err != nil {
			close(internalStopCh)
			close(auditStopCh)
			return err
		}
	}

	// Now that listener have bound successfully, it is the
	// responsibility of the caller to close the provided channel to
	// ensure cleanup.
	go func() {
		<-stopCh
		close(internalStopCh)
		if stoppedCh != nil {
			<-stoppedCh
		}
		s.HandlerChainWaitGroup.Wait()
		close(auditStopCh)
	}()

	s.RunPostStartHooks(stopCh)

	if _, err := systemd.SdNotify(true, "READY=1\n"); err != nil {
		klog.Errorf("Unable to send systemd daemon successful start message: %v\n", err)
	}

	return nil
}

// RunPostStartHooks runs the PostStartHooks for the server
func (s *GenericAPIServer) RunPostStartHooks(stopCh <-chan struct{}) {
	s.postStartHookLock.Lock()
	defer s.postStartHookLock.Unlock()
	s.postStartHooksCalled = true

	context := PostStartHookContext{
		LoopbackClientConfig: s.LoopbackClientConfig,
		StopCh:               stopCh,
	}

	for hookName, hookEntry := range s.postStartHooks {
		go runPostStartHook(hookName, hookEntry, context)
	}
}
```

这里我们先分析NewBootstrapController，再回过头来看

### NewBootstrapController

bootstrap controller 在初始化时需要设定多个参数，主要有 PublicIP、ServiceCIDR、PublicServicePort 等。PublicIP 是通过命令行参数 `--advertise-address` 指定的，PublicServicePort 通过 `--secure-port` 启动参数来指定（默认为 6443），ServiceCIDR 通过 `--service-cluster-ip-range` 参数指定（默认为 10.0.0.0/24）

```go
// k8s.io/kubernetes/pkg/master/controller.go:87
// NewBootstrapController returns a controller for watching the core capabilities of the master
func (c *completedConfig) NewBootstrapController(legacyRESTStorage corerest.LegacyRESTStorage, serviceClient corev1client.ServicesGetter, nsClient corev1client.NamespacesGetter, eventClient corev1client.EventsGetter, healthClient rest.Interface) *Controller {
	// 1、获取 PublicServicePort  
	_, publicServicePort, err := c.GenericConfig.SecureServing.HostPort()
	if err != nil {
		klog.Fatalf("failed to get listener address: %v", err)
	}

	// 2、指定需要创建的kube-system，kube-public以及kube-node-lease namespace
	systemNamespaces := []string{metav1.NamespaceSystem, metav1.NamespacePublic, corev1.NamespaceNodeLease}

	return &Controller{
		ServiceClient:   serviceClient,
		NamespaceClient: nsClient,
		EventClient:     eventClient,
		healthClient:    healthClient,

		EndpointReconciler: c.ExtraConfig.EndpointReconcilerConfig.Reconciler,
		EndpointInterval:   c.ExtraConfig.EndpointReconcilerConfig.Interval,

		SystemNamespaces:         systemNamespaces,
		SystemNamespacesInterval: 1 * time.Minute,

		ServiceClusterIPRegistry:          legacyRESTStorage.ServiceClusterIPAllocator,
		// ServiceCIDR 通过 --service-cluster-ip-range 参数指定  
		ServiceClusterIPRange:             c.ExtraConfig.ServiceIPRange,
		SecondaryServiceClusterIPRegistry: legacyRESTStorage.SecondaryServiceClusterIPAllocator,
		SecondaryServiceClusterIPRange:    c.ExtraConfig.SecondaryServiceIPRange,

		ServiceClusterIPInterval: 3 * time.Minute,

		ServiceNodePortRegistry: legacyRESTStorage.ServiceNodePortAllocator,
		ServiceNodePortRange:    c.ExtraConfig.ServiceNodePortRange,
		ServiceNodePortInterval: 3 * time.Minute,

		// API Server 绑定的IP，这个IP会作为kubernetes service的Endpoint的IP，通过--advertise-address指定   
		PublicIP: c.GenericConfig.PublicAddress,

		// 取 clusterIP range 中的第一个 IP    
		ServiceIP:                 c.ExtraConfig.APIServerServiceIP,
		// 默认为 443    
		ServicePort:               c.ExtraConfig.APIServerServicePort,
		ExtraServicePorts:         c.ExtraConfig.ExtraServicePorts,
		ExtraEndpointPorts:        c.ExtraConfig.ExtraEndpointPorts,
    // 通过--secure-port指定，默认为6443
		PublicServicePort:         publicServicePort,
		// 缺省是基于 ClusterIP 启动模式，这里为0    
		KubernetesServiceNodePort: c.ExtraConfig.KubernetesServiceNodePort,
	}
}
```

PublicIP 是通过命令行参数 `--advertise-address` 指定的；如果没有指定，系统会自动选出一个 global IP，其中选出 global IP的代码如下：

```go
// NewAPIServerCommand creates a *cobra.Command object with default parameters
func NewAPIServerCommand() *cobra.Command {
	s := options.NewServerRunOptions()
	cmd := &cobra.Command{
		Use: "kube-apiserver",
		Long: `The Kubernetes API server validates and configures data
for the api objects which include pods, services, replicationcontrollers, and
others. The API Server services REST operations and provides the frontend to the
cluster's shared state through which all other components interact.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			verflag.PrintAndExitIfRequested()
			utilflag.PrintFlags(cmd.Flags())

			// set default options
			completedOptions, err := Complete(s)
			if err != nil {
				return err
			}

			// validate options
			if errs := completedOptions.Validate(); len(errs) != 0 {
				return utilerrors.NewAggregate(errs)
			}

			return Run(completedOptions, genericapiserver.SetupSignalHandler())
		},
	}

	...

	return cmd
}

// Complete set default ServerRunOptions.
// Should be called after kube-apiserver flags parsed.
func Complete(s *options.ServerRunOptions) (completedServerRunOptions, error) {
	var options completedServerRunOptions
	// set defaults
	if err := s.GenericServerRunOptions.DefaultAdvertiseAddress(s.SecureServing.SecureServingOptions); err != nil {
		return options, err
	}
	if err := kubeoptions.DefaultAdvertiseAddress(s.GenericServerRunOptions, s.InsecureServing.DeprecatedInsecureServingOptions); err != nil {
		return options, err
	}

	// process s.ServiceClusterIPRange from list to Primary and Secondary
	// we process secondary only if provided by user
	apiServerServiceIP, primaryServiceIPRange, secondaryServiceIPRange, err := getServiceIPAndRanges(s.ServiceClusterIPRanges)
	if err != nil {
		return options, err
	}
	s.PrimaryServiceClusterIPRange = primaryServiceIPRange
	s.SecondaryServiceClusterIPRange = secondaryServiceIPRange

	if err := s.SecureServing.MaybeDefaultWithSelfSignedCerts(s.GenericServerRunOptions.AdvertiseAddress.String(), []string{"kubernetes.default.svc", "kubernetes.default", "kubernetes"}, []net.IP{apiServerServiceIP}); err != nil {
		return options, fmt.Errorf("error creating self-signed certificates: %v", err)
	}

	...
	options.ServerRunOptions = s
	return options, nil
}

// DefaultAdvertiseAddress sets the field AdvertiseAddress if unset. The field will be set based on the SecureServingOptions.
func (s *ServerRunOptions) DefaultAdvertiseAddress(secure *SecureServingOptions) error {
	if secure == nil {
		return nil
	}

	if s.AdvertiseAddress == nil || s.AdvertiseAddress.IsUnspecified() {
		hostIP, err := secure.DefaultExternalAddress()
		if err != nil {
			return fmt.Errorf("Unable to find suitable network address.error='%v'. "+
				"Try to set the AdvertiseAddress directly or provide a valid BindAddress to fix this.", err)
		}
		s.AdvertiseAddress = hostIP
	}

	return nil
}

func (s *SecureServingOptions) DefaultExternalAddress() (net.IP, error) {
	if s.ExternalAddress != nil && !s.ExternalAddress.IsUnspecified() {
		return s.ExternalAddress, nil
	}
	return utilnet.ResolveBindAddress(s.BindAddress)
}

// ResolveBindAddress returns the IP address of a daemon, based on the given bindAddress:
// If bindAddress is unset, it returns the host's default IP, as with ChooseHostInterface().
// If bindAddress is unspecified or loopback, it returns the default IP of the same
// address family as bindAddress.
// Otherwise, it just returns bindAddress.
func ResolveBindAddress(bindAddress net.IP) (net.IP, error) {
	addressFamilies := preferIPv4
	if bindAddress != nil && memberOf(bindAddress, familyIPv6) {
		addressFamilies = preferIPv6
	}

	if bindAddress == nil || bindAddress.IsUnspecified() || bindAddress.IsLoopback() {
		hostIP, err := chooseHostInterface(addressFamilies)
		if err != nil {
			return nil, err
		}
		bindAddress = hostIP
	}
	return bindAddress, nil
}

// k8s.io/kubernetes/vendor/k8s.io/apimachinery/pkg/util/net/interface.go:339
func chooseHostInterface(addressFamilies AddressFamilyPreference) (net.IP, error) {
	var nw networkInterfacer = networkInterface{}
	if _, err := os.Stat(ipv4RouteFile); os.IsNotExist(err) {
		return chooseIPFromHostInterfaces(nw, addressFamilies)
	}
	routes, err := getAllDefaultRoutes()
	if err != nil {
		return nil, err
	}
	return chooseHostInterfaceFromRoute(routes, nw, addressFamilies)
}

const (
	ipv4RouteFile = "/proc/net/route"
	ipv6RouteFile = "/proc/net/ipv6_route"
)

// chooseHostInterfaceFromRoute cycles through each default route provided, looking for a
// global IP address from the interface for the route. addressFamilies determines whether it
// prefers IPv4 or IPv6
func chooseHostInterfaceFromRoute(routes []Route, nw networkInterfacer, addressFamilies AddressFamilyPreference) (net.IP, error) {
	for _, family := range addressFamilies {
		klog.V(4).Infof("Looking for default routes with IPv%d addresses", uint(family))
		for _, route := range routes {
			if route.Family != family {
				continue
			}
			klog.V(4).Infof("Default route transits interface %q", route.Interface)
			finalIP, err := getIPFromInterface(route.Interface, family, nw)
			if err != nil {
				return nil, err
			}
			if finalIP != nil {
				klog.V(4).Infof("Found active IP %v ", finalIP)
				return finalIP, nil
			}
		}
	}
	klog.V(4).Infof("No active IP found by looking at default routes")
	return nil, fmt.Errorf("unable to select an IP from default routes.")
}
```

### BootstrapController.PostStartHook

上文提到过kube-apiserver会运行起来前调用BootstrapController.PostStartHook，该函数涵盖了bootstrapController的核心功能，主要包括：修复 ClusterIP、修复 NodePort、更新 kubernetes service以及创建系统所需要的名字空间（default、kube-system、kube-public）。bootstrap controller 在启动后首先会完成一次 ClusterIP、NodePort 和 Kubernets 服务的处理，然后异步循环运行上面的4个工作。以下是其 `PostStartHook`方法：

```go
// PostStartHook initiates the core controller loops that must exist for bootstrapping.
func (c *Controller) PostStartHook(hookContext genericapiserver.PostStartHookContext) error {
	c.Start()
	return nil
}

// k8s.io/kubernetes/pkg/master/controller.go:142
// Start begins the core controller loops that must exist for bootstrapping
// a cluster.
func (c *Controller) Start() {
	if c.runner != nil {
		return
	}

	// 1、首次启动时首先从 kubernetes endpoints 中移除自身的配置，此时 kube-apiserver 可能处于非 ready 状态
	// Reconcile during first run removing itself until server is ready.
	endpointPorts := createEndpointPortSpec(c.PublicServicePort, "https", c.ExtraEndpointPorts)
	if err := c.EndpointReconciler.RemoveEndpoints(kubernetesServiceName, c.PublicIP, endpointPorts); err != nil {
		klog.Errorf("Unable to remove old endpoints from kubernetes service: %v", err)
	}

	// 2、初始化 repairClusterIPs 和 repairNodePorts 对象  
	repairClusterIPs := servicecontroller.NewRepair(c.ServiceClusterIPInterval, c.ServiceClient, c.EventClient, &c.ServiceClusterIPRange, c.ServiceClusterIPRegistry, &c.SecondaryServiceClusterIPRange, c.SecondaryServiceClusterIPRegistry)
	repairNodePorts := portallocatorcontroller.NewRepair(c.ServiceNodePortInterval, c.ServiceClient, c.EventClient, c.ServiceNodePortRange, c.ServiceNodePortRegistry)

	// 3、首先运行一次 repairClusterIPs 和 repairNodePorts，即进行初始化  
	// run all of the controllers once prior to returning from Start.
	if err := repairClusterIPs.RunOnce(); err != nil {
		// If we fail to repair cluster IPs apiserver is useless. We should restart and retry.
		klog.Fatalf("Unable to perform initial IP allocation check: %v", err)
	}
	if err := repairNodePorts.RunOnce(); err != nil {
		// If we fail to repair node ports apiserver is useless. We should restart and retry.
		klog.Fatalf("Unable to perform initial service nodePort check: %v", err)
	}

  // 4、定期执行 bootstrap controller 主要的四个功能(reconciliation)  
	c.runner = async.NewRunner(c.RunKubernetesNamespaces, c.RunKubernetesService, repairClusterIPs.RunUntil, repairNodePorts.RunUntil)
	c.runner.Start()
}

// NewRunner makes a runner for the given function(s). The function(s) should loop until
// the channel is closed.
func NewRunner(f ...func(stop chan struct{})) *Runner {
	return &Runner{loopFuncs: f}
}

// Start begins running.
func (r *Runner) Start() {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.stop == nil {
		c := make(chan struct{})
		r.stop = &c
		for i := range r.loopFuncs {
			go r.loopFuncs[i](*r.stop)
		}
	}
}
```

下面我们依此展开分析这几个主要功能：

#### RunKubernetesNamespaces

`c.RunKubernetesNamespaces` 主要功能是通过createNamespaceIfNeeded创建 kube-system，kube-public 以及 kube-node-lease 命名空间，之后每隔一分钟检查一次：

```go
// NewBootstrapController returns a controller for watching the core capabilities of the master
func (c *completedConfig) NewBootstrapController(legacyRESTStorage corerest.LegacyRESTStorage, serviceClient corev1client.ServicesGetter, nsClient corev1client.NamespacesGetter, eventClient corev1client.EventsGetter, healthClient rest.Interface) *Controller {
	_, publicServicePort, err := c.GenericConfig.SecureServing.HostPort()
	if err != nil {
		klog.Fatalf("failed to get listener address: %v", err)
	}

	systemNamespaces := []string{metav1.NamespaceSystem, metav1.NamespacePublic, corev1.NamespaceNodeLease}

	return &Controller{
		ServiceClient:   serviceClient,
		NamespaceClient: nsClient,
		EventClient:     eventClient,
		healthClient:    healthClient,

		EndpointReconciler: c.ExtraConfig.EndpointReconcilerConfig.Reconciler,
		EndpointInterval:   c.ExtraConfig.EndpointReconcilerConfig.Interval,

		SystemNamespaces:         systemNamespaces,
		SystemNamespacesInterval: 1 * time.Minute,

		ServiceClusterIPRegistry:          legacyRESTStorage.ServiceClusterIPAllocator,
		ServiceClusterIPRange:             c.ExtraConfig.ServiceIPRange,
		SecondaryServiceClusterIPRegistry: legacyRESTStorage.SecondaryServiceClusterIPAllocator,
		SecondaryServiceClusterIPRange:    c.ExtraConfig.SecondaryServiceIPRange,

		ServiceClusterIPInterval: 3 * time.Minute,

		ServiceNodePortRegistry: legacyRESTStorage.ServiceNodePortAllocator,
		ServiceNodePortRange:    c.ExtraConfig.ServiceNodePortRange,
		ServiceNodePortInterval: 3 * time.Minute,

		PublicIP: c.GenericConfig.PublicAddress,

		ServiceIP:                 c.ExtraConfig.APIServerServiceIP,
		ServicePort:               c.ExtraConfig.APIServerServicePort,
		ExtraServicePorts:         c.ExtraConfig.ExtraServicePorts,
		ExtraEndpointPorts:        c.ExtraConfig.ExtraEndpointPorts,
		PublicServicePort:         publicServicePort,
		KubernetesServiceNodePort: c.ExtraConfig.KubernetesServiceNodePort,
	}
}

// RunKubernetesNamespaces periodically makes sure that all internal namespaces exist
func (c *Controller) RunKubernetesNamespaces(ch chan struct{}) {
	wait.Until(func() {
		// Loop the system namespace list, and create them if they do not exist
		for _, ns := range c.SystemNamespaces {
			if err := createNamespaceIfNeeded(c.NamespaceClient, ns); err != nil {
				runtime.HandleError(fmt.Errorf("unable to create required kubernetes system namespace %s: %v", ns, err))
			}
		}
	}, c.SystemNamespacesInterval, ch)
}

// k8s.io/kubernetes/pkg/master/client_util.go:27
func createNamespaceIfNeeded(c corev1client.NamespacesGetter, ns string) error {
	if _, err := c.Namespaces().Get(context.TODO(), ns, metav1.GetOptions{}); err == nil {
		// the namespace already exists
		return nil
	}
	newNs := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ns,
			Namespace: "",
		},
	}
	_, err := c.Namespaces().Create(context.TODO(), newNs, metav1.CreateOptions{})
	if err != nil && errors.IsAlreadyExists(err) {
		err = nil
	}
	return err
}
```

#### RunKubernetesService

`c.RunKubernetesService` 主要是检查 kubernetes service 是否处于正常状态，并定期执行同步操作。首先调用 `/healthz` 接口检查 apiserver 当前是否处于 ready 状态，若处于 ready 状态然后调用 `c.UpdateKubernetesService` 服务更新 kubernetes service 状态

```
// RunKubernetesService periodically updates the kubernetes service
func (c *Controller) RunKubernetesService(ch chan struct{}) {
   // wait until process is ready
   wait.PollImmediateUntil(100*time.Millisecond, func() (bool, error) {
      var code int
      c.healthClient.Get().AbsPath("/healthz").Do(context.TODO()).StatusCode(&code)
      return code == http.StatusOK, nil
   }, ch)

   wait.NonSlidingUntil(func() {
      // Service definition is not reconciled after first
      // run, ports and type will be corrected only during
      // start.
      if err := c.UpdateKubernetesService(false); err != nil {
         runtime.HandleError(fmt.Errorf("unable to sync kubernetes service: %v", err))
      }
   }, c.EndpointInterval, ch)
}
```

`c.UpdateKubernetesService` 的主要逻辑为：

- 1、调用 `createNamespaceIfNeeded` 创建 default namespace；
- 2、调用 `c.CreateOrUpdateMasterServiceIfNeeded` 为 master 创建 kubernetes service；
- 3、调用 `c.EndpointReconciler.ReconcileEndpoints` 更新 master 的 endpoint；

```go
// UpdateKubernetesService attempts to update the default Kube service.
func (c *Controller) UpdateKubernetesService(reconcile bool) error {
	// Update service & endpoint records.
	// TODO: when it becomes possible to change this stuff,
	// stop polling and start watching.
	// TODO: add endpoints of all replicas, not just the elected master.
	if err := createNamespaceIfNeeded(c.NamespaceClient, metav1.NamespaceDefault); err != nil {
		return err
	}

	servicePorts, serviceType := createPortAndServiceSpec(c.ServicePort, c.PublicServicePort, c.KubernetesServiceNodePort, "https", c.ExtraServicePorts)
	if err := c.CreateOrUpdateMasterServiceIfNeeded(kubernetesServiceName, c.ServiceIP, servicePorts, serviceType, reconcile); err != nil {
		return err
	}
	endpointPorts := createEndpointPortSpec(c.PublicServicePort, "https", c.ExtraEndpointPorts)
	if err := c.EndpointReconciler.ReconcileEndpoints(kubernetesServiceName, c.PublicIP, endpointPorts, reconcile); err != nil {
		return err
	}
	return nil
}
```

这里通过createPortAndServiceSpec创建了ServicePort，为Kubernetes default service的创建做准备

```go
// createPortAndServiceSpec creates an array of service ports.
// If the NodePort value is 0, just the servicePort is used, otherwise, a node port is exposed.
func createPortAndServiceSpec(servicePort int, targetServicePort int, nodePort int, servicePortName string, extraServicePorts []corev1.ServicePort) ([]corev1.ServicePort, corev1.ServiceType) {
	//Use the Cluster IP type for the service port if NodePort isn't provided.
	//Otherwise, we will be binding the master service to a NodePort.
	servicePorts := []corev1.ServicePort{{Protocol: corev1.ProtocolTCP,
		Port:       int32(servicePort),
		Name:       servicePortName,
		TargetPort: intstr.FromInt(targetServicePort)}}
	serviceType := corev1.ServiceTypeClusterIP
	if nodePort > 0 {
		servicePorts[0].NodePort = int32(nodePort)
		serviceType = corev1.ServiceTypeNodePort
	}
	if extraServicePorts != nil {
		servicePorts = append(servicePorts, extraServicePorts...)
	}
	return servicePorts, serviceType
}
```

创建完成后如下：

```yaml
  ports:
  - name: https
    port: 443
    protocol: TCP
    targetPort: 6443
```

接着掉用CreateOrUpdateMasterServiceIfNeeded创建kubernetes default service：

```go
const kubernetesServiceName = "kubernetes"

// CreateOrUpdateMasterServiceIfNeeded will create the specified service if it
// doesn't already exist.
func (c *Controller) CreateOrUpdateMasterServiceIfNeeded(serviceName string, serviceIP net.IP, servicePorts []corev1.ServicePort, serviceType corev1.ServiceType, reconcile bool) error {
	if s, err := c.ServiceClient.Services(metav1.NamespaceDefault).Get(context.TODO(), serviceName, metav1.GetOptions{}); err == nil {
		// The service already exists.
		if reconcile {
			if svc, updated := reconcilers.GetMasterServiceUpdateIfNeeded(s, servicePorts, serviceType); updated {
				klog.Warningf("Resetting master service %q to %#v", serviceName, svc)
				_, err := c.ServiceClient.Services(metav1.NamespaceDefault).Update(context.TODO(), svc, metav1.UpdateOptions{})
				return err
			}
		}
		return nil
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: metav1.NamespaceDefault,
			Labels:    map[string]string{"provider": "kubernetes", "component": "apiserver"},
		},
		Spec: corev1.ServiceSpec{
			Ports: servicePorts,
			// maintained by this code, not by the pod selector
			Selector:        nil,
			ClusterIP:       serviceIP.String(),
			SessionAffinity: corev1.ServiceAffinityNone,
			Type:            serviceType,
		},
	}

	_, err := c.ServiceClient.Services(metav1.NamespaceDefault).Create(context.TODO(), svc, metav1.CreateOptions{})
	if errors.IsAlreadyExists(err) {
		return c.CreateOrUpdateMasterServiceIfNeeded(serviceName, serviceIP, servicePorts, serviceType, reconcile)
	}
	return err
}
```

逻辑很清晰，先判断是否存在default kubernetes service，如果不存在则创建该service：

```yaml
apiVersion: v1
kind: Service
metadata:
  labels:
    component: apiserver
    provider: kubernetes
  name: kubernetes
  namespace: default
spec:
  clusterIP: 10.96.0.1
  ports:
  - name: https
    port: 443
    protocol: TCP
    targetPort: 6443
  sessionAffinity: None
  type: ClusterIP
```

注意这里spec.selector为空，这是default kubernetes service与其它正常service的最大区别，表明了这个特殊的service对应的endpoints不由endpoints controller控制，而是直接受kube-apiserver bootstrap-controller管理(maintained by this code, not by the pod selector)

在创建完default kubernetes service之后，会构建default kubernetes endpoint(c.EndpointReconciler.ReconcileEndpoints)

EndpointReconciler 的具体实现由 `EndpointReconcilerType` 决定，`EndpointReconcilerType` 是 `--endpoint-reconciler-type` 参数指定的，可选的参数有 `master-count, lease, none`，每种类型对应不同的 EndpointReconciler 实例，在 v1.18 中默认为 lease，此处仅分析 lease 对应的 EndpointReconciler 的实现

一个集群中可能会有多个 apiserver 实例，因此需要统一管理 apiserver service 的 endpoints，`c.EndpointReconciler.ReconcileEndpoints` 就是用来管理 apiserver endpoints 的。一个集群中 apiserver 的所有实例会在 etcd 中的对应目录下创建 key，并定期更新这个 key 来上报自己的心跳信息，ReconcileEndpoints 会从 etcd 中获取 apiserver 的实例信息并更新 endpoint：

```go
// createEndpointPortSpec creates an array of endpoint ports
func createEndpointPortSpec(endpointPort int, endpointPortName string, extraEndpointPorts []corev1.EndpointPort) []corev1.EndpointPort {
	endpointPorts := []corev1.EndpointPort{{Protocol: corev1.ProtocolTCP,
		Port: int32(endpointPort),
		Name: endpointPortName,
	}}
	if extraEndpointPorts != nil {
		endpointPorts = append(endpointPorts, extraEndpointPorts...)
	}
	return endpointPorts
}

// NewLeaseEndpointReconciler creates a new LeaseEndpoint reconciler
func NewLeaseEndpointReconciler(epAdapter EndpointsAdapter, masterLeases Leases) EndpointReconciler {
	return &leaseEndpointReconciler{
		epAdapter:             epAdapter,
		masterLeases:          masterLeases,
		stopReconcilingCalled: false,
	}
}

func (c *Config) createLeaseReconciler() reconcilers.EndpointReconciler {
	endpointClient := corev1client.NewForConfigOrDie(c.GenericConfig.LoopbackClientConfig)
	var endpointSliceClient discoveryclient.EndpointSlicesGetter
	if utilfeature.DefaultFeatureGate.Enabled(features.EndpointSlice) {
		endpointSliceClient = discoveryclient.NewForConfigOrDie(c.GenericConfig.LoopbackClientConfig)
	}
	endpointsAdapter := reconcilers.NewEndpointsAdapter(endpointClient, endpointSliceClient)

	ttl := c.ExtraConfig.MasterEndpointReconcileTTL
	config, err := c.ExtraConfig.StorageFactory.NewConfig(api.Resource("apiServerIPInfo"))
	if err != nil {
		klog.Fatalf("Error determining service IP ranges: %v", err)
	}
	leaseStorage, _, err := storagefactory.Create(*config)
	if err != nil {
		klog.Fatalf("Error creating storage factory: %v", err)
	}
	masterLeases := reconcilers.NewLeases(leaseStorage, "/masterleases/", ttl)

	return reconcilers.NewLeaseEndpointReconciler(endpointsAdapter, masterLeases)
}

func (c *Config) createEndpointReconciler() reconcilers.EndpointReconciler {
	klog.Infof("Using reconciler: %v", c.ExtraConfig.EndpointReconcilerType)
	switch c.ExtraConfig.EndpointReconcilerType {
	// there are numerous test dependencies that depend on a default controller
	case "", reconcilers.MasterCountReconcilerType:
		return c.createMasterCountReconciler()
	case reconcilers.LeaseEndpointReconcilerType:
		return c.createLeaseReconciler()
	case reconcilers.NoneEndpointReconcilerType:
		return c.createNoneReconciler()
	default:
		klog.Fatalf("Reconciler not implemented: %v", c.ExtraConfig.EndpointReconcilerType)
	}
	return nil
}

// ReconcileEndpoints lists keys in a special etcd directory.
// Each key is expected to have a TTL of R+n, where R is the refresh interval
// at which this function is called, and n is some small value.  If an
// apiserver goes down, it will fail to refresh its key's TTL and the key will
// expire. ReconcileEndpoints will notice that the endpoints object is
// different from the directory listing, and update the endpoints object
// accordingly.
func (r *leaseEndpointReconciler) ReconcileEndpoints(serviceName string, ip net.IP, endpointPorts []corev1.EndpointPort, reconcilePorts bool) error {
	r.reconcilingLock.Lock()
	defer r.reconcilingLock.Unlock()

	if r.stopReconcilingCalled {
		return nil
	}

	// 更新masterleases key TTL
	// Refresh the TTL on our key, independently of whether any error or
	// update conflict happens below. This makes sure that at least some of
	// the masters will add our endpoint.
	if err := r.masterLeases.UpdateLease(ip.String()); err != nil {
		return err
	}

	return r.doReconcile(serviceName, endpointPorts, reconcilePorts)
}

func (r *leaseEndpointReconciler) doReconcile(serviceName string, endpointPorts []corev1.EndpointPort, reconcilePorts bool) error {
	// 获取default kubernetes endpoints  
	e, err := r.epAdapter.Get(corev1.NamespaceDefault, serviceName, metav1.GetOptions{})
	shouldCreate := false
	if err != nil {
		if !errors.IsNotFound(err) {
			return err
		}

		// 如果不存在，则创建endpoints    
		shouldCreate = true
		e = &corev1.Endpoints{
			ObjectMeta: metav1.ObjectMeta{
				Name:      serviceName,
				Namespace: corev1.NamespaceDefault,
			},
		}
	}
	
  // 从etcd中获取master IP keys(代表了kube-apiserver数目)  
	// ... and the list of master IP keys from etcd
	masterIPs, err := r.masterLeases.ListLeases()
	if err != nil {
		return err
	}
	  
	// Since we just refreshed our own key, assume that zero endpoints
	// returned from storage indicates an issue or invalid state, and thus do
	// not update the endpoints list based on the result.
	if len(masterIPs) == 0 {
		return fmt.Errorf("no master IPs were listed in storage, refusing to erase all endpoints for the kubernetes service")
	}

	// 将dafault kubernetes endpoint与masterIP列表以及端口列表进行比较，验证已经存在的endpoint有效性
	// Next, we compare the current list of endpoints with the list of master IP keys
	formatCorrect, ipCorrect, portsCorrect := checkEndpointSubsetFormatWithLease(e, masterIPs, endpointPorts, reconcilePorts)
	if formatCorrect && ipCorrect && portsCorrect {
		return r.epAdapter.EnsureEndpointSliceFromEndpoints(corev1.NamespaceDefault, e)
	}

	// 如果不正确，则重新创建endpoint  
	if !formatCorrect {
		// Something is egregiously wrong, just re-make the endpoints record.
		e.Subsets = []corev1.EndpointSubset{{
			Addresses: []corev1.EndpointAddress{},
			Ports:     endpointPorts,
		}}
	}

	if !formatCorrect || !ipCorrect {
		// repopulate the addresses according to the expected IPs from etcd
		e.Subsets[0].Addresses = make([]corev1.EndpointAddress, len(masterIPs))
		for ind, ip := range masterIPs {
			e.Subsets[0].Addresses[ind] = corev1.EndpointAddress{IP: ip}
		}

		// Lexicographic order is retained by this step.
		e.Subsets = endpointsv1.RepackSubsets(e.Subsets)
	}

	if !portsCorrect {
		// Reset ports.
		e.Subsets[0].Ports = endpointPorts
	}

	// 创建或者更新default kubernetes endpoint  
	klog.Warningf("Resetting endpoints for master service %q to %v", serviceName, masterIPs)
	if shouldCreate {
		if _, err = r.epAdapter.Create(corev1.NamespaceDefault, e); errors.IsAlreadyExists(err) {
			err = nil
		}
	} else {
		_, err = r.epAdapter.Update(corev1.NamespaceDefault, e)
	}
	return err
}

// checkEndpointSubsetFormatWithLease determines if the endpoint is in the
// format ReconcileEndpoints expects when the controller is using leases.
//
// Return values:
// * formatCorrect is true if exactly one subset is found.
// * ipsCorrect when the addresses in the endpoints match the expected addresses list
// * portsCorrect is true when endpoint ports exactly match provided ports.
//     portsCorrect is only evaluated when reconcilePorts is set to true.
func checkEndpointSubsetFormatWithLease(e *corev1.Endpoints, expectedIPs []string, ports []corev1.EndpointPort, reconcilePorts bool) (formatCorrect bool, ipsCorrect bool, portsCorrect bool) {
	if len(e.Subsets) != 1 {
		return false, false, false
	}
	sub := &e.Subsets[0]
	portsCorrect = true
	if reconcilePorts {
		if len(sub.Ports) != len(ports) {
			portsCorrect = false
		} else {
			for i, port := range ports {
				if port != sub.Ports[i] {
					portsCorrect = false
					break
				}
			}
		}
	}

	ipsCorrect = true
	if len(sub.Addresses) != len(expectedIPs) {
		ipsCorrect = false
	} else {
		// check the actual content of the addresses
		// present addrs is used as a set (the keys) and to indicate if a
		// value was already found (the values)
		presentAddrs := make(map[string]bool, len(expectedIPs))
		for _, ip := range expectedIPs {
			presentAddrs[ip] = false
		}

		// uniqueness is assumed amongst all Addresses.
		for _, addr := range sub.Addresses {
			if alreadySeen, ok := presentAddrs[addr.IP]; alreadySeen || !ok {
				ipsCorrect = false
				break
			}

			presentAddrs[addr.IP] = true
		}
	}

	return true, ipsCorrect, portsCorrect
}
```

leaseEndpointReconciler.ReconcileEndpoints的流程如上所示：

* 更新masterleases key TTL
* 获取default kubernetes endpoints 
* 如果不存在，则创建endpoints    
* 将dafault kubernetes endpoint与masterIP列表以及端口列表进行比较，验证已经存在的endpoint有效性
* 如果不正确，则修正endpoint字段并更新

masterleases key如下：

```bash
$ ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/server.crt --key=/etc/kubernetes/pki/etcd/server.key get --prefix --keys-only /registry/masterleases
/registry/masterleases/192.168.60.21
/registry/masterleases/192.168.60.22
/registry/masterleases/192.168.60.23
```

这里再次总结RunKubernetesService的逻辑：检查 kubernetes service 是否处于正常状态，并定期执行同步操作。首先调用 `/healthz` 接口检查 apiserver 当前是否处于 ready 状态，若处于 ready 状态然后调用 `c.UpdateKubernetesService` 服务更新 kubernetes service 状态（创建 default namespace => 创建 kubernetes service => 更新 master 的 endpoint）

最终创建的endpoint如下所示：

```yaml
apiVersion: v1
kind: Endpoints
metadata:
  name: kubernetes
  namespace: default
subsets:
- addresses:
  - ip: 192.168.60.21
  - ip: 192.168.60.22
  - ip: 192.168.60.23
  ports:
  - name: https
    port: 6443
    protocol: TCP
```

#### repairClusterIPs.RunUntil

这里再次回到Controller.Start函数：

```go
// Start begins the core controller loops that must exist for bootstrapping
// a cluster.
func (c *Controller) Start() {
	if c.runner != nil {
		return
	}

	// Reconcile during first run removing itself until server is ready.
	endpointPorts := createEndpointPortSpec(c.PublicServicePort, "https", c.ExtraEndpointPorts)
	if err := c.EndpointReconciler.RemoveEndpoints(kubernetesServiceName, c.PublicIP, endpointPorts); err != nil {
		klog.Errorf("Unable to remove old endpoints from kubernetes service: %v", err)
	}

	repairClusterIPs := servicecontroller.NewRepair(c.ServiceClusterIPInterval, c.ServiceClient, c.EventClient, &c.ServiceClusterIPRange, c.ServiceClusterIPRegistry, &c.SecondaryServiceClusterIPRange, c.SecondaryServiceClusterIPRegistry)
	repairNodePorts := portallocatorcontroller.NewRepair(c.ServiceNodePortInterval, c.ServiceClient, c.EventClient, c.ServiceNodePortRange, c.ServiceNodePortRegistry)

	// run all of the controllers once prior to returning from Start.
	if err := repairClusterIPs.RunOnce(); err != nil {
		// If we fail to repair cluster IPs apiserver is useless. We should restart and retry.
		klog.Fatalf("Unable to perform initial IP allocation check: %v", err)
	}
	if err := repairNodePorts.RunOnce(); err != nil {
		// If we fail to repair node ports apiserver is useless. We should restart and retry.
		klog.Fatalf("Unable to perform initial service nodePort check: %v", err)
	}

	c.runner = async.NewRunner(c.RunKubernetesNamespaces, c.RunKubernetesService, repairClusterIPs.RunUntil, repairNodePorts.RunUntil)
	c.runner.Start()
}
```

这里会先创建repairClusterIPs，然后执行repairClusterIPs.RunUntil来提供基于 Service ClusterIP 的修复及检查功能：

```go
// k8s.io/kubernetes/pkg/registry/core/service/ipallocator/controller/repair.go:76
// NewRepair creates a controller that periodically ensures that all clusterIPs are uniquely allocated across the cluster
// and generates informational warnings for a cluster that is not in sync.
func NewRepair(interval time.Duration, serviceClient corev1client.ServicesGetter, eventClient corev1client.EventsGetter, network *net.IPNet, alloc rangeallocation.RangeRegistry, secondaryNetwork *net.IPNet, secondaryAlloc rangeallocation.RangeRegistry) *Repair {
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartRecordingToSink(&corev1client.EventSinkImpl{Interface: eventClient.Events("")})
	recorder := eventBroadcaster.NewRecorder(legacyscheme.Scheme, v1.EventSource{Component: "ipallocator-repair-controller"})

	return &Repair{
		interval:      interval,
		serviceClient: serviceClient,

		network:          network,
		alloc:            alloc,
		secondaryNetwork: secondaryNetwork,
		secondaryAlloc:   secondaryAlloc,

		leaks:    map[string]int{},
		recorder: recorder,
	}
}

// RunUntil starts the controller until the provided ch is closed.
func (c *Repair) RunUntil(ch chan struct{}) {
	wait.Until(func() {
		if err := c.RunOnce(); err != nil {
			runtime.HandleError(err)
		}
	}, c.interval, ch)
}

// RunOnce verifies the state of the cluster IP allocations and returns an error if an unrecoverable problem occurs.
func (c *Repair) RunOnce() error {
	return retry.RetryOnConflict(retry.DefaultBackoff, c.runOnce)
}

// runOnce verifies the state of the cluster IP allocations and returns an error if an unrecoverable problem occurs.
func (c *Repair) runOnce() error {
	// TODO: (per smarterclayton) if Get() or ListServices() is a weak consistency read,
	// or if they are executed against different leaders,
	// the ordering guarantee required to ensure no IP is allocated twice is violated.
	// ListServices must return a ResourceVersion higher than the etcd index Get triggers,
	// and the release code must not release services that have had IPs allocated but not yet been created
	// See #8295

	// If etcd server is not running we should wait for some time and fail only then. This is particularly
	// important when we start apiserver and etcd at the same time.
	var snapshot *api.RangeAllocation
	var secondarySnapshot *api.RangeAllocation

	var stored, secondaryStored ipallocator.Interface
	var err, secondaryErr error

	// 1、首先从 etcd 中获取已经使用 ClusterIP 的快照  
	err = wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		var err error
		snapshot, err = c.alloc.Get()
		if err != nil {
			return false, err
		}

		if c.shouldWorkOnSecondary() {
			secondarySnapshot, err = c.secondaryAlloc.Get()
			if err != nil {
				return false, err
			}
		}

		return true, nil
	})
	if err != nil {
		return fmt.Errorf("unable to refresh the service IP block: %v", err)
	}
	// 2、判断 snapshot 是否已经初始化  
	// If not yet initialized.
	if snapshot.Range == "" {
		snapshot.Range = c.network.String()
	}

	if c.shouldWorkOnSecondary() && secondarySnapshot.Range == "" {
		secondarySnapshot.Range = c.secondaryNetwork.String()
	}
	// Create an allocator because it is easy to use.

	stored, err = ipallocator.NewFromSnapshot(snapshot)
	if c.shouldWorkOnSecondary() {
		secondaryStored, secondaryErr = ipallocator.NewFromSnapshot(secondarySnapshot)
	}

	if err != nil || secondaryErr != nil {
		return fmt.Errorf("unable to rebuild allocator from snapshots: %v", err)
	}

	// 3、获取 service list  
	// We explicitly send no resource version, since the resource version
	// of 'snapshot' is from a different collection, it's not comparable to
	// the service collection. The caching layer keeps per-collection RVs,
	// and this is proper, since in theory the collections could be hosted
	// in separate etcd (or even non-etcd) instances.
	list, err := c.serviceClient.Services(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("unable to refresh the service IP block: %v", err)
	}

	// 4、将 CIDR 转换为对应的 IP range 格式  
	var rebuilt, secondaryRebuilt *ipallocator.Range
	rebuilt, err = ipallocator.NewCIDRRange(c.network)
	if err != nil {
		return fmt.Errorf("unable to create CIDR range: %v", err)
	}

	if c.shouldWorkOnSecondary() {
		secondaryRebuilt, err = ipallocator.NewCIDRRange(c.secondaryNetwork)
	}

	if err != nil {
		return fmt.Errorf("unable to create CIDR range: %v", err)
	}

	// 5、检查每个 Service 的 ClusterIP，保证其处于正常状态  
	// Check every Service's ClusterIP, and rebuild the state as we think it should be.
	for _, svc := range list.Items {
		if !helper.IsServiceIPSet(&svc) {
			// didn't need a cluster IP
			continue
		}
		ip := net.ParseIP(svc.Spec.ClusterIP)
		if ip == nil {
			// cluster IP is corrupt
			c.recorder.Eventf(&svc, v1.EventTypeWarning, "ClusterIPNotValid", "Cluster IP %s is not a valid IP; please recreate service", svc.Spec.ClusterIP)
			runtime.HandleError(fmt.Errorf("the cluster IP %s for service %s/%s is not a valid IP; please recreate", svc.Spec.ClusterIP, svc.Name, svc.Namespace))
			continue
		}

		// mark it as in-use
		actualAlloc := c.selectAllocForIP(ip, rebuilt, secondaryRebuilt)
		switch err := actualAlloc.Allocate(ip); err {
		// 6、检查 ip 是否泄漏      
		case nil:
			actualStored := c.selectAllocForIP(ip, stored, secondaryStored)
			if actualStored.Has(ip) {
				// remove it from the old set, so we can find leaks
				actualStored.Release(ip)
			} else {
				// cluster IP doesn't seem to be allocated
				c.recorder.Eventf(&svc, v1.EventTypeWarning, "ClusterIPNotAllocated", "Cluster IP %s is not allocated; repairing", ip)
				runtime.HandleError(fmt.Errorf("the cluster IP %s for service %s/%s is not allocated; repairing", ip, svc.Name, svc.Namespace))
			}
			delete(c.leaks, ip.String()) // it is used, so it can't be leaked
		// 7、ip 重复分配      
		case ipallocator.ErrAllocated:
			// cluster IP is duplicate
			c.recorder.Eventf(&svc, v1.EventTypeWarning, "ClusterIPAlreadyAllocated", "Cluster IP %s was assigned to multiple services; please recreate service", ip)
			runtime.HandleError(fmt.Errorf("the cluster IP %s for service %s/%s was assigned to multiple services; please recreate", ip, svc.Name, svc.Namespace))
		// 8、ip 超出范围      
		case err.(*ipallocator.ErrNotInRange):
			// cluster IP is out of range
			c.recorder.Eventf(&svc, v1.EventTypeWarning, "ClusterIPOutOfRange", "Cluster IP %s is not within the service CIDR %s; please recreate service", ip, c.network)
			runtime.HandleError(fmt.Errorf("the cluster IP %s for service %s/%s is not within the service CIDR %s; please recreate", ip, svc.Name, svc.Namespace, c.network))
 		// 9、ip 已经分配完     
		case ipallocator.ErrFull:
			// somehow we are out of IPs
			cidr := actualAlloc.CIDR()
			c.recorder.Eventf(&svc, v1.EventTypeWarning, "ServiceCIDRFull", "Service CIDR %v is full; you must widen the CIDR in order to create new services", cidr)
			return fmt.Errorf("the service CIDR %v is full; you must widen the CIDR in order to create new services", cidr)
		default:
			c.recorder.Eventf(&svc, v1.EventTypeWarning, "UnknownError", "Unable to allocate cluster IP %s due to an unknown error", ip)
			return fmt.Errorf("unable to allocate cluster IP %s for service %s/%s due to an unknown error, exiting: %v", ip, svc.Name, svc.Namespace, err)
		}
	}

	// 10、对比是否有泄漏 ip  
	c.checkLeaked(stored, rebuilt)
	if c.shouldWorkOnSecondary() {
		c.checkLeaked(secondaryStored, secondaryRebuilt)
	}

	// 11、更新快照  
	// Blast the rebuilt state into storage.
	err = c.saveSnapShot(rebuilt, c.alloc, snapshot)
	if err != nil {
		return err
	}

	if c.shouldWorkOnSecondary() {
		err := c.saveSnapShot(secondaryRebuilt, c.secondaryAlloc, secondarySnapshot)
		if err != nil {
			return nil
		}
	}
	return nil
}
```

repairClusterIP 主要解决的问题有：

- 保证集群中所有的 ClusterIP 都是唯一分配的；
- 保证分配的 ClusterIP 不会超出指定范围；
- 确保已经分配给 service 但是因为 crash 等其它原因没有正确创建 ClusterIP；

#### repairNodePorts.RunUntil

### BootstrapController.PreShutdownHook

```go
// PreShutdownHook triggers the actions needed to shut down the API Server cleanly.
func (c *Controller) PreShutdownHook() error {
	c.Stop()
	return nil
}

// Stop cleans up this API Servers endpoint reconciliation leases so another master can take over more quickly.
func (c *Controller) Stop() {
	if c.runner != nil {
		c.runner.Stop()
	}
	endpointPorts := createEndpointPortSpec(c.PublicServicePort, "https", c.ExtraEndpointPorts)
	finishedReconciling := make(chan struct{})
	go func() {
		defer close(finishedReconciling)
		klog.Infof("Shutting down kubernetes service endpoint reconciler")
		c.EndpointReconciler.StopReconciling()
		if err := c.EndpointReconciler.RemoveEndpoints(kubernetesServiceName, c.PublicIP, endpointPorts); err != nil {
			klog.Error(err)
		}
	}()

	select {
	case <-finishedReconciling:
		// done
	case <-time.After(2 * c.EndpointInterval):
		// don't block server shutdown forever if we can't reach etcd to remove ourselves
		klog.Warning("RemoveEndpoints() timed out")
	}
}

func (r *leaseEndpointReconciler) RemoveEndpoints(serviceName string, ip net.IP, endpointPorts []corev1.EndpointPort) error {
	if err := r.masterLeases.RemoveLease(ip.String()); err != nil {
		return err
	}

	return r.doReconcile(serviceName, endpointPorts, true)
}

func (r *leaseEndpointReconciler) StopReconciling() {
	r.reconcilingLock.Lock()
	defer r.reconcilingLock.Unlock()
	r.stopReconcilingCalled = true
}

// ReconcileEndpoints lists keys in a special etcd directory.
// Each key is expected to have a TTL of R+n, where R is the refresh interval
// at which this function is called, and n is some small value.  If an
// apiserver goes down, it will fail to refresh its key's TTL and the key will
// expire. ReconcileEndpoints will notice that the endpoints object is
// different from the directory listing, and update the endpoints object
// accordingly.
func (r *leaseEndpointReconciler) ReconcileEndpoints(serviceName string, ip net.IP, endpointPorts []corev1.EndpointPort, reconcilePorts bool) error {
	r.reconcilingLock.Lock()
	defer r.reconcilingLock.Unlock()

	if r.stopReconcilingCalled {
		return nil
	}

	// Refresh the TTL on our key, independently of whether any error or
	// update conflict happens below. This makes sure that at least some of
	// the masters will add our endpoint.
	if err := r.masterLeases.UpdateLease(ip.String()); err != nil {
		return err
	}

	return r.doReconcile(serviceName, endpointPorts, reconcilePorts)
}
```

可以看到PreShutdownHook会先停止ReconcileEndpoints，然后清理掉default Kubernetes endpoint中本身masterIP的记录(cleans up this API Servers endpoint)

## 总结

* apiserver bootstrap-controller创建&运行逻辑在k8s.io/kubernetes/pkg/master目录
* bootstrap-controller主要用于创建以及维护内部kubernetes apiserver service
* default kubernetes service spec.selector为空，这是default kubernetes service与其它正常service的最大区别，表明了这个特殊的service对应的endpoints不由endpoints controller控制，而是直接受kube-apiserver bootstrap-controller管理(maintained by this code, not by the pod selector)
* bootstrap-controller的几个主要功能如下：
  * 创建 default、kube-system 和 kube-public 以及 kube-node-lease 命名空间
  * 创建&维护 default kubernetes service以及对应的endpoint
  * 提供基于 Service ClusterIP 的修复及检查功能(`--service-cluster-ip-range`指定范围)
  * 提供基于 Service NodePort 的修复及检查功能(`--service-node-port-range`指定范围)

## Refs

* [bootstrap controller 源码分析](https://github.com/gosoon/source-code-reading-notes/blob/master/kubernetes/apiserver_bootstrap_controller.md)