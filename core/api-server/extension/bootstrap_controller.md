kube-apiserver bootstrap-controller
===================================

## bootstrap-controller概述

在 kubernetes，可以从集群外部和内部两种方式访问 kubernetes API，在集群外直接访问 apiserver 提供的 API，在集群内即 pod 中可以通过访问 service 为 kubernetes 的 ClusterIP。kubernetes 集群在初始化完成后就会创建一个 kubernetes service，该 service 是 kube-apiserver 创建并进行维护的，如下所示：

```
$ kubectl get svc
NAME             TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)           AGE
kubernetes       ClusterIP   10.96.0.1      <none>        443/TCP           36d

$ kubectl get ep kubernetes
NAME         ENDPOINTS                                                  AGE
kubernetes   192.168.60.21:6443,192.168.60.22:6443,192.168.60.23:6443   36d
```

内置的 kubernetes service 无法删除，其 ClusterIP 为通过 `--service-cluster-ip-range` 参数指定的 ip 段中的首个 ip，kubernetes endpoints 中的 ip 以及 port 可以通过 `--advertise-address` 和 `--secure-port` 启动参数来指定

```
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
- 创建 default、kube-system 和 kube-public 命名空间，如果启用了 `NodeLease` 特性还会创建 kube-node-lease 命名空间；
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

bootstrap controller 在初始化时需要设定多个参数，主要有 PublicIP、ServiceCIDR、PublicServicePort 等。PublicIP 是通过命令行参数 `--advertise-address` 指定的，如果没有指定，系统会自动选出一个 global IP。PublicServicePort 通过 `--secure-port` 启动参数来指定（默认为 6443），ServiceCIDR 通过 `--service-cluster-ip-range` 参数指定（默认为 10.0.0.0/24）

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





## Refs

* [bootstrap controller 源码分析](https://github.com/gosoon/source-code-reading-notes/blob/master/kubernetes/apiserver_bootstrap_controller.md)