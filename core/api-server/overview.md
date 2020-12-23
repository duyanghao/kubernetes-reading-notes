kubernetes apiserver原理概览
==========================

## 前言

整个Kubernetes技术体系由声明式API以及Controller构成，而kube-apiserver是Kubernetes的声明式api server，并为其它组件交互提供了桥梁。因此加深对kube-apiserver的理解就显得至关重要

![img](https://duyanghao.github.io/public/img/apiserver-overview/apiserver-overview.png)

## 整体组件功能

kube-apiserver作为整个Kubernetes集群操作etcd的唯一入口，负责Kubernetes各资源的认证&鉴权，校验以及CRUD等操作，提供RESTful APIs，供其它组件调用：

![img](https://camo.githubusercontent.com/51343f8fc557dcd869e40d2323c28f26b32702e167aa9ad3f26508c3584bd51f/68747470733a2f2f666569736b792e676974626f6f6b732e696f2f6b756265726e657465732f636f6e74656e742f636f6d706f6e656e74732f696d616765732f6b7562652d6170697365727665722e706e67)

kube-apiserver包含三种APIServer：

* aggregatorServer：负责处理 `apiregistration.k8s.io` 组下的APIService资源请求，同时将来自用户的请求拦截转发给aggregated server(AA)
* kubeAPIServer：负责对请求的一些通用处理，包括：认证、鉴权以及各个内建资源(pod, deployment，service and etc)的REST服务等
* apiExtensionsServer：负责CustomResourceDefinition（CRD）apiResources以及apiVersions的注册，同时处理CRD以及相应CustomResource（CR）的REST请求(如果对应CR不能被处理的话则会返回404)，也是apiserver Delegation的最后一环

另外还包括bootstrap-controller，主要负责Kubernetes default apiserver service的创建以及管理

接下来将对上述组件进行概览性总结

## bootstrap-controller

- apiserver bootstrap-controller创建&运行逻辑在k8s.io/kubernetes/pkg/master目录
- bootstrap-controller主要用于创建以及维护内部kubernetes default apiserver service
- kubernetes default apiserver service spec.selector为空，这是default apiserver service与其它正常service的最大区别，表明了这个特殊的service对应的endpoints不由endpoints controller控制，而是直接受kube-apiserver bootstrap-controller管理(maintained by this code, not by the pod selector)
- bootstrap-controller的几个主要功能如下：
  - 创建 default、kube-system 和 kube-public 以及 kube-node-lease 命名空间
  - 创建&维护kubernetes default apiserver service以及对应的endpoint
  - 提供基于Service ClusterIP的检查及修复功能(`--service-cluster-ip-range`指定范围)
  - 提供基于Service NodePort的检查及修复功能(`--service-node-port-range`指定范围)

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
	
	// 定期执行bootstrap controller主要的四个功能(reconciliation)  
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

更多代码原理详情，参考[kubernetes-reading-notes](https://github.com/duyanghao/kubernetes-reading-notes/tree/master/core/api-server)

## kubeAPIServer

KubeAPIServer主要提供对内建API Resources的操作请求，为Kubernetes中各API Resources注册路由信息，同时暴露RESTful API，使集群中以及集群外的服务都可以通过RESTful API操作Kubernetes中的资源

另外，kubeAPIServer是整个Kubernetes apiserver的核心，下面将要讲述的aggregatorServer以及apiExtensionsServer都是建立在kubeAPIServer基础上进行扩展的(补充了Kubernetes对用户自定义资源的能力支持)

kubeAPIServer最核心的功能是为Kubernetes内置资源添加路由，如下：

- 调用 `m.InstallLegacyAPI` 将核心 API Resources添加到路由中，在apiserver中即是以 `/api` 开头的 resource；
- 调用 `m.InstallAPIs` 将扩展的 API Resources添加到路由中，在apiserver中即是以 `/apis` 开头的 resource；

```go
// k8s.io/kubernetes/pkg/master/master.go:332
// New returns a new instance of Master from the given config.
// Certain config fields will be set to a default value if unset.
// Certain config fields must be specified, including:
//   KubeletClientConfig
func (c completedConfig) New(delegationTarget genericapiserver.DelegationTarget) (*Master, error) {
	// 1、初始化GenericAPIServer
	s, err := c.GenericConfig.New("kube-apiserver", delegationTarget)
	if err != nil {
		return nil, err
	}

	// 2、注册logs相关路由
	if c.ExtraConfig.EnableLogsSupport {
		routes.Logs{}.Install(s.Handler.GoRestfulContainer)
	}
	...
	m := &Master{
		GenericAPIServer:          s,
		ClusterAuthenticationInfo: c.ExtraConfig.ClusterAuthenticationInfo,
	}

	// 3、安装 LegacyAPI(core API)
	// install legacy rest storage
	if c.ExtraConfig.APIResourceConfigSource.VersionEnabled(apiv1.SchemeGroupVersion) {
		legacyRESTStorageProvider := corerest.LegacyRESTStorageProvider{
			StorageFactory:              c.ExtraConfig.StorageFactory,
			ProxyTransport:              c.ExtraConfig.ProxyTransport,
			KubeletClientConfig:         c.ExtraConfig.KubeletClientConfig,
			EventTTL:                    c.ExtraConfig.EventTTL,
			ServiceIPRange:              c.ExtraConfig.ServiceIPRange,
			SecondaryServiceIPRange:     c.ExtraConfig.SecondaryServiceIPRange,
			ServiceNodePortRange:        c.ExtraConfig.ServiceNodePortRange,
			LoopbackClientConfig:        c.GenericConfig.LoopbackClientConfig,
			ServiceAccountIssuer:        c.ExtraConfig.ServiceAccountIssuer,
			ServiceAccountMaxExpiration: c.ExtraConfig.ServiceAccountMaxExpiration,
			APIAudiences:                c.GenericConfig.Authentication.APIAudiences,
		}
		if err := m.InstallLegacyAPI(&c, c.GenericConfig.RESTOptionsGetter, legacyRESTStorageProvider); err != nil {
			return nil, err
		}
	}

	// The order here is preserved in discovery.
	// If resources with identical names exist in more than one of these groups (e.g. "deployments.apps"" and "deployments.extensions"),
	// the order of this list determines which group an unqualified resource name (e.g. "deployments") should prefer.
	// This priority order is used for local discovery, but it ends up aggregated in `k8s.io/kubernetes/cmd/kube-apiserver/app/aggregator.go
	// with specific priorities.
	// TODO: describe the priority all the way down in the RESTStorageProviders and plumb it back through the various discovery
	// handlers that we have.
	restStorageProviders := []RESTStorageProvider{
		auditregistrationrest.RESTStorageProvider{},
		authenticationrest.RESTStorageProvider{Authenticator: c.GenericConfig.Authentication.Authenticator, APIAudiences: c.GenericConfig.Authentication.APIAudiences},
		authorizationrest.RESTStorageProvider{Authorizer: c.GenericConfig.Authorization.Authorizer, RuleResolver: c.GenericConfig.RuleResolver},
		autoscalingrest.RESTStorageProvider{},
		batchrest.RESTStorageProvider{},
		certificatesrest.RESTStorageProvider{},
		coordinationrest.RESTStorageProvider{},
		discoveryrest.StorageProvider{},
		extensionsrest.RESTStorageProvider{},
		networkingrest.RESTStorageProvider{},
		noderest.RESTStorageProvider{},
		policyrest.RESTStorageProvider{},
		rbacrest.RESTStorageProvider{Authorizer: c.GenericConfig.Authorization.Authorizer},
		schedulingrest.RESTStorageProvider{},
		settingsrest.RESTStorageProvider{},
		storagerest.RESTStorageProvider{},
		flowcontrolrest.RESTStorageProvider{},
		// keep apps after extensions so legacy clients resolve the extensions versions of shared resource names.
		// See https://github.com/kubernetes/kubernetes/issues/42392
		appsrest.RESTStorageProvider{},
		admissionregistrationrest.RESTStorageProvider{},
		eventsrest.RESTStorageProvider{TTL: c.ExtraConfig.EventTTL},
	}
	// 4、安装 APIs(named groups apis)
	if err := m.InstallAPIs(c.ExtraConfig.APIResourceConfigSource, c.GenericConfig.RESTOptionsGetter, restStorageProviders...); err != nil {
		return nil, err
	}

	if c.ExtraConfig.Tunneler != nil {
		m.installTunneler(c.ExtraConfig.Tunneler, corev1client.NewForConfigOrDie(c.GenericConfig.LoopbackClientConfig).Nodes())
	}

	m.GenericAPIServer.AddPostStartHookOrDie("start-cluster-authentication-info-controller", func(hookContext genericapiserver.PostStartHookContext) error {
		kubeClient, err := kubernetes.NewForConfig(hookContext.LoopbackClientConfig)
		if err != nil {
			return err
		}
		controller := clusterauthenticationtrust.NewClusterAuthenticationTrustController(m.ClusterAuthenticationInfo, kubeClient)

		// prime values and start listeners
		if m.ClusterAuthenticationInfo.ClientCA != nil {
			if notifier, ok := m.ClusterAuthenticationInfo.ClientCA.(dynamiccertificates.Notifier); ok {
				notifier.AddListener(controller)
			}
			if controller, ok := m.ClusterAuthenticationInfo.ClientCA.(dynamiccertificates.ControllerRunner); ok {
				// runonce to be sure that we have a value.
				if err := controller.RunOnce(); err != nil {
					runtime.HandleError(err)
				}
				go controller.Run(1, hookContext.StopCh)
			}
		}
		if m.ClusterAuthenticationInfo.RequestHeaderCA != nil {
			if notifier, ok := m.ClusterAuthenticationInfo.RequestHeaderCA.(dynamiccertificates.Notifier); ok {
				notifier.AddListener(controller)
			}
			if controller, ok := m.ClusterAuthenticationInfo.RequestHeaderCA.(dynamiccertificates.ControllerRunner); ok {
				// runonce to be sure that we have a value.
				if err := controller.RunOnce(); err != nil {
					runtime.HandleError(err)
				}
				go controller.Run(1, hookContext.StopCh)
			}
		}

		go controller.Run(1, hookContext.StopCh)
		return nil
	})

	return m, nil
}
```

整个kubeAPIServer提供了三类API Resource接口：

- core group：主要在 `/api/v1` 下；
- named groups：其 path 为 `/apis/$GROUP/$VERSION`；
- 系统状态的一些 API：如`/metrics` 、`/version` 等；

而API的URL大致以 `/apis/{group}/{version}/namespaces/{namespace}/resource/{name}` 组成，结构如下图所示：

![img](https://github.com/duyanghao/kubernetes-reading-notes/raw/master/core/api-server/images/apis.png)

kubeAPIServer会为每种API资源创建对应的RESTStorage，RESTStorage的目的是将每种资源的访问路径及其后端存储的操作对应起来：通过构造的REST Storage实现的接口判断该资源可以执行哪些操作（如：create、update等），将其对应的操作存入到action中，每一个操作对应一个标准的REST method，如create对应REST method为POST，而update对应REST method为PUT。最终根据actions数组依次遍历，对每一个操作添加一个handler(handler对应REST Storage实现的相关接口)，并注册到route，最终对外提供RESTful API，如下：

```go
// m.GenericAPIServer.InstallLegacyAPIGroup --> s.installAPIResources --> apiGroupVersion.InstallREST --> installer.Install --> a.registerResourceHandlers

// k8s.io/kubernetes/pkg/registry/core/rest/storage_core.go:102
func (c LegacyRESTStorageProvider) NewLegacyRESTStorage(restOptionsGetter generic.RESTOptionsGetter) (LegacyRESTStorage, genericapiserver.APIGroupInfo, error) {
	apiGroupInfo := genericapiserver.APIGroupInfo{
		PrioritizedVersions:          legacyscheme.Scheme.PrioritizedVersionsForGroup(""),
		VersionedResourcesStorageMap: map[string]map[string]rest.Storage{},
		Scheme:                       legacyscheme.Scheme,
		ParameterCodec:               legacyscheme.ParameterCodec,
		NegotiatedSerializer:         legacyscheme.Codecs,
	}

	...
	// 1、LegacyAPI 下的 resource RESTStorage 的初始化  
	restStorage := LegacyRESTStorage{}

	podTemplateStorage, err := podtemplatestore.NewREST(restOptionsGetter)
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}
	...
	endpointsStorage, err := endpointsstore.NewREST(restOptionsGetter)
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}

	nodeStorage, err := nodestore.NewStorage(restOptionsGetter, c.KubeletClientConfig, c.ProxyTransport)
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}

	// 2、pod RESTStorage 的初始化  
	podStorage, err := podstore.NewStorage(
		restOptionsGetter,
		nodeStorage.KubeletConnectionInfo,
		c.ProxyTransport,
		podDisruptionClient,
	)
	...

	// 3、restStorageMap 保存 resource http path 与 RESTStorage 对应关系  
	restStorageMap := map[string]rest.Storage{
		"pods":             podStorage.Pod,
		"pods/attach":      podStorage.Attach,
		"pods/status":      podStorage.Status,
		"pods/log":         podStorage.Log,
		"pods/exec":        podStorage.Exec,
		"pods/portforward": podStorage.PortForward,
		"pods/proxy":       podStorage.Proxy,
		"pods/binding":     podStorage.Binding,
		"bindings":         podStorage.LegacyBinding,

		"podTemplates": podTemplateStorage,

		"replicationControllers":        controllerStorage.Controller,
		"replicationControllers/status": controllerStorage.Status,

		"services":        serviceRest,
		"services/proxy":  serviceRestProxy,
		"services/status": serviceStatusStorage,

		"endpoints": endpointsStorage,

		"nodes":        nodeStorage.Node,
		"nodes/status": nodeStorage.Status,
		"nodes/proxy":  nodeStorage.Proxy,

		"events": eventStorage,

		"limitRanges":                   limitRangeStorage,
		"resourceQuotas":                resourceQuotaStorage,
		"resourceQuotas/status":         resourceQuotaStatusStorage,
		"namespaces":                    namespaceStorage,
		"namespaces/status":             namespaceStatusStorage,
		"namespaces/finalize":           namespaceFinalizeStorage,
		"secrets":                       secretStorage,
		"serviceAccounts":               serviceAccountStorage,
		"persistentVolumes":             persistentVolumeStorage,
		"persistentVolumes/status":      persistentVolumeStatusStorage,
		"persistentVolumeClaims":        persistentVolumeClaimStorage,
		"persistentVolumeClaims/status": persistentVolumeClaimStatusStorage,
		"configMaps":                    configMapStorage,

		"componentStatuses": componentstatus.NewStorage(componentStatusStorage{c.StorageFactory}.serversToValidate),
	}
	apiGroupInfo.VersionedResourcesStorageMap["v1"] = restStorageMap

	return restStorage, apiGroupInfo, nil
}

// k8s.io/kubernetes/pkg/registry/core/pod/storage/storage.go:70
// NewStorage returns a RESTStorage object that will work against pods.
func NewStorage(optsGetter generic.RESTOptionsGetter, k client.ConnectionInfoGetter, proxyTransport http.RoundTripper, podDisruptionBudgetClient policyclient.PodDisruptionBudgetsGetter) (PodStorage, error) {

	store := &genericregistry.Store{
		NewFunc:                  func() runtime.Object { return &api.Pod{} },
		NewListFunc:              func() runtime.Object { return &api.PodList{} },
		PredicateFunc:            registrypod.MatchPod,
		DefaultQualifiedResource: api.Resource("pods"),

		CreateStrategy:      registrypod.Strategy,
		UpdateStrategy:      registrypod.Strategy,
		DeleteStrategy:      registrypod.Strategy,
		ReturnDeletedObject: true,

		TableConvertor: printerstorage.TableConvertor{TableGenerator: printers.NewTableGenerator().With(printersinternal.AddHandlers)},
	}
	options := &generic.StoreOptions{
		RESTOptions: optsGetter,
		AttrFunc:    registrypod.GetAttrs,
		TriggerFunc: map[string]storage.IndexerFunc{"spec.nodeName": registrypod.NodeNameTriggerFunc},
		Indexers:    registrypod.Indexers(),
	}
	// 调用 store.CompleteWithOptions  
	if err := store.CompleteWithOptions(options); err != nil {
		return PodStorage{}, err
	}

	statusStore := *store
	statusStore.UpdateStrategy = registrypod.StatusStrategy
	ephemeralContainersStore := *store
	ephemeralContainersStore.UpdateStrategy = registrypod.EphemeralContainersStrategy

	bindingREST := &BindingREST{store: store}
	// PodStorage 对象  
	return PodStorage{
		Pod:                 &REST{store, proxyTransport},
		Binding:             &BindingREST{store: store},
		LegacyBinding:       &LegacyBindingREST{bindingREST},
		Eviction:            newEvictionStorage(store, podDisruptionBudgetClient),
		Status:              &StatusREST{store: &statusStore},
		EphemeralContainers: &EphemeralContainersREST{store: &ephemeralContainersStore},
		Log:                 &podrest.LogREST{Store: store, KubeletConn: k},
		Proxy:               &podrest.ProxyREST{Store: store, ProxyTransport: proxyTransport},
		Exec:                &podrest.ExecREST{Store: store, KubeletConn: k},
		Attach:              &podrest.AttachREST{Store: store, KubeletConn: k},
		PortForward:         &podrest.PortForwardREST{Store: store, KubeletConn: k},
	}, nil
}

// k8s.io/kubernetes/staging/src/k8s.io/apiserver/pkg/endpoints/installer.go:181
func (a *APIInstaller) registerResourceHandlers(path string, storage rest.Storage, ws *restful.WebService) (*metav1.APIResource, error) {
	...

	// 1、判断该 resource 实现了哪些 REST 操作接口，以此来判断其支持的 verbs 以便为其添加路由
	// what verbs are supported by the storage, used to know what verbs we support per path
	creater, isCreater := storage.(rest.Creater)
	namedCreater, isNamedCreater := storage.(rest.NamedCreater)
	lister, isLister := storage.(rest.Lister)
	getter, isGetter := storage.(rest.Getter)
	getterWithOptions, isGetterWithOptions := storage.(rest.GetterWithOptions)
	gracefulDeleter, isGracefulDeleter := storage.(rest.GracefulDeleter)
	collectionDeleter, isCollectionDeleter := storage.(rest.CollectionDeleter)
	updater, isUpdater := storage.(rest.Updater)
	patcher, isPatcher := storage.(rest.Patcher)
	watcher, isWatcher := storage.(rest.Watcher)
	connecter, isConnecter := storage.(rest.Connecter)
	storageMeta, isMetadata := storage.(rest.StorageMetadata)
	storageVersionProvider, isStorageVersionProvider := storage.(rest.StorageVersionProvider)

	...
	// 2、为 resource 添加对应的 actions(+根据是否支持 namespace)
	// Get the list of actions for the given scope.
	switch {
	case !namespaceScoped:
		// Handle non-namespace scoped resources like nodes.
		resourcePath := resource
		resourceParams := params
		itemPath := resourcePath + "/{name}"
		nameParams := append(params, nameParam)
		proxyParams := append(nameParams, pathParam)
		suffix := ""
		if isSubresource {
			suffix = "/" + subresource
			itemPath = itemPath + suffix
			resourcePath = itemPath
			resourceParams = nameParams
		}
		apiResource.Name = path
		apiResource.Namespaced = false
		apiResource.Kind = resourceKind
		namer := handlers.ContextBasedNaming{
			SelfLinker:         a.group.Linker,
			ClusterScoped:      true,
			SelfLinkPathPrefix: gpath.Join(a.prefix, resource) + "/",
			SelfLinkPathSuffix: suffix,
		}

		// Handler for standard REST verbs (GET, PUT, POST and DELETE).
		// Add actions at the resource path: /api/apiVersion/resource
		actions = appendIf(actions, action{"LIST", resourcePath, resourceParams, namer, false}, isLister)
		actions = appendIf(actions, action{"POST", resourcePath, resourceParams, namer, false}, isCreater)
		actions = appendIf(actions, action{"DELETECOLLECTION", resourcePath, resourceParams, namer, false}, isCollectionDeleter)
		// DEPRECATED in 1.11
		actions = appendIf(actions, action{"WATCHLIST", "watch/" + resourcePath, resourceParams, namer, false}, allowWatchList)

		// Add actions at the item path: /api/apiVersion/resource/{name}
		actions = appendIf(actions, action{"GET", itemPath, nameParams, namer, false}, isGetter)
		if getSubpath {
			actions = appendIf(actions, action{"GET", itemPath + "/{path:*}", proxyParams, namer, false}, isGetter)
		}
		actions = appendIf(actions, action{"PUT", itemPath, nameParams, namer, false}, isUpdater)
		actions = appendIf(actions, action{"PATCH", itemPath, nameParams, namer, false}, isPatcher)
		actions = appendIf(actions, action{"DELETE", itemPath, nameParams, namer, false}, isGracefulDeleter)
		// DEPRECATED in 1.11
		actions = appendIf(actions, action{"WATCH", "watch/" + itemPath, nameParams, namer, false}, isWatcher)
		actions = appendIf(actions, action{"CONNECT", itemPath, nameParams, namer, false}, isConnecter)
		actions = appendIf(actions, action{"CONNECT", itemPath + "/{path:*}", proxyParams, namer, false}, isConnecter && connectSubpath)
	default:
		namespaceParamName := "namespaces"
		// Handler for standard REST verbs (GET, PUT, POST and DELETE).
		namespaceParam := ws.PathParameter("namespace", "object name and auth scope, such as for teams and projects").DataType("string")
		namespacedPath := namespaceParamName + "/{namespace}/" + resource
		namespaceParams := []*restful.Parameter{namespaceParam}

		resourcePath := namespacedPath
		resourceParams := namespaceParams
		itemPath := namespacedPath + "/{name}"
		nameParams := append(namespaceParams, nameParam)
		proxyParams := append(nameParams, pathParam)
		itemPathSuffix := ""
		if isSubresource {
			itemPathSuffix = "/" + subresource
			itemPath = itemPath + itemPathSuffix
			resourcePath = itemPath
			resourceParams = nameParams
		}
		apiResource.Name = path
		apiResource.Namespaced = true
		apiResource.Kind = resourceKind
		namer := handlers.ContextBasedNaming{
			SelfLinker:         a.group.Linker,
			ClusterScoped:      false,
			SelfLinkPathPrefix: gpath.Join(a.prefix, namespaceParamName) + "/",
			SelfLinkPathSuffix: itemPathSuffix,
		}

		actions = appendIf(actions, action{"LIST", resourcePath, resourceParams, namer, false}, isLister)
		actions = appendIf(actions, action{"POST", resourcePath, resourceParams, namer, false}, isCreater)
		actions = appendIf(actions, action{"DELETECOLLECTION", resourcePath, resourceParams, namer, false}, isCollectionDeleter)
		// DEPRECATED in 1.11
		actions = appendIf(actions, action{"WATCHLIST", "watch/" + resourcePath, resourceParams, namer, false}, allowWatchList)

		actions = appendIf(actions, action{"GET", itemPath, nameParams, namer, false}, isGetter)
		if getSubpath {
			actions = appendIf(actions, action{"GET", itemPath + "/{path:*}", proxyParams, namer, false}, isGetter)
		}
		actions = appendIf(actions, action{"PUT", itemPath, nameParams, namer, false}, isUpdater)
		actions = appendIf(actions, action{"PATCH", itemPath, nameParams, namer, false}, isPatcher)
		actions = appendIf(actions, action{"DELETE", itemPath, nameParams, namer, false}, isGracefulDeleter)
		// DEPRECATED in 1.11
		actions = appendIf(actions, action{"WATCH", "watch/" + itemPath, nameParams, namer, false}, isWatcher)
		actions = appendIf(actions, action{"CONNECT", itemPath, nameParams, namer, false}, isConnecter)
		actions = appendIf(actions, action{"CONNECT", itemPath + "/{path:*}", proxyParams, namer, false}, isConnecter && connectSubpath)

		// list or post across namespace.
		// For ex: LIST all pods in all namespaces by sending a LIST request at /api/apiVersion/pods.
		// TODO: more strongly type whether a resource allows these actions on "all namespaces" (bulk delete)
		if !isSubresource {
			actions = appendIf(actions, action{"LIST", resource, params, namer, true}, isLister)
			// DEPRECATED in 1.11
			actions = appendIf(actions, action{"WATCHLIST", "watch/" + resource, params, namer, true}, allowWatchList)
		}
	}

	// Create Routes for the actions.
	// TODO: Add status documentation using Returns()
	// Errors (see api/errors/errors.go as well as go-restful router):
	// http.StatusNotFound, http.StatusMethodNotAllowed,
	// http.StatusUnsupportedMediaType, http.StatusNotAcceptable,
	// http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
	// http.StatusRequestTimeout, http.StatusConflict, http.StatusPreconditionFailed,
	// http.StatusUnprocessableEntity, http.StatusInternalServerError,
	// http.StatusServiceUnavailable
	// and api error codes
	// Note that if we specify a versioned Status object here, we may need to
	// create one for the tests, also
	// Success:
	// http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent
	//
	// test/integration/auth_test.go is currently the most comprehensive status code test

	for _, s := range a.group.Serializer.SupportedMediaTypes() {
		if len(s.MediaTypeSubType) == 0 || len(s.MediaTypeType) == 0 {
			return nil, fmt.Errorf("all serializers in the group Serializer must have MediaTypeType and MediaTypeSubType set: %s", s.MediaType)
		}
	}
	mediaTypes, streamMediaTypes := negotiation.MediaTypesForSerializer(a.group.Serializer)
	allMediaTypes := append(mediaTypes, streamMediaTypes...)
	ws.Produces(allMediaTypes...)

	// 3、根据 action 创建对应的 route  
	kubeVerbs := map[string]struct{}{}
	reqScope := handlers.RequestScope{
		Serializer:      a.group.Serializer,
		ParameterCodec:  a.group.ParameterCodec,
		Creater:         a.group.Creater,
		Convertor:       a.group.Convertor,
		Defaulter:       a.group.Defaulter,
		Typer:           a.group.Typer,
		UnsafeConvertor: a.group.UnsafeConvertor,
		Authorizer:      a.group.Authorizer,

		EquivalentResourceMapper: a.group.EquivalentResourceRegistry,

		// TODO: Check for the interface on storage
		TableConvertor: tableProvider,

		// TODO: This seems wrong for cross-group subresources. It makes an assumption that a subresource and its parent are in the same group version. Revisit this.
		Resource:    a.group.GroupVersion.WithResource(resource),
		Subresource: subresource,
		Kind:        fqKindToRegister,

		HubGroupVersion: schema.GroupVersion{Group: fqKindToRegister.Group, Version: runtime.APIVersionInternal},

		MetaGroupVersion: metav1.SchemeGroupVersion,

		MaxRequestBodyBytes: a.group.MaxRequestBodyBytes,
	}
	...
	// 4、从 rest.Storage 到 restful.Route 映射
	// 为每个操作添加对应的 handler
	for _, action := range actions {
		...
		switch action.Verb {
		case "GET": // Get a resource.
  	case "LIST": // List all resources of a kind.
		case "PUT": // Update a resource.
		case "PATCH": // Partially update a resource
		case "POST": // Create a resource.
			var handler restful.RouteFunction
			// 5、初始化 handler
			if isNamedCreater {
				handler = restfulCreateNamedResource(namedCreater, reqScope, admit)
			} else {
				handler = restfulCreateResource(creater, reqScope, admit)
			}
			handler = metrics.InstrumentRouteFunc(action.Verb, group, version, resource, subresource, requestScope, metrics.APIServerComponent, handler)
			article := GetArticleForNoun(kind, " ")
			doc := "create" + article + kind
			if isSubresource {
				doc = "create " + subresource + " of" + article + kind
			}
			// 6、route 与 handler 进行绑定    
			route := ws.POST(action.Path).To(handler).
				Doc(doc).
				Param(ws.QueryParameter("pretty", "If 'true', then the output is pretty printed.")).
				Operation("create"+namespaced+kind+strings.Title(subresource)+operationSuffix).
				Produces(append(storageMeta.ProducesMIMETypes(action.Verb), mediaTypes...)...).
				Returns(http.StatusOK, "OK", producedObject).
				// TODO: in some cases, the API may return a v1.Status instead of the versioned object
				// but currently go-restful can't handle multiple different objects being returned.
				Returns(http.StatusCreated, "Created", producedObject).
				Returns(http.StatusAccepted, "Accepted", producedObject).
				Reads(defaultVersionedObject).
				Writes(producedObject)
			if err := AddObjectParams(ws, route, versionedCreateOptions); err != nil {
				return nil, err
			}
			addParams(route, action.Params)
			// 7、添加到路由中    
			routes = append(routes, route)
		case "DELETE": // Delete a resource.
		...
		default:
			return nil, fmt.Errorf("unrecognized action verb: %s", action.Verb)
		}
		for _, route := range routes {
			route.Metadata(ROUTE_META_GVK, metav1.GroupVersionKind{
				Group:   reqScope.Kind.Group,
				Version: reqScope.Kind.Version,
				Kind:    reqScope.Kind.Kind,
			})
			route.Metadata(ROUTE_META_ACTION, strings.ToLower(action.Verb))
			ws.Route(route)
		}
		// Note: update GetAuthorizerAttributes() when adding a custom handler.
	}

	apiResource.Verbs = make([]string, 0, len(kubeVerbs))
	for kubeVerb := range kubeVerbs {
		apiResource.Verbs = append(apiResource.Verbs, kubeVerb)
	}
	sort.Strings(apiResource.Verbs)

	if shortNamesProvider, ok := storage.(rest.ShortNamesProvider); ok {
		apiResource.ShortNames = shortNamesProvider.ShortNames()
	}
	if categoriesProvider, ok := storage.(rest.CategoriesProvider); ok {
		apiResource.Categories = categoriesProvider.Categories()
	}
	if gvkProvider, ok := storage.(rest.GroupVersionKindProvider); ok {
		gvk := gvkProvider.GroupVersionKind(a.group.GroupVersion)
		apiResource.Group = gvk.Group
		apiResource.Version = gvk.Version
		apiResource.Kind = gvk.Kind
	}

	// Record the existence of the GVR and the corresponding GVK
	a.group.EquivalentResourceRegistry.RegisterKindFor(reqScope.Resource, reqScope.Subresource, fqKindToRegister)

	return &apiResource, nil
}
```

而kubeAPIServer从接受到创建请求到完成创建，整个与etcd的交互环节如下：

```bash
v1beta1 ⇒ internal ⇒    |    ⇒       |    ⇒  v1  ⇒ json/yaml ⇒ etcd
                     admission    validation
```

![API-server-storage-flow-2](https://camo.githubusercontent.com/38c6882499f6d15e7322e649a07f8a602c3009d7eafb1ed6ec444aa368ef849c/687474703a2f2f63646e2e7469616e66656979752e636f6d2f4150492d7365727665722d73746f726167652d666c6f772d322e706e67)

下面依次介绍各环节：

**Decoder**

kubernetes 中的多数 resource 都会有一个 `internal version`，因为在整个开发过程中一个 resource 可能会对应多个 version，比如 deployment 会有 `extensions/v1beta1`，`apps/v1`。 为了避免出现问题，kube-apiserver 必须要知道如何在每一对版本之间进行转换（例如，v1⇔v1alpha1，v1⇔v1beta1，v1beta1⇔v1alpha1），因此其使用了一个特殊的`internal version`，`internal version` 作为一个通用的 version 会包含所有 version 的字段，它具有所有 version 的功能。 Decoder 会首先把 creater object 转换到 `internal version`

**Admission**

在解码完成后，需要通过验证集群的全局约束来检查是否可以创建或更新对象，并根据集群配置设置默认值。在 `k8s.io/kubernetes/plugin/pkg/admission` 目录下可以看到 kube-apiserver 可以使用的所有全局约束插件，kube-apiserver 在启动时通过设置 `--enable-admission-plugins` 参数来开启需要使用的插件，通过 `ValidatingAdmissionWebhook` 或 `MutatingAdmissionWebhook` 添加的插件也都会在此处进行工作

**Validation**

主要检查 object 中字段的合法性

**Encode**

Encode完成与Decoder相反的操作，将internal version object转化为storage version object，`storage version` 是在 etcd 中存储时的另一个 version

```go
// k8s.io/kubernetes/staging/src/k8s.io/apiserver/pkg/endpoints/handlers/create.go:196
// CreateNamedResource returns a function that will handle a resource creation with name.
func CreateNamedResource(r rest.NamedCreater, scope *RequestScope, admission admission.Interface) http.HandlerFunc {
	return createHandler(r, scope, admission, true)
}

// k8s.io/kubernetes/staging/src/k8s.io/apiserver/pkg/endpoints/handlers/create.go:47
func createHandler(r rest.NamedCreater, scope *RequestScope, admit admission.Interface, includeName bool) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// For performance tracking purposes.
		trace := utiltrace.New("Create", utiltrace.Field{Key: "url", Value: req.URL.Path}, utiltrace.Field{Key: "user-agent", Value: &lazyTruncatedUserAgent{req}}, utiltrace.Field{Key: "client", Value: &lazyClientIP{req}})
		defer trace.LogIfLong(500 * time.Millisecond)

		if isDryRun(req.URL) && !utilfeature.DefaultFeatureGate.Enabled(features.DryRun) {
			scope.err(errors.NewBadRequest("the dryRun feature is disabled"), w, req)
			return
		}

		// TODO: we either want to remove timeout or document it (if we document, move timeout out of this function and declare it in api_installer)
		timeout := parseTimeout(req.URL.Query().Get("timeout"))

		namespace, name, err := scope.Namer.Name(req)
		if err != nil {
			if includeName {
				// name was required, return
				scope.err(err, w, req)
				return
			}

			// otherwise attempt to look up the namespace
			namespace, err = scope.Namer.Namespace(req)
			if err != nil {
				scope.err(err, w, req)
				return
			}
		}

		ctx, cancel := context.WithTimeout(req.Context(), timeout)
		defer cancel()
		ctx = request.WithNamespace(ctx, namespace)
		outputMediaType, _, err := negotiation.NegotiateOutputMediaType(req, scope.Serializer, scope)
		if err != nil {
			scope.err(err, w, req)
			return
		}

		gv := scope.Kind.GroupVersion()
		s, err := negotiation.NegotiateInputSerializer(req, false, scope.Serializer)
		if err != nil {
			scope.err(err, w, req)
			return
		}

		decoder := scope.Serializer.DecoderToVersion(s.Serializer, scope.HubGroupVersion)

		body, err := limitedReadBody(req, scope.MaxRequestBodyBytes)
		if err != nil {
			scope.err(err, w, req)
			return
		}

		options := &metav1.CreateOptions{}
		values := req.URL.Query()
		if err := metainternalversionscheme.ParameterCodec.DecodeParameters(values, scope.MetaGroupVersion, options); err != nil {
			err = errors.NewBadRequest(err.Error())
			scope.err(err, w, req)
			return
		}
		if errs := validation.ValidateCreateOptions(options); len(errs) > 0 {
			err := errors.NewInvalid(schema.GroupKind{Group: metav1.GroupName, Kind: "CreateOptions"}, "", errs)
			scope.err(err, w, req)
			return
		}
		options.TypeMeta.SetGroupVersionKind(metav1.SchemeGroupVersion.WithKind("CreateOptions"))

		defaultGVK := scope.Kind
		original := r.New()
		trace.Step("About to convert to expected version")
		// Decode
		obj, gvk, err := decoder.Decode(body, &defaultGVK, original)
		if err != nil {
			err = transformDecodeError(scope.Typer, err, original, gvk, body)
			scope.err(err, w, req)
			return
		}
		if gvk.GroupVersion() != gv {
			err = errors.NewBadRequest(fmt.Sprintf("the API version in the data (%s) does not match the expected API version (%v)", gvk.GroupVersion().String(), gv.String()))
			scope.err(err, w, req)
			return
		}
		trace.Step("Conversion done")

		ae := request.AuditEventFrom(ctx)
		admit = admission.WithAudit(admit, ae)
		audit.LogRequestObject(ae, obj, scope.Resource, scope.Subresource, scope.Serializer)

		userInfo, _ := request.UserFrom(ctx)

		// On create, get name from new object if unset
		if len(name) == 0 {
			_, name, _ = scope.Namer.ObjectName(obj)
		}

		trace.Step("About to store object in database")
		admissionAttributes := admission.NewAttributesRecord(obj, nil, scope.Kind, namespace, name, scope.Resource, scope.Subresource, admission.Create, options, dryrun.IsDryRun(options.DryRun), userInfo)
		requestFunc := func() (runtime.Object, error) {
			return r.Create(
				ctx,
				name,
				obj,
				rest.AdmissionToValidateObjectFunc(admit, admissionAttributes, scope),
				options,
			)
		}
		result, err := finishRequest(timeout, func() (runtime.Object, error) {
			if scope.FieldManager != nil {
				liveObj, err := scope.Creater.New(scope.Kind)
				if err != nil {
					return nil, fmt.Errorf("failed to create new object (Create for %v): %v", scope.Kind, err)
				}
				obj, err = scope.FieldManager.Update(liveObj, obj, managerOrUserAgent(options.FieldManager, req.UserAgent()))
				if err != nil {
					return nil, fmt.Errorf("failed to update object (Create for %v) managed fields: %v", scope.Kind, err)
				}
			}
			if mutatingAdmission, ok := admit.(admission.MutationInterface); ok && mutatingAdmission.Handles(admission.Create) {
				if err := mutatingAdmission.Admit(ctx, admissionAttributes, scope); err != nil {
					return nil, err
				}
			}
			result, err := requestFunc()
			// If the object wasn't committed to storage because it's serialized size was too large,
			// it is safe to remove managedFields (which can be large) and try again.
			if isTooLargeError(err) {
				if accessor, accessorErr := meta.Accessor(obj); accessorErr == nil {
					accessor.SetManagedFields(nil)
					result, err = requestFunc()
				}
			}
			return result, err
		})
		if err != nil {
			scope.err(err, w, req)
			return
		}
		trace.Step("Object stored in database")

		code := http.StatusCreated
		status, ok := result.(*metav1.Status)
		if ok && err == nil && status.Code == 0 {
			status.Code = int32(code)
		}

		transformResponseObject(ctx, scope, trace, req, w, code, outputMediaType, result)
	}
}

// k8s.io/kubernetes/staging/src/k8s.io/apiserver/pkg/registry/generic/registry/store.go:337
// Create inserts a new item according to the unique key from the object.
func (e *Store) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	if err := rest.BeforeCreate(e.CreateStrategy, ctx, obj); err != nil {
		return nil, err
	}
	// at this point we have a fully formed object.  It is time to call the validators that the apiserver
	// handling chain wants to enforce.
	if createValidation != nil {
		// Validation
		if err := createValidation(ctx, obj.DeepCopyObject()); err != nil {
			return nil, err
		}
	}

	name, err := e.ObjectNameFunc(obj)
	if err != nil {
		return nil, err
	}
	key, err := e.KeyFunc(ctx, name)
	if err != nil {
		return nil, err
	}
	qualifiedResource := e.qualifiedResourceFromContext(ctx)
	ttl, err := e.calculateTTL(obj, 0, false)
	if err != nil {
		return nil, err
	}
	out := e.NewFunc()
	if err := e.Storage.Create(ctx, key, obj, out, ttl, dryrun.IsDryRun(options.DryRun)); err != nil {
		err = storeerr.InterpretCreateError(err, qualifiedResource, name)
		err = rest.CheckGeneratedNameError(e.CreateStrategy, err, obj)
		if !apierrors.IsAlreadyExists(err) {
			return nil, err
		}
		if errGet := e.Storage.Get(ctx, key, "", out, false); errGet != nil {
			return nil, err
		}
		accessor, errGetAcc := meta.Accessor(out)
		if errGetAcc != nil {
			return nil, err
		}
		if accessor.GetDeletionTimestamp() != nil {
			msg := &err.(*apierrors.StatusError).ErrStatus.Message
			*msg = fmt.Sprintf("object is being deleted: %s", *msg)
		}
		return nil, err
	}
	if e.AfterCreate != nil {
		if err := e.AfterCreate(out); err != nil {
			return nil, err
		}
	}
	if e.Decorator != nil {
		if err := e.Decorator(out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// k8s.io/kubernetes/staging/src/k8s.io/apiserver/pkg/storage/etcd3/store.go:143
// Create implements storage.Interface.Create.
func (s *store) Create(ctx context.Context, key string, obj, out runtime.Object, ttl uint64) error {
	if version, err := s.versioner.ObjectResourceVersion(obj); err == nil && version != 0 {
		return errors.New("resourceVersion should not be set on objects to be created")
	}
	if err := s.versioner.PrepareObjectForStorage(obj); err != nil {
		return fmt.Errorf("PrepareObjectForStorage failed: %v", err)
	}
	// Encode
	data, err := runtime.Encode(s.codec, obj)
	if err != nil {
		return err
	}
	key = path.Join(s.pathPrefix, key)

	opts, err := s.ttlOpts(ctx, int64(ttl))
	if err != nil {
		return err
	}

	newData, err := s.transformer.TransformToStorage(data, authenticatedDataString(key))
	if err != nil {
		return storage.NewInternalError(err.Error())
	}

	startTime := time.Now()
	txnResp, err := s.client.KV.Txn(ctx).If(
		notFound(key),
	).Then(
		clientv3.OpPut(key, string(newData), opts...),
	).Commit()
	metrics.RecordEtcdRequestLatency("create", getTypeName(obj), startTime)
	if err != nil {
		return err
	}
	if !txnResp.Succeeded {
		return storage.NewKeyExistsError(key, 0)
	}

	if out != nil {
		putResp := txnResp.Responses[0].GetResponsePut()
		return decode(s.codec, s.versioner, data, out, putResp.Header.Revision)
	}
	return nil
}
```

kubeAPIServer代码结构整理如下：

```bash
apiserver整体启动逻辑 k8s.io/kubernetes/cmd/kube-apiserver
apiserver bootstrap-controller创建&运行逻辑 k8s.io/kubernetes/pkg/master
API Resource对应后端RESTStorage(based on genericregistry.Store)创建 k8s.io/kubernetes/pkg/registry
aggregated-apiserver创建&处理逻辑 k8s.io/kubernetes/staging/src/k8s.io/kube-aggregator
extensions-apiserver创建&处理逻辑 k8s.io/kubernetes/staging/src/k8s.io/apiextensions-apiserver
apiserver创建&运行 k8s.io/kubernetes/staging/src/k8s.io/apiserver/pkg/server
注册API Resource资源处理handler(InstallREST&Install&registerResourceHandlers) k8s.io/kubernetes/staging/src/k8s.io/apiserver/pkg/endpoints
创建存储后端(etcdv3) k8s.io/kubernetes/staging/src/k8s.io/apiserver/pkg/storage
genericregistry.Store.CompleteWithOptions初始化 k8s.io/kubernetes/staging/src/k8s.io/apiserver/pkg/registry
```

调用链整理如下：

```bash
                    |--> CreateNodeDialer
                    |
                    |--> CreateKubeAPIServerConfig
                    |
CreateServerChain --|--> createAPIExtensionsConfig
                    |
                    |                                                                       |--> c.GenericConfig.New
                    |--> createAPIExtensionsServer --> apiextensionsConfig.Complete().New --|
                    |                                                                       |--> s.GenericAPIServer.InstallAPIGroup
                    |
                    |                                                                 |--> c.GenericConfig.New
                    |                                                                 |
                    |--> CreateKubeAPIServer --> kubeAPIServerConfig.Complete().New --|--> m.InstallLegacyAPI --> legacyRESTStorageProvider.NewLegacyRESTStorage --> m.GenericAPIServer.InstallLegacyAPIGroup
                    |                                                                 |
                    |                                                                 |--> m.InstallAPIs --> restStorageBuilder.NewRESTStorage --> m.GenericAPIServer.InstallAPIGroups
                    |
                    |
                    |--> createAggregatorConfig
                    |
                    |                                                                             |--> c.GenericConfig.New
                    |                                                                             |
                    |--> createAggregatorServer --> aggregatorConfig.Complete().NewWithDelegate --|--> apiservicerest.NewRESTStorage
                                                                                                  |
                                                                                                  |--> s.GenericAPIServer.InstallAPIGroup
```

更多代码原理详情，参考[kubernetes-reading-notes](https://github.com/duyanghao/kubernetes-reading-notes/tree/master/core/api-server)

## aggregatorServer

aggregatorServer主要用于处理扩展Kubernetes API Resources的第二种方式Aggregated APIServer(AA)，将CR请求代理给AA：

![Extension apiservers](https://github.com/kubernetes-sigs/apiserver-builder-alpha/raw/master/docs/concepts/extensionserver.jpg)

这里结合Kubernetes官方给出的aggregated apiserver例子[sample-apiserver](https://github.com/kubernetes/sample-apiserver)，总结原理如下：

* aggregatorServer通过APIServices对象关联到某个Service来进行请求的转发，其关联的Service类型进一步决定了请求转发的形式。aggregatorServer包括一个 `GenericAPIServer` 和维护自身状态的Controller。其中 `GenericAPIServer` 主要处理 `apiregistration.k8s.io` 组下的APIService资源请求，而Controller包括：
  - `apiserviceRegistrationController`：负责根据APIService定义的aggregated server service构建代理，将CR的请求转发给后端的aggregated server
  - `availableConditionController`：维护 APIServices 的可用状态，包括其引用 Service 是否可用等；
  - `autoRegistrationController`：用于保持 API 中存在的一组特定的 APIServices；
  - `crdRegistrationController`：负责将 CRD GroupVersions 自动注册到 APIServices 中；
  - `openAPIAggregationController`：将 APIServices 资源的变化同步至提供的 OpenAPI 文档；
* apiserviceRegistrationController负责根据APIService定义的aggregated server service构建代理，将CR的请求转发给后端的aggregated server。apiService有两种类型：Local(Service为空)以及Service(Service非空)。apiserviceRegistrationController负责对这两种类型apiService设置代理：Local类型会直接路由给kube-apiserver进行处理；而Service类型则会设置代理并将请求转化为对aggregated Service的请求(proxyPath := "/apis/" + apiService.Spec.Group + "/" + apiService.Spec.Version)，而请求的负载均衡策略则是优先本地访问kube-apiserver(如果service为kubernetes default apiserver service:443)=>通过service ClusterIP:Port访问(默认) 或者 通过随机选择service endpoint backend进行访问：
  ```go
  // k8s.io/kubernetes/staging/src/k8s.io/kube-aggregator/pkg/apiserver/apiserver.go:285
  // AddAPIService adds an API service.  It is not thread-safe, so only call it on one thread at a time please.
  // It's a slow moving API, so its ok to run the controller on a single thread
  func (s *APIAggregator) AddAPIService(apiService *v1.APIService) error {
  	// if the proxyHandler already exists, it needs to be updated. The aggregation bits do not
  	// since they are wired against listers because they require multiple resources to respond
  	if proxyHandler, exists := s.proxyHandlers[apiService.Name]; exists {
  		proxyHandler.updateAPIService(apiService)
  		if s.openAPIAggregationController != nil {
  			s.openAPIAggregationController.UpdateAPIService(proxyHandler, apiService)
  		}
  		return nil
  	}
  
  	proxyPath := "/apis/" + apiService.Spec.Group + "/" + apiService.Spec.Version
  	// v1. is a special case for the legacy API.  It proxies to a wider set of endpoints.
  	if apiService.Name == legacyAPIServiceName {
  		proxyPath = "/api"
  	}
  
  	// register the proxy handler
  	proxyHandler := &proxyHandler{
  		localDelegate:   s.delegateHandler,
  		proxyClientCert: s.proxyClientCert,
  		proxyClientKey:  s.proxyClientKey,
  		proxyTransport:  s.proxyTransport,
  		serviceResolver: s.serviceResolver,
  		egressSelector:  s.egressSelector,
  	}
  	proxyHandler.updateAPIService(apiService)
  	if s.openAPIAggregationController != nil {
  		s.openAPIAggregationController.AddAPIService(proxyHandler, apiService)
  	}
  	s.proxyHandlers[apiService.Name] = proxyHandler
  	s.GenericAPIServer.Handler.NonGoRestfulMux.Handle(proxyPath, proxyHandler)
  	s.GenericAPIServer.Handler.NonGoRestfulMux.UnlistedHandlePrefix(proxyPath+"/", proxyHandler)
  
  	// if we're dealing with the legacy group, we're done here
  	if apiService.Name == legacyAPIServiceName {
  		return nil
  	}
  
  	// if we've already registered the path with the handler, we don't want to do it again.
  	if s.handledGroups.Has(apiService.Spec.Group) {
  		return nil
  	}
  
  	// it's time to register the group aggregation endpoint
  	groupPath := "/apis/" + apiService.Spec.Group
  	groupDiscoveryHandler := &apiGroupHandler{
  		codecs:    aggregatorscheme.Codecs,
  		groupName: apiService.Spec.Group,
  		lister:    s.lister,
  		delegate:  s.delegateHandler,
  	}
  	// aggregation is protected
  	s.GenericAPIServer.Handler.NonGoRestfulMux.Handle(groupPath, groupDiscoveryHandler)
  	s.GenericAPIServer.Handler.NonGoRestfulMux.UnlistedHandle(groupPath+"/", groupDiscoveryHandler)
  	s.handledGroups.Insert(apiService.Spec.Group)
  	return nil
  }
  
  // k8s.io/kubernetes/staging/src/k8s.io/kube-aggregator/pkg/apiserver/handler_proxy.go:109
  func (r *proxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
  	// 加载roxyHandlingInfo处理请求  
  	value := r.handlingInfo.Load()
  	if value == nil {
  		r.localDelegate.ServeHTTP(w, req)
  		return
  	}
  	handlingInfo := value.(proxyHandlingInfo)
  	if handlingInfo.local {
  		if r.localDelegate == nil {
  			http.Error(w, "", http.StatusNotFound)
  			return
  		}
  		r.localDelegate.ServeHTTP(w, req)
  		return
  	}
  	// 判断APIService服务是否正常
  	if !handlingInfo.serviceAvailable {
  		proxyError(w, req, "service unavailable", http.StatusServiceUnavailable)
  		return
  	}
  
  	if handlingInfo.transportBuildingError != nil {
  		proxyError(w, req, handlingInfo.transportBuildingError.Error(), http.StatusInternalServerError)
  		return
  	}
  
  	// 从请求解析用户  
  	user, ok := genericapirequest.UserFrom(req.Context())
  	if !ok {
  		proxyError(w, req, "missing user", http.StatusInternalServerError)
  		return
  	}
  
  	// 将原始请求转化为对APIService的请求
  	// write a new location based on the existing request pointed at the target service
  	location := &url.URL{}
  	location.Scheme = "https"
  	rloc, err := r.serviceResolver.ResolveEndpoint(handlingInfo.serviceNamespace, handlingInfo.serviceName, handlingInfo.servicePort)
  	if err != nil {
  		klog.Errorf("error resolving %s/%s: %v", handlingInfo.serviceNamespace, handlingInfo.serviceName, err)
  		proxyError(w, req, "service unavailable", http.StatusServiceUnavailable)
  		return
  	}
  	location.Host = rloc.Host
  	location.Path = req.URL.Path
  	location.RawQuery = req.URL.Query().Encode()
  
  	newReq, cancelFn := newRequestForProxy(location, req)
  	defer cancelFn()
  
  	if handlingInfo.proxyRoundTripper == nil {
  		proxyError(w, req, "", http.StatusNotFound)
  		return
  	}
  
  	// we need to wrap the roundtripper in another roundtripper which will apply the front proxy headers
  	proxyRoundTripper, upgrade, err := maybeWrapForConnectionUpgrades(handlingInfo.restConfig, handlingInfo.proxyRoundTripper, req)
  	if err != nil {
  		proxyError(w, req, err.Error(), http.StatusInternalServerError)
  		return
  	}
  	proxyRoundTripper = transport.NewAuthProxyRoundTripper(user.GetName(), user.GetGroups(), user.GetExtra(), proxyRoundTripper)
  
  	// if we are upgrading, then the upgrade path tries to use this request with the TLS config we provide, but it does
  	// NOT use the roundtripper.  Its a direct call that bypasses the round tripper.  This means that we have to
  	// attach the "correct" user headers to the request ahead of time.  After the initial upgrade, we'll be back
  	// at the roundtripper flow, so we only have to muck with this request, but we do have to do it.
  	if upgrade {
  		transport.SetAuthProxyHeaders(newReq, user.GetName(), user.GetGroups(), user.GetExtra())
  	}
  
  	handler := proxy.NewUpgradeAwareHandler(location, proxyRoundTripper, true, upgrade, &responder{w: w})
  	handler.ServeHTTP(w, newReq)
  }
  ```

  ```bash
  $ kubectl get APIService           
  NAME                                   SERVICE                      AVAILABLE   AGE
  ...
  v1.apps                                Local                        True        50d
  ...
  v1beta1.metrics.k8s.io                 kube-system/metrics-server   True        50d
  ...
  ```
  
  ```yaml
  # default APIServices
  $ kubectl get -o yaml APIService/v1.apps
  apiVersion: apiregistration.k8s.io/v1
  kind: APIService
  metadata:
    creationTimestamp: "2020-10-20T10:39:48Z"
    labels:
      kube-aggregator.kubernetes.io/automanaged: onstart
    name: v1.apps
    resourceVersion: "16"
    selfLink: /apis/apiregistration.k8s.io/v1/apiservices/v1.apps
    uid: 09374c3d-db49-45e1-8524-1bd8f86daaae
  spec:
    group: apps
    groupPriorityMinimum: 17800
    version: v1
    versionPriority: 15
  status:
    conditions:
    - lastTransitionTime: "2020-10-20T10:39:48Z"
      message: Local APIServices are always available
      reason: Local
      status: "True"
      type: Available
      
  # aggregated server    
  $ kubectl get -o yaml APIService/v1beta1.metrics.k8s.io
  apiVersion: apiregistration.k8s.io/v1
  kind: APIService
  metadata:
    creationTimestamp: "2020-10-20T10:43:12Z"
    labels:
      addonmanager.kubernetes.io/mode: Reconcile
      kubernetes.io/cluster-service: "true"
    name: v1beta1.metrics.k8s.io
    resourceVersion: "35484437"
    selfLink: /apis/apiregistration.k8s.io/v1/apiservices/v1beta1.metrics.k8s.io
    uid: b16f7fb6-8aa1-475c-b616-fdbd9402bac2
  spec:
    group: metrics.k8s.io
    groupPriorityMinimum: 100
    insecureSkipTLSVerify: true
    service:
      name: metrics-server
      namespace: kube-system
      port: 443
    version: v1beta1
    versionPriority: 100
  status:
    conditions:
    - lastTransitionTime: "2020-12-05T00:50:48Z"
      message: all checks passed
      reason: Passed
      status: "True"
      type: Available
  
  # CRD
  $ kubectl get -o yaml APIService/v1.duyanghao.example.com
  apiVersion: apiregistration.k8s.io/v1
  kind: APIService
  metadata:
    creationTimestamp: "2020-12-11T08:45:37Z"
    labels:
      kube-aggregator.kubernetes.io/automanaged: "true"
    name: v1.duyanghao.example.com
    resourceVersion: "40788945"
    selfLink: /apis/apiregistration.k8s.io/v1/apiservices/v1.duyanghao.example.com
    uid: 9da804ac-e9f1-406b-b253-b1d13e0bb725
  spec:
    group: duyanghao.example.com
    groupPriorityMinimum: 1000
    version: v1
    versionPriority: 100
  status:
    conditions:
    - lastTransitionTime: "2020-12-11T08:45:37Z"
      message: Local APIServices are always available
      reason: Local
      status: "True"
      type: Available
  ```
* aggregatorServer创建过程中会根据所有kube-apiserver定义的API资源创建默认的APIService列表，名称即是$VERSION/$GROUP，这些APIService都会有标签`kube-aggregator.kubernetes.io/automanaged: onstart`，例如：v1.apps apiService。autoRegistrationController创建并维护这些列表中的APIService，也即我们看到的Local apiService；对于自定义的APIService(aggregated server)，则不会对其进行处理
* aggregated server实现CR(自定义API资源) 的CRUD API接口，并可以灵活选择后端存储，可以与core kube-apiserver一起公用etcd，也可自己独立部署etcd数据库或者其它数据库。aggregated server实现的CR API路径为：/apis/$GROUP/$VERSION，具体到sample apiserver为：/apis/wardle.example.com/v1alpha1，下面的资源类型有：flunders以及fischers
* aggregated server通过部署APIService类型资源，service fields指向对应的aggregated server service实现与core kube-apiserver的集成与交互
* sample-apiserver目录结构如下，可参考编写自己的aggregated server：
  ```bash
  staging/src/k8s.io/sample-apiserver
  ├── artifacts
  │   ├── example
  │   │   ├── apiservice.yaml
  │   │   ├── auth-delegator.yaml
  │   │   ├── auth-reader.yaml
  │   │   ├── deployment.yaml
  │   │   ├── ns.yaml
  │   │   ├── rbac-bind.yaml
  │   │   ├── rbac.yaml
  │   │   ├── sa.yaml
  │   │   └── service.yaml
  │   ├── flunders
  │   │   └── 01-flunder.yaml
  │   └── simple-image
  │       └── Dockerfile
  ├── hack
  │   ├── build-image.sh
  │   ├── update-codegen.sh
  │   └── verify-codegen.sh
  ├── main.go
  └── pkg
      ├── admission
      ├── apis
      │   └── wardle
      │       ├── register.go
      │       ├── types.go
      │       ├── v1alpha1
      │       │   ├── BUILD
      │       │   ├── conversion.go
      │       │   ├── defaults.go
      │       │   ├── doc.go
      │       │   ├── register.go
      │       │   ├── types.go
      │       │   ├── zz_generated.conversion.go
      │       │   ├── zz_generated.deepcopy.go
      │       │   └── zz_generated.defaults.go
      │       ├── v1beta1
      │       │   ├── BUILD
      │       │   ├── doc.go
      │       │   ├── register.go
      │       │   ├── types.go
      │       │   ├── zz_generated.conversion.go
      │       │   ├── zz_generated.deepcopy.go
      │       │   └── zz_generated.defaults.go
      │       ├── validation
      │       │   ├── BUILD
      │       │   └── validation.go
      │       └── zz_generated.deepcopy.go
      ├── apiserver
      │   ├── BUILD
      │   ├── apiserver.go
      │   └── scheme_test.go
      ├── cmd
      │   └── server
      │       ├── BUILD
      │       └── start.go
      ├── generated
      │   ├── clientset
      │   │   └── versioned
      │   │       ├── BUILD
      │   │       ├── clientset.go
      │   │       ├── doc.go
      │   │       ├── fake
      │   │       │   ├── BUILD
      │   │       │   ├── clientset_generated.go
      │   │       │   ├── doc.go
      │   │       │   └── register.go
      │   │       ├── scheme
      │   │       │   ├── BUILD
      │   │       │   ├── doc.go
      │   │       │   └── register.go
      │   │       └── typed
      │   │           └── wardle
      │   │               ├── v1alpha1
      │   │               │   ├── BUILD
      │   │               │   ├── doc.go
      │   │               │   ├── fake
      │   │               │   │   ├── BUILD
      │   │               │   │   ├── doc.go
      │   │               │   │   ├── fake_fischer.go
      │   │               │   │   ├── fake_flunder.go
      │   │               │   │   └── fake_wardle_client.go
      │   │               │   ├── fischer.go
      │   │               │   ├── flunder.go
      │   │               │   ├── generated_expansion.go
      │   │               │   └── wardle_client.go
      │   │               └── v1beta1
      │   │                   ├── BUILD
      │   │                   ├── doc.go
      │   │                   ├── fake
      │   │                   │   ├── BUILD
      │   │                   │   ├── doc.go
      │   │                   │   ├── fake_flunder.go
      │   │                   │   └── fake_wardle_client.go
      │   │                   ├── flunder.go
      │   │                   ├── generated_expansion.go
      │   │                   └── wardle_client.go
      │   ├── informers
      │   │   └── externalversions
      │   │       ├── BUILD
      │   │       ├── factory.go
      │   │       ├── generic.go
      │   │       ├── internalinterfaces
      │   │       │   ├── BUILD
      │   │       │   └── factory_interfaces.go
      │   │       └── wardle
      │   │           ├── BUILD
      │   │           ├── interface.go
      │   │           ├── v1alpha1
      │   │           │   ├── BUILD
      │   │           │   ├── fischer.go
      │   │           │   ├── flunder.go
      │   │           │   └── interface.go
      │   │           └── v1beta1
      │   │               ├── BUILD
      │   │               ├── flunder.go
      │   │               └── interface.go
      │   ├── listers
      │   │   └── wardle
      │   │       ├── v1alpha1
      │   │       │   ├── BUILD
      │   │       │   ├── expansion_generated.go
      │   │       │   ├── fischer.go
      │   │       │   └── flunder.go
      │   │       └── v1beta1
      │   │           ├── BUILD
      │   │           ├── expansion_generated.go
      │   │           └── flunder.go
      │   └── openapi
      │       ├── BUILD
      │       └── zz_generated.openapi.go
      └── registry
          ├── BUILD
          ├── registry.go
          └── wardle
              ├── fischer
              │   ├── BUILD
              │   ├── etcd.go
              │   └── strategy.go
              └── flunder
                  ├── BUILD
                  ├── etcd.go
                  └── strategy.go
  ```
  * 其中，artifacts用于部署yaml示例
  * hack目录存放自动脚本(eg: update-codegen)
  * main.go是aggregated server启动入口；pkg/cmd负责启动aggregated server具体逻辑；pkg/apiserver用于aggregated server初始化以及路由注册
  * pkg/apis负责相关CR的结构体定义，自动生成(update-codegen)
  * pkg/admission负责准入的相关代码
  * pkg/generated负责生成访问CR的clientset，informers，以及listers
  * pkg/registry目录负责CR相关的RESTStorage实现

更多代码原理详情，参考[kubernetes-reading-notes](https://github.com/duyanghao/kubernetes-reading-notes/tree/master/core/api-server)

## apiExtensionsServer

apiExtensionsServer主要负责CustomResourceDefinition（CRD）apiResources以及apiVersions的注册，同时处理CRD以及相应CustomResource（CR）的REST请求(如果对应CR不能被处理的话则会返回404)，也是apiserver Delegation的最后一环

原理总结如下：

* Custom Resource，简称CR，是Kubernetes自定义资源类型，与之相对应的就是Kubernetes内置的各种资源类型，例如Pod、Service等。利用CR我们可以定义任何想要的资源类型
* CRD通过yaml文件的形式向Kubernetes注册CR实现自定义api-resources，属于第二种扩展Kubernetes API资源的方式，也是普遍使用的一种
* APIExtensionServer负责CustomResourceDefinition（CRD）apiResources以及apiVersions的注册，同时处理CRD以及相应CustomResource（CR）的REST请求(如果对应CR不能被处理的话则会返回404)，也是apiserver Delegation的最后一环
* `crdRegistrationController`负责将CRD GroupVersions自动注册到APIServices中。具体逻辑为：枚举所有CRDs，然后根据CRD定义的crd.Spec.Group以及crd.Spec.Versions字段构建APIService，并添加到autoRegisterController.apiServicesToSync中，由autoRegisterController进行创建以及维护操作。这也是为什么创建完CRD后会产生对应的APIService对象
* APIExtensionServer包含的controller以及功能如下所示：
  - `openapiController`：将 crd 资源的变化同步至提供的 OpenAPI 文档，可通过访问 `/openapi/v2` 进行查看；
  - `crdController`：负责将 crd 信息注册到 apiVersions 和 apiResources 中，两者的信息可通过 `kubectl api-versions` 和 `kubectl api-resources` 查看：
    * `kubectl api-versions`命令返回所有Kubernetes集群资源的版本信息(实际发出了两个请求，分别是`https://127.0.0.1:6443/api`以及`https://127.0.0.1:6443/apis`，并在最后将两个请求的返回结果进行了合并)
      ```bash
      $ kubectl -v=8 api-versions 
      I1211 11:44:50.276446   22493 loader.go:375] Config loaded from file:  /root/.kube/config
      I1211 11:44:50.277005   22493 round_trippers.go:420] GET https://127.0.0.1:6443/api?timeout=32s
      I1211 11:44:50.277026   22493 round_trippers.go:427] Request Headers:
      I1211 11:44:50.277045   22493 round_trippers.go:431]     User-Agent: kubectl/v1.18.3 (linux/amd64) kubernetes/2e7996e
      I1211 11:44:50.277055   22493 round_trippers.go:431]     Authorization: Bearer <masked>
      I1211 11:44:50.277064   22493 round_trippers.go:431]     Accept: application/json, */*
      I1211 11:44:50.281865   22493 round_trippers.go:446] Response Status: 200 OK in 4 milliseconds
      I1211 11:44:50.281918   22493 round_trippers.go:449] Response Headers:
      I1211 11:44:50.281931   22493 round_trippers.go:452]     Cache-Control: no-cache, private
      I1211 11:44:50.281950   22493 round_trippers.go:452]     Content-Type: application/json
      I1211 11:44:50.281961   22493 round_trippers.go:452]     Content-Length: 135
      I1211 11:44:50.281977   22493 round_trippers.go:452]     Date: Fri, 11 Dec 2020 03:44:50 GMT
      I1211 11:44:50.290265   22493 request.go:1068] Response Body: {"kind":"APIVersions","versions":["v1"],"serverAddressByClientCIDRs":[{"clientCIDR":"0.0.0.0/0","serverAddress":"x.x.x.x:6443"}]}
      I1211 11:44:50.293673   22493 round_trippers.go:420] GET https://127.0.0.1:6443/apis?timeout=32s
      I1211 11:44:50.293695   22493 round_trippers.go:427] Request Headers:
      I1211 11:44:50.293722   22493 round_trippers.go:431]     Accept: application/json, */*
      I1211 11:44:50.293730   22493 round_trippers.go:431]     User-Agent: kubectl/v1.18.3 (linux/amd64) kubernetes/2e7996e
      I1211 11:44:50.293750   22493 round_trippers.go:431]     Authorization: Bearer <masked>
      I1211 11:44:50.294415   22493 round_trippers.go:446] Response Status: 200 OK in 0 milliseconds
      I1211 11:44:50.294436   22493 round_trippers.go:449] Response Headers:
      I1211 11:44:50.294443   22493 round_trippers.go:452]     Cache-Control: no-cache, private
      I1211 11:44:50.294452   22493 round_trippers.go:452]     Content-Type: application/json
      I1211 11:44:50.294459   22493 round_trippers.go:452]     Date: Fri, 11 Dec 2020 03:44:50 GMT
      I1211 11:44:50.298360   22493 request.go:1068] Response Body: {"kind":"APIGroupList","apiVersion":"v1","groups":[{"name":"apiregistration.k8s.io","versions":[{"groupVersion":"apiregistration.k8s.io/v1","version":"v1"},{"groupVersion":"apiregistration.k8s.io/v1beta1","version":"v1beta1"}],"preferredVersion":{"groupVersion":"apiregistration.k8s.io/v1","version":"v1"}},{"name":"extensions","versions":[{"groupVersion":"extensions/v1beta1","version":"v1beta1"}],"preferredVersion":{"groupVersion":"extensions/v1beta1","version":"v1beta1"}},{"name":"apps","versions":[{"groupVersion":"apps/v1","version":"v1"}],"preferredVersion":{"groupVersion":"apps/v1","version":"v1"}},{"name":"events.k8s.io","versions":[{"groupVersion":"events.k8s.io/v1beta1","version":"v1beta1"}],"preferredVersion":{"groupVersion":"events.k8s.io/v1beta1","version":"v1beta1"}},{"name":"authentication.k8s.io","versions":[{"groupVersion":"authentication.k8s.io/v1","version":"v1"},{"groupVersion":"authentication.k8s.io/v1beta1","version":"v1beta1"}],"preferredVersion":{"groupVersion":"authentication.k8s.io/v1"," [truncated 4985 chars]
      admissionregistration.k8s.io/v1
      admissionregistration.k8s.io/v1beta1
      apiextensions.k8s.io/v1
      apiextensions.k8s.io/v1beta1
      apiregistration.k8s.io/v1
      apiregistration.k8s.io/v1beta1
      apps/v1
      auth.tkestack.io/v1
      authentication.k8s.io/v1
      authentication.k8s.io/v1beta1
      ...
      storage.k8s.io/v1
      storage.k8s.io/v1beta1
      v1
      ```
    * `kubectl api-resources`命令就是先获取所有API版本信息，然后对每一个API版本调用接口获取该版本下的所有API资源类型
      ```bash
      $ kubectl -v=8 api-resources
      5077 loader.go:375] Config loaded from file:  /root/.kube/config
      I1211 15:19:47.593450   15077 round_trippers.go:420] GET https://127.0.0.1:6443/api?timeout=32s
      I1211 15:19:47.593470   15077 round_trippers.go:427] Request Headers:
      I1211 15:19:47.593480   15077 round_trippers.go:431]     Accept: application/json, */*
      I1211 15:19:47.593489   15077 round_trippers.go:431]     User-Agent: kubectl/v1.18.3 (linux/amd64) kubernetes/2e7996e
      I1211 15:19:47.593522   15077 round_trippers.go:431]     Authorization: Bearer <masked>
      I1211 15:19:47.598055   15077 round_trippers.go:446] Response Status: 200 OK in 4 milliseconds
      I1211 15:19:47.598077   15077 round_trippers.go:449] Response Headers:
      I1211 15:19:47.598088   15077 round_trippers.go:452]     Cache-Control: no-cache, private
      I1211 15:19:47.598120   15077 round_trippers.go:452]     Content-Type: application/json
      I1211 15:19:47.598131   15077 round_trippers.go:452]     Content-Length: 135
      I1211 15:19:47.598147   15077 round_trippers.go:452]     Date: Fri, 11 Dec 2020 07:19:47 GMT
      I1211 15:19:47.602273   15077 request.go:1068] Response Body: {"kind":"APIVersions","versions":["v1"],"serverAddressByClientCIDRs":[{"clientCIDR":"0.0.0.0/0","serverAddress":"x.x.x.x:6443"}]}
      I1211 15:19:47.606279   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis?timeout=32s
      I1211 15:19:47.606299   15077 round_trippers.go:427] Request Headers:
      I1211 15:19:47.606334   15077 round_trippers.go:431]     Accept: application/json, */*
      I1211 15:19:47.606343   15077 round_trippers.go:431]     User-Agent: kubectl/v1.18.3 (linux/amd64) kubernetes/2e7996e
      I1211 15:19:47.606362   15077 round_trippers.go:431]     Authorization: Bearer <masked>
      I1211 15:19:47.607007   15077 round_trippers.go:446] Response Status: 200 OK in 0 milliseconds
      I1211 15:19:47.607028   15077 round_trippers.go:449] Response Headers:
      I1211 15:19:47.607058   15077 round_trippers.go:452]     Date: Fri, 11 Dec 2020 07:19:47 GMT
      I1211 15:19:47.607070   15077 round_trippers.go:452]     Cache-Control: no-cache, private
      I1211 15:19:47.607089   15077 round_trippers.go:452]     Content-Type: application/json
      I1211 15:19:47.610333   15077 request.go:1068] Response Body: {"kind":"APIGroupList","apiVersion":"v1","groups":[{"name":"apiregistration.k8s.io","versions":[{"groupVersion":"apiregistration.k8s.io/v1","version":"v1"},{"groupVersion":"apiregistration.k8s.io/v1beta1","version":"v1beta1"}],"preferredVersion":{"groupVersion":"apiregistration.k8s.io/v1","version":"v1"}},{"name":"extensions","versions":[{"groupVersion":"extensions/v1beta1","version":"v1beta1"}],"preferredVersion":{"groupVersion":"extensions/v1beta1","version":"v1beta1"}},{"name":"apps","versions":[{"groupVersion":"apps/v1","version":"v1"}],"preferredVersion":{"groupVersion":"apps/v1","version":"v1"}},{"name":"events.k8s.io","versions":[{"groupVersion":"events.k8s.io/v1beta1","version":"v1beta1"}],"preferredVersion":{"groupVersion":"events.k8s.io/v1beta1","version":"v1beta1"}},{"name":"authentication.k8s.io","versions":[{"groupVersion":"authentication.k8s.io/v1","version":"v1"},{"groupVersion":"authentication.k8s.io/v1beta1","version":"v1beta1"}],"preferredVersion":{"groupVersion":"authentication.k8s.io/v1"," [truncated 4985 chars]
      I1211 15:19:47.614700   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/batch/v1?timeout=32s
      I1211 15:19:47.614804   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/authentication.k8s.io/v1?timeout=32s
      I1211 15:19:47.615687   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/auth.tkestack.io/v1?timeout=32s
      https://127.0.0.1:6443/apis/authentication.k8s.io/v1beta1?timeout=32s
      I1211 15:19:47.616794   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/coordination.k8s.io/v1?timeout=32s
      I1211 15:19:47.616863   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/apps/v1?timeout=32s
      I1211 15:19:47.616877   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/scheduling.k8s.io/v1beta1?timeout=32s
      I1211 15:19:47.617128   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/networking.k8s.io/v1beta1?timeout=32s
      ...
      I1211 15:19:47.617555   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/monitor.tkestack.io/v1?timeout=32s
      I1211 15:19:47.616542   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/networking.k8s.io/v1?timeout=32s
      I1211 15:19:47.617327   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/coordination.k8s.io/v1beta1?timeout=32s
      I1211 15:19:47.617412   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/monitoring.coreos.com/v1?timeout=32s
      I1211 15:19:47.617385   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/autoscaling/v2beta2?timeout=32s
      I1211 15:19:47.617852   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/discovery.k8s.io/v1beta1?timeout=32s
      I1211 15:19:47.618032   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/admissionregistration.k8s.io/v1?timeout=32s
      I1211 15:19:47.618125   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/apiregistration.k8s.io/v1?timeout=32s
      I1211 15:19:47.618317   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/authorization.k8s.io/v1beta1?timeout=32s
      I1211 15:19:47.616968   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/policy/v1beta1?timeout=32s
      I1211 15:19:47.617138   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/configuration.konghq.com/v1?timeout=32s
      I1211 15:19:47.616526   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/metrics.k8s.io/v1beta1?timeout=32s
      I1211 15:19:47.616789   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/events.k8s.io/v1beta1?timeout=32s
      I1211 15:19:47.618075   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/storage.k8s.io/v1beta1?timeout=32s
      I1211 15:19:47.618612   15077 round_trippers.go:420] GET https://127.0.0.1:6443/api/v1?timeout=32s
      I1211 15:19:47.618268   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/notify.tkestack.io/v1?timeout=32s
      I1211 15:19:47.618631   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/apiextensions.k8s.io/v1beta1?timeout=32s
      I1211 15:19:47.616594   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/node.k8s.io/v1beta1?timeout=32s
      I1211 15:19:47.616595   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/storage.k8s.io/v1?timeout=32s
      I1211 15:19:47.619458   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/apiregistration.k8s.io/v1beta1?timeout=32s
      I1211 15:19:47.619586   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/platform.tkestack.io/v1?timeout=32s
      I1211 15:19:47.616973   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/authorization.k8s.io/v1?timeout=32s
      ...
      I1211 15:19:47.617240   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/duyanghao.example.com/v1?timeout=32s
      I1211 15:19:47.617305   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/autoscaling/v2beta1?timeout=32s
      I1211 15:19:47.617321   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/rbac.authorization.k8s.io/v1beta1?timeout=32s
      I1211 15:19:47.617428   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/admissionregistration.k8s.io/v1beta1?timeout=32s
      I1211 15:19:47.617362   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/extensions/v1beta1?timeout=32s
      I1211 15:19:47.616554   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/scheduling.k8s.io/v1?timeout=32s
      I1211 15:19:47.618275   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/rbac.authorization.k8s.io/v1?timeout=32s
      I1211 15:19:47.618349   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/batch/v1beta1?timeout=32s
      I1211 15:19:47.618724   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/apiextensions.k8s.io/v1?timeout=32s
      I1211 15:19:47.618903   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/certificates.k8s.io/v1beta1?timeout=32s
      I1211 15:19:47.616721   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/autoscaling/v1?timeout=32s
      ...
      NAME                              SHORTNAMES   APIGROUP                       NAMESPACED   KIND
      bindings                                                                      true         Binding
      componentstatuses                 cs                                          false        ComponentStatus
      configmaps                        cm                                          true         ConfigMap
      endpoints                         ep                                          true         Endpoints
      events                            ev                                          true         Event
      limitranges                       limits                                      true         LimitRange
      namespaces                        ns                                          false        Namespace
      nodes                             no                                          false        Node
      persistentvolumeclaims            pvc                                         true         PersistentVolumeClaim
      persistentvolumes                 pv                                          false        PersistentVolume
      pods                              po                                          true         Pod
      podtemplates                                                                  true         PodTemplate
      replicationcontrollers            rc                                          true         ReplicationController
      resourcequotas                    quota                                       true         ResourceQuota
      secrets                                                                       true         Secret
      serviceaccounts                   sa                                          true         ServiceAccount
      services                          svc                                         true         Service
      customresourcedefinitions         crd,crds     apiextensions.k8s.io           false        CustomResourceDefinition
      apiservices                                    apiregistration.k8s.io         false        APIService
      controllerrevisions                            apps                           true         ControllerRevision
      daemonsets                        ds           apps                           true         DaemonSet
      deployments                       deploy       apps                           true         Deployment
      replicasets                       rs           apps                           true         ReplicaSet
      statefulsets                      sts          apps                           true         StatefulSet
      HorizontalPodAutoscaler
      cronjobs                          cj           batch                          true         CronJob
      jobs                                           batch                          true         Job
      leases                                         coordination.k8s.io            true         Lease
      endpointslices                                 discovery.k8s.io               true         EndpointSlice
      projects                                       duyanghao.example.com          true         Project
      ...
      csinodes                                       storage.k8s.io                 false        CSINode
      storageclasses                    sc           storage.k8s.io                 false        StorageClass
      volumeattachments                              storage.k8s.io                 false        VolumeAttachment
      ```
  - `namingController`：检查 crd obj 中是否有命名冲突，可在 crd `.status.conditions` 中查看；
  - `establishingController`：检查 crd 是否处于正常状态，可在 crd `.status.conditions` 中查看；
  - `nonStructuralSchemaController`：检查 crd obj 结构是否正常，可在 crd `.status.conditions` 中查看；
  - `apiApprovalController`：检查 crd 是否遵循 Kubernetes API 声明策略，可在 crd `.status.conditions` 中查看；
  - `finalizingController`：类似于 finalizes 的功能，与 CRs 的删除有关；
* 总结CR CRUD APIServer处理逻辑如下：
  - createAPIExtensionsServer=>NewCustomResourceDefinitionHandler=>crdHandler=>注册CR CRUD API接口：
    ```go
    // New returns a new instance of CustomResourceDefinitions from the given config.
    func (c completedConfig) New(delegationTarget genericapiserver.DelegationTarget) (*CustomResourceDefinitions, error) {
    	...
    	crdHandler, err := NewCustomResourceDefinitionHandler(
    		versionDiscoveryHandler,
    		groupDiscoveryHandler,
    		s.Informers.Apiextensions().V1().CustomResourceDefinitions(),
    		delegateHandler,
    		c.ExtraConfig.CRDRESTOptionsGetter,
    		c.GenericConfig.AdmissionControl,
    		establishingController,
    		c.ExtraConfig.ServiceResolver,
    		c.ExtraConfig.AuthResolverWrapper,
    		c.ExtraConfig.MasterCount,
    		s.GenericAPIServer.Authorizer,
    		c.GenericConfig.RequestTimeout,
    		time.Duration(c.GenericConfig.MinRequestTimeout)*time.Second,
    		apiGroupInfo.StaticOpenAPISpec,
    		c.GenericConfig.MaxRequestBodyBytes,
    	)
    	if err != nil {
    		return nil, err
    	}
    	s.GenericAPIServer.Handler.NonGoRestfulMux.Handle("/apis", crdHandler)
    	s.GenericAPIServer.Handler.NonGoRestfulMux.HandlePrefix("/apis/", crdHandler)
    	...
    	return s, nil
    }
    ```
  - crdHandler处理逻辑如下：
    - 解析req(GET /apis/duyanghao.example.com/v1/namespaces/default/students)，根据请求路径中的group(duyanghao.example.com)，version(v1)，以及resource字段(students)获取对应CRD内容(crd, err := r.crdLister.Get(crdName))
    - 通过crd.UID以及crd.Name获取crdInfo，若不存在则创建对应的crdInfo(crdInfo, err := r.getOrCreateServingInfoFor(crd.UID, crd.Name))。crdInfo中包含了CRD定义以及该CRD对应Custom Resource的customresource.REST storage
    - customresource.REST storage由CR对应的Group(duyanghao.example.com)，Version(v1)，Kind(Student)，Resource(students)等创建完成，由于CR在Kubernetes代码中并没有具体结构体定义，所以这里会先初始化一个范型结构体Unstructured(用于保存所有类型的Custom Resource)，并对该结构体进行SetGroupVersionKind操作(设置具体Custom Resource Type)
    - 从customresource.REST storage获取Unstructured结构体后会对其进行相应转换然后返回
    ```go
    // k8s.io/kubernetes/staging/src/k8s.io/apiextensions-apiserver/pkg/apiserver/customresource_handler.go:223
    func (r *crdHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
    	ctx := req.Context()
    	requestInfo, ok := apirequest.RequestInfoFrom(ctx)
    	if !ok {
    		responsewriters.ErrorNegotiated(
    			apierrors.NewInternalError(fmt.Errorf("no RequestInfo found in the context")),
    			Codecs, schema.GroupVersion{Group: requestInfo.APIGroup, Version: requestInfo.APIVersion}, w, req,
    		)
    		return
    	}
    	if !requestInfo.IsResourceRequest {
    		pathParts := splitPath(requestInfo.Path)
    		// only match /apis/<group>/<version>
    		// only registered under /apis
    		if len(pathParts) == 3 {
    			if !r.hasSynced() {
    				responsewriters.ErrorNegotiated(serverStartingError(), Codecs, schema.GroupVersion{Group: requestInfo.APIGroup, Version: requestInfo.APIVersion}, w, req)
    				return
    			}
    			r.versionDiscoveryHandler.ServeHTTP(w, req)
    			return
    		}
    		// only match /apis/<group>
    		if len(pathParts) == 2 {
    			if !r.hasSynced() {
    				responsewriters.ErrorNegotiated(serverStartingError(), Codecs, schema.GroupVersion{Group: requestInfo.APIGroup, Version: requestInfo.APIVersion}, w, req)
    				return
    			}
    			r.groupDiscoveryHandler.ServeHTTP(w, req)
    			return
    		}
    
    		r.delegate.ServeHTTP(w, req)
    		return
    	}
    
    	crdName := requestInfo.Resource + "." + requestInfo.APIGroup
    	crd, err := r.crdLister.Get(crdName)
    	if apierrors.IsNotFound(err) {
    		if !r.hasSynced() {
    			responsewriters.ErrorNegotiated(serverStartingError(), Codecs, schema.GroupVersion{Group: requestInfo.APIGroup, Version: requestInfo.APIVersion}, w, req)
    			return
    		}
    
    		r.delegate.ServeHTTP(w, req)
    		return
    	}
    	if err != nil {
    		utilruntime.HandleError(err)
    		responsewriters.ErrorNegotiated(
    			apierrors.NewInternalError(fmt.Errorf("error resolving resource")),
    			Codecs, schema.GroupVersion{Group: requestInfo.APIGroup, Version: requestInfo.APIVersion}, w, req,
    		)
    		return
    	}
    
    	// if the scope in the CRD and the scope in request differ (with exception of the verbs in possiblyAcrossAllNamespacesVerbs
    	// for namespaced resources), pass request to the delegate, which is supposed to lead to a 404.
    	namespacedCRD, namespacedReq := crd.Spec.Scope == apiextensionsv1.NamespaceScoped, len(requestInfo.Namespace) > 0
    	if !namespacedCRD && namespacedReq {
    		r.delegate.ServeHTTP(w, req)
    		return
    	}
    	if namespacedCRD && !namespacedReq && !possiblyAcrossAllNamespacesVerbs.Has(requestInfo.Verb) {
    		r.delegate.ServeHTTP(w, req)
    		return
    	}
    
    	if !apiextensionshelpers.HasServedCRDVersion(crd, requestInfo.APIVersion) {
    		r.delegate.ServeHTTP(w, req)
    		return
    	}
    
    	// There is a small chance that a CRD is being served because NamesAccepted condition is true,
    	// but it becomes "unserved" because another names update leads to a conflict
    	// and EstablishingController wasn't fast enough to put the CRD into the Established condition.
    	// We accept this as the problem is small and self-healing.
    	if !apiextensionshelpers.IsCRDConditionTrue(crd, apiextensionsv1.NamesAccepted) &&
    		!apiextensionshelpers.IsCRDConditionTrue(crd, apiextensionsv1.Established) {
    		r.delegate.ServeHTTP(w, req)
    		return
    	}
    
    	terminating := apiextensionshelpers.IsCRDConditionTrue(crd, apiextensionsv1.Terminating)
    
    	crdInfo, err := r.getOrCreateServingInfoFor(crd.UID, crd.Name)
    	if apierrors.IsNotFound(err) {
    		r.delegate.ServeHTTP(w, req)
    		return
    	}
    	if err != nil {
    		utilruntime.HandleError(err)
    		responsewriters.ErrorNegotiated(
    			apierrors.NewInternalError(fmt.Errorf("error resolving resource")),
    			Codecs, schema.GroupVersion{Group: requestInfo.APIGroup, Version: requestInfo.APIVersion}, w, req,
    		)
    		return
    	}
    	if !hasServedCRDVersion(crdInfo.spec, requestInfo.APIVersion) {
    		r.delegate.ServeHTTP(w, req)
    		return
    	}
    
    	verb := strings.ToUpper(requestInfo.Verb)
    	resource := requestInfo.Resource
    	subresource := requestInfo.Subresource
    	scope := metrics.CleanScope(requestInfo)
    	supportedTypes := []string{
    		string(types.JSONPatchType),
    		string(types.MergePatchType),
    	}
    	if utilfeature.DefaultFeatureGate.Enabled(features.ServerSideApply) {
    		supportedTypes = append(supportedTypes, string(types.ApplyPatchType))
    	}
    
    	var handlerFunc http.HandlerFunc
    	subresources, err := apiextensionshelpers.GetSubresourcesForVersion(crd, requestInfo.APIVersion)
    	if err != nil {
    		utilruntime.HandleError(err)
    		responsewriters.ErrorNegotiated(
    			apierrors.NewInternalError(fmt.Errorf("could not properly serve the subresource")),
    			Codecs, schema.GroupVersion{Group: requestInfo.APIGroup, Version: requestInfo.APIVersion}, w, req,
    		)
    		return
    	}
    	switch {
    	case subresource == "status" && subresources != nil && subresources.Status != nil:
    		handlerFunc = r.serveStatus(w, req, requestInfo, crdInfo, terminating, supportedTypes)
    	case subresource == "scale" && subresources != nil && subresources.Scale != nil:
    		handlerFunc = r.serveScale(w, req, requestInfo, crdInfo, terminating, supportedTypes)
    	case len(subresource) == 0:
    		handlerFunc = r.serveResource(w, req, requestInfo, crdInfo, terminating, supportedTypes)
    	default:
    		responsewriters.ErrorNegotiated(
    			apierrors.NewNotFound(schema.GroupResource{Group: requestInfo.APIGroup, Resource: requestInfo.Resource}, requestInfo.Name),
    			Codecs, schema.GroupVersion{Group: requestInfo.APIGroup, Version: requestInfo.APIVersion}, w, req,
    		)
    	}
    
    	if handlerFunc != nil {
    		handlerFunc = metrics.InstrumentHandlerFunc(verb, requestInfo.APIGroup, requestInfo.APIVersion, resource, subresource, scope, metrics.APIServerComponent, handlerFunc)
    		handler := genericfilters.WithWaitGroup(handlerFunc, longRunningFilter, crdInfo.waitGroup)
    		handler.ServeHTTP(w, req)
    		return
    	}
    }
    ```

更多代码原理详情，参考[kubernetes-reading-notes](https://github.com/duyanghao/kubernetes-reading-notes/tree/master/core/api-server)

## Conclusion

本文从源码层面对Kubernetes apiserver进行了一个概览性总结，包括：aggregatorServer，kubeAPIServer，apiExtensionsServer以及bootstrap-controller等。通过阅读本文可以对apiserver内部原理有一个大致的理解，另外也有助于后续深入研究

## Refs

* [kubernetes-reading-notes](https://github.com/duyanghao/kubernetes-reading-notes/tree/master/core/api-server)