kube-apiserver
==============

kube-apiserver作为整个Kubernetes集群操作etcd的唯一入口，负责Kubernetes各资源的认证&鉴权，校验以及CRUD等操作。Kubernetes提供RESTful APIs，供其它组件调用，本文将对kube-apiserver整体架构进行源码分析(后续分章节展开各部分细节)

## 概念梳理

上述分析了kube-apiserver的整体流程，也即：

```
CreateServerChain(创建三种APIServer)->PrepareRun(执行APIServer运行前的准备工作)->prepared.Run(运行APIServer)
```

kube-apiserver包含三个APIServer：

* aggregatorServer：暴露的功能类似于一个七层负载均衡，将来自用户的请求拦截转发给其他服务器
* kubeAPIServer：负责对请求的一些通用处理，包括：认证、鉴权以及各个内建资源的 REST 服务等
* apiExtensionsServer：主要处理 CustomResourceDefinition（CRD）和 CustomResource（CR）的 REST 请求，也是 Delegation 的最后一环，如果对应 CR 不能被处理的话则会返回 404

AggregatorServer 和 APIExtensionsServer 对应两种主要扩展 APIServer 资源的方式，也即分别是 AA 和 CRD

### AggregatorServer

其中，Aggregator 通过 APIServices 对象关联到某个 Service 来进行请求的转发，其关联的 Service 类型进一步决定了请求转发形式。Aggregator 包括一个 `GenericAPIServer` 和维护自身状态的 Controller。其中 `GenericAPIServer` 主要处理 `apiregistration.k8s.io` 组下的 APIService 资源请求，controller包括：

- `apiserviceRegistrationController`：负责 APIServices 中资源的注册与删除；
- `availableConditionController`：维护 APIServices 的可用状态，包括其引用 Service 是否可用等；
- `autoRegistrationController`：用于保持 API 中存在的一组特定的 APIServices；
- `crdRegistrationController`：负责将 CRD GroupVersions 自动注册到 APIServices 中；
- `openAPIAggregationController`：将 APIServices 资源的变化同步至提供的 OpenAPI 文档；

Kubernetes 中的一些附加组件，比如 metrics-server 就是通过 Aggregator 的方式进行扩展的，实际环境中可以通过使用 [apiserver-builder](https://github.com/kubernetes-sigs/apiserver-builder-alpha) 工具轻松以 Aggregator 的扩展方式创建自定义资源

### KubeAPIServer

KubeAPIServer 主要是提供对 API Resource 的操作请求，为 Kubernetes 中众多 API 注册路由信息，暴露 RESTful API 并且对外提供 Kubernetes service，使集群中以及集群外的服务都可以通过 RESTful API 操作 kubernetes 中的资源

### APIExtensionServer

APIExtensionServer 作为 Delegation 链的最后一层，是处理所有用户通过 Custom Resource Definition 定义的资源服务器

其中包含的 controller 以及功能如下所示：

- `openapiController`：将 crd 资源的变化同步至提供的 OpenAPI 文档，可通过访问 `/openapi/v2` 进行查看；
- `crdController`：负责将 crd 信息注册到 apiVersions 和 apiResources 中，两者的信息可通过 `$ kubectl api-versions` 和 `$ kubectl api-resources` 查看；
- `namingController`：检查 crd obj 中是否有命名冲突，可在 crd `.status.conditions` 中查看；
- `establishingController`：检查 crd 是否处于正常状态，可在 crd `.status.conditions` 中查看；
- `nonStructuralSchemaController`：检查 crd obj 结构是否正常，可在 crd `.status.conditions` 中查看；
- `apiApprovalController`：检查 crd 是否遵循 Kubernetes API 声明策略，可在 crd `.status.conditions` 中查看；
- `finalizingController`：类似于 finalizes 的功能，与 CRs 的删除有关；

## 启动流程

kube-apiserver启动主体函数为Run：

```go
// Run runs the specified APIServer.  This should never exit.
func Run(completeOptions completedServerRunOptions, stopCh <-chan struct{}) error {
	// To help debugging, immediately log version
	klog.Infof("Version: %+v", version.Get())

	server, err := CreateServerChain(completeOptions, stopCh)
	if err != nil {
		return err
	}

	prepared, err := server.PrepareRun()
	if err != nil {
		return err
	}

	return prepared.Run(stopCh)
}
```

`Run` 方法的主要逻辑为：

- 1、调用 `CreateServerChain` 构建服务调用链并判断是否启动非安全的 http server，http server 链中包含 apiserver 要启动的三个 server，以及为每个 server 注册对应资源的路由；
- 2、调用 `server.PrepareRun` 进行服务运行前的准备，该方法主要完成了健康检查、存活检查和`OpenAPI`路由的注册工作；
- 3、调用 `prepared.Run` 启动 https server；

server 的初始化使用委托模式，通过 DelegationTarget 接口，把基本的 API Server、CustomResource、Aggregator 这三种服务采用链式结构串联起来，对外提供服务：

```go
// DelegationTarget is an interface which allows for composition of API servers with top level handling that works
// as expected.
type DelegationTarget interface {
	// UnprotectedHandler returns a handler that is NOT protected by a normal chain
	UnprotectedHandler() http.Handler

	// PostStartHooks returns the post-start hooks that need to be combined
	PostStartHooks() map[string]postStartHookEntry

	// PreShutdownHooks returns the pre-stop hooks that need to be combined
	PreShutdownHooks() map[string]preShutdownHookEntry

	// HealthzChecks returns the healthz checks that need to be combined
	HealthzChecks() []healthz.HealthChecker

	// ListedPaths returns the paths for supporting an index
	ListedPaths() []string

	// NextDelegate returns the next delegationTarget in the chain of delegations
	NextDelegate() DelegationTarget

	// PrepareRun does post API installation setup steps. It calls recursively the same function of the delegates.
	PrepareRun() preparedGenericAPIServer
}
```

### CreateServerChain

`CreateServerChain` 是完成 server 初始化的方法，里面包含 `APIExtensionsServer`、`KubeAPIServer`、`AggregatorServer` 初始化的所有流程，最终返回 `aggregatorapiserver.APIAggregator` 实例，初始化流程主要有：http filter chain 的配置、API Group 的注册、http path 与 handler 的关联以及 handler 后端存储 etcd 的配置。其主要逻辑为：

- 1、调用 `CreateKubeAPIServerConfig` 创建 KubeAPIServer 所需要的配置，主要是创建 `master.Config`，其中会调用 `buildGenericConfig` 生成 genericConfig，genericConfig 中包含 apiserver 的核心配置；
- 2、判断是否启用了扩展的 API server 并调用 `createAPIExtensionsConfig` 为其创建配置；
- 3、调用 `createAPIExtensionsServer` 创建 apiExtensionsServer 实例；
- 4、调用 `CreateKubeAPIServer `初始化 kubeAPIServer；
- 5、调用 `createAggregatorConfig` 为 aggregatorServer 创建配置并调用 `createAggregatorServer` 初始化 aggregatorServer；
- 6、配置并判断是否启动非安全的 http server；

```go
// CreateServerChain creates the apiservers connected via delegation.
func CreateServerChain(completedOptions completedServerRunOptions, stopCh <-chan struct{}) (*aggregatorapiserver.APIAggregator, error) {
	nodeTunneler, proxyTransport, err := CreateNodeDialer(completedOptions)
	if err != nil {
		return nil, err
	}

	kubeAPIServerConfig, insecureServingInfo, serviceResolver, pluginInitializer, err := CreateKubeAPIServerConfig(completedOptions, nodeTunneler, proxyTransport)
	if err != nil {
		return nil, err
	}

	// If additional API servers are added, they should be gated.
	apiExtensionsConfig, err := createAPIExtensionsConfig(*kubeAPIServerConfig.GenericConfig, kubeAPIServerConfig.ExtraConfig.VersionedInformers, pluginInitializer, completedOptions.ServerRunOptions, completedOptions.MasterCount,
		serviceResolver, webhook.NewDefaultAuthenticationInfoResolverWrapper(proxyTransport, kubeAPIServerConfig.GenericConfig.EgressSelector, kubeAPIServerConfig.GenericConfig.LoopbackClientConfig))
	if err != nil {
		return nil, err
	}
	apiExtensionsServer, err := createAPIExtensionsServer(apiExtensionsConfig, genericapiserver.NewEmptyDelegate())
	if err != nil {
		return nil, err
	}

	kubeAPIServer, err := CreateKubeAPIServer(kubeAPIServerConfig, apiExtensionsServer.GenericAPIServer)
	if err != nil {
		return nil, err
	}

	// aggregator comes last in the chain
	aggregatorConfig, err := createAggregatorConfig(*kubeAPIServerConfig.GenericConfig, completedOptions.ServerRunOptions, kubeAPIServerConfig.ExtraConfig.VersionedInformers, serviceResolver, proxyTransport, pluginInitializer)
	if err != nil {
		return nil, err
	}
	aggregatorServer, err := createAggregatorServer(aggregatorConfig, kubeAPIServer.GenericAPIServer, apiExtensionsServer.Informers)
	if err != nil {
		// we don't need special handling for innerStopCh because the aggregator server doesn't create any go routines
		return nil, err
	}

	if insecureServingInfo != nil {
		insecureHandlerChain := kubeserver.BuildInsecureHandlerChain(aggregatorServer.GenericAPIServer.UnprotectedHandler(), kubeAPIServerConfig.GenericConfig)
		if err := insecureServingInfo.Serve(insecureHandlerChain, kubeAPIServerConfig.GenericConfig.RequestTimeout, stopCh); err != nil {
			return nil, err
		}
	}

	return aggregatorServer, nil
}
```

先看CreateKubeAPIServerConfig，在 `CreateKubeAPIServerConfig` 中主要是调用 `buildGenericConfig` 创建 genericConfig 以及构建 master.Config 对象：

```go
// CreateKubeAPIServerConfig creates all the resources for running the API server, but runs none of them
func CreateKubeAPIServerConfig(
	s completedServerRunOptions,
	nodeTunneler tunneler.Tunneler,
	proxyTransport *http.Transport,
) (
	*master.Config,
	*genericapiserver.DeprecatedInsecureServingInfo,
	aggregatorapiserver.ServiceResolver,
	[]admission.PluginInitializer,
	error,
) {
	// 1、构建 genericConfig
	genericConfig, versionedInformers, insecureServingInfo, serviceResolver, pluginInitializers, admissionPostStartHook, storageFactory, err := buildGenericConfig(s.ServerRunOptions, proxyTransport)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	
	... 
	// 2、初始化所支持的 capabilities
	capabilities.Initialize(capabilities.Capabilities{
		AllowPrivileged: s.AllowPrivileged,
		// TODO(vmarmol): Implement support for HostNetworkSources.
		PrivilegedSources: capabilities.PrivilegedSources{
			HostNetworkSources: []string{},
			HostPIDSources:     []string{},
			HostIPCSources:     []string{},
		},
		PerConnectionBandwidthLimitBytesPerSec: s.MaxConnectionBytesPerSec,
	})

	if len(s.ShowHiddenMetricsForVersion) > 0 {
		metrics.SetShowHidden()
	}
  
	// 3、获取 service ip range 以及 api server service IP
	serviceIPRange, apiServerServiceIP, err := master.ServiceIPRange(s.PrimaryServiceClusterIPRange)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	...
	// 4、构建 master.Config 对象
	config := &master.Config{
		GenericConfig: genericConfig,
		ExtraConfig: master.ExtraConfig{
			APIResourceConfigSource: storageFactory.APIResourceConfigSource,
			StorageFactory:          storageFactory,
			EventTTL:                s.EventTTL,
			KubeletClientConfig:     s.KubeletConfig,
			EnableLogsSupport:       s.EnableLogsHandler,
			ProxyTransport:          proxyTransport,

			Tunneler: nodeTunneler,

			ServiceIPRange:          serviceIPRange,
			APIServerServiceIP:      apiServerServiceIP,
			SecondaryServiceIPRange: secondaryServiceIPRange,

			APIServerServicePort: 443,

			ServiceNodePortRange:      s.ServiceNodePortRange,
			KubernetesServiceNodePort: s.KubernetesServiceNodePort,

			EndpointReconcilerType: reconcilers.Type(s.EndpointReconcilerType),
			MasterCount:            s.MasterCount,

			ServiceAccountIssuer:        s.ServiceAccountIssuer,
			ServiceAccountMaxExpiration: s.ServiceAccountTokenMaxExpiration,

			VersionedInformers: versionedInformers,
		},
	}

	...

	return config, insecureServingInfo, serviceResolver, pluginInitializers, nil
}
```

展开buildGenericConfig：

```go
// BuildGenericConfig takes the master server options and produces the genericapiserver.Config associated with it
func buildGenericConfig(
	s *options.ServerRunOptions,
	proxyTransport *http.Transport,
) (
	genericConfig *genericapiserver.Config,
	versionedInformers clientgoinformers.SharedInformerFactory,
	insecureServingInfo *genericapiserver.DeprecatedInsecureServingInfo,
	serviceResolver aggregatorapiserver.ServiceResolver,
	pluginInitializers []admission.PluginInitializer,
	admissionPostStartHook genericapiserver.PostStartHookFunc,
	storageFactory *serverstorage.DefaultStorageFactory,
	lastErr error,
) {
	// 1、为 genericConfig 设置默认值
	genericConfig = genericapiserver.NewConfig(legacyscheme.Codecs)
	genericConfig.MergedResourceConfig = master.DefaultAPIResourceConfigSource()

	...

	genericConfig.OpenAPIConfig = genericapiserver.DefaultOpenAPIConfig(generatedopenapi.GetOpenAPIDefinitions, openapinamer.NewDefinitionNamer(legacyscheme.Scheme, extensionsapiserver.Scheme, aggregatorscheme.Scheme))
	genericConfig.OpenAPIConfig.Info.Title = "Kubernetes"
	genericConfig.LongRunningFunc = filters.BasicLongRunningRequestCheck(
		sets.NewString("watch", "proxy"),
		sets.NewString("attach", "exec", "proxy", "log", "portforward"),
	)

	kubeVersion := version.Get()
	genericConfig.Version = &kubeVersion

	storageFactoryConfig := kubeapiserver.NewStorageFactoryConfig()
	storageFactoryConfig.APIResourceConfig = genericConfig.MergedResourceConfig
	completedStorageFactoryConfig, err := storageFactoryConfig.Complete(s.Etcd)
	if err != nil {
		lastErr = err
		return
	}
	// 初始化 storageFactory
	storageFactory, lastErr = completedStorageFactoryConfig.New()
	if lastErr != nil {
		return
	}
	if genericConfig.EgressSelector != nil {
		storageFactory.StorageConfig.Transport.EgressLookup = genericConfig.EgressSelector.Lookup
	}
	// 2、初始化 RESTOptionsGetter，后期根据其获取操作 Etcd 的句柄，同时添加 etcd 的健康检查方法
	if lastErr = s.Etcd.ApplyWithStorageFactoryTo(storageFactory, genericConfig); lastErr != nil {
		return
	}

	// 3、设置使用 protobufs 用来内部交互，并且禁用压缩功能
	// Use protobufs for self-communication.
	// Since not every generic apiserver has to support protobufs, we
	// cannot default to it in generic apiserver and need to explicitly
	// set it in kube-apiserver.
	genericConfig.LoopbackClientConfig.ContentConfig.ContentType = "application/vnd.kubernetes.protobuf"
	// Disable compression for self-communication, since we are going to be
	// on a fast local network
	genericConfig.LoopbackClientConfig.DisableCompression = true

	// 4、创建 clientset
	kubeClientConfig := genericConfig.LoopbackClientConfig
	clientgoExternalClient, err := clientgoclientset.NewForConfig(kubeClientConfig)
	if err != nil {
		lastErr = fmt.Errorf("failed to create real external clientset: %v", err)
		return
	}
	versionedInformers = clientgoinformers.NewSharedInformerFactory(clientgoExternalClient, 10*time.Minute)

	// 5、创建认证实例，支持多种认证方式：请求 Header 认证、Auth 文件认证、CA 证书认证、Bearer token 认证、
	// ServiceAccount 认证、BootstrapToken 认证、WebhookToken 认证等
	genericConfig.Authentication.Authenticator, genericConfig.OpenAPIConfig.SecurityDefinitions, err = BuildAuthenticator(s, genericConfig.EgressSelector, clientgoExternalClient, versionedInformers)
	if err != nil {
		lastErr = fmt.Errorf("invalid authentication config: %v", err)
		return
	}

	// 6、创建鉴权实例，包含：Node、RBAC、Webhook、ABAC、AlwaysAllow、AlwaysDeny
	genericConfig.Authorization.Authorizer, genericConfig.RuleResolver, err = BuildAuthorizer(s, genericConfig.EgressSelector, versionedInformers)
	if err != nil {
		lastErr = fmt.Errorf("invalid authorization config: %v", err)
		return
	}
	if !sets.NewString(s.Authorization.Modes...).Has(modes.ModeRBAC) {
		genericConfig.DisabledPostStartHooks.Insert(rbacrest.PostStartHookName)
	}

	admissionConfig := &kubeapiserveradmission.Config{
		ExternalInformers:    versionedInformers,
		LoopbackClientConfig: genericConfig.LoopbackClientConfig,
		CloudConfigFile:      s.CloudProvider.CloudConfigFile,
	}
	serviceResolver = buildServiceResolver(s.EnableAggregatorRouting, genericConfig.LoopbackClientConfig.Host, versionedInformers)

	authInfoResolverWrapper := webhook.NewDefaultAuthenticationInfoResolverWrapper(proxyTransport, genericConfig.EgressSelector, genericConfig.LoopbackClientConfig)

	// 7、审计插件的初始化
	lastErr = s.Audit.ApplyTo(
		genericConfig,
		genericConfig.LoopbackClientConfig,
		versionedInformers,
		serveroptions.NewProcessInfo("kube-apiserver", "kube-system"),
		&serveroptions.WebhookOptions{
			AuthInfoResolverWrapper: authInfoResolverWrapper,
			ServiceResolver:         serviceResolver,
		},
	)
	if lastErr != nil {
		return
	}

	// 8、准入插件的初始化
	pluginInitializers, admissionPostStartHook, err = admissionConfig.New(proxyTransport, genericConfig.EgressSelector, serviceResolver)
	if err != nil {
		lastErr = fmt.Errorf("failed to create admission plugin initializer: %v", err)
		return
	}

	err = s.Admission.ApplyTo(
		genericConfig,
		versionedInformers,
		kubeClientConfig,
		feature.DefaultFeatureGate,
		pluginInitializers...)
	if err != nil {
		lastErr = fmt.Errorf("failed to initialize admission: %v", err)
	}

	return
}

func DefaultBuildHandlerChain(apiHandler http.Handler, c *Config) http.Handler {
	handler := genericapifilters.WithAuthorization(apiHandler, c.Authorization.Authorizer, c.Serializer)
	if c.FlowControl != nil {
		handler = genericfilters.WithPriorityAndFairness(handler, c.LongRunningFunc, c.FlowControl)
	} else {
		handler = genericfilters.WithMaxInFlightLimit(handler, c.MaxRequestsInFlight, c.MaxMutatingRequestsInFlight, c.LongRunningFunc)
	}
	handler = genericapifilters.WithImpersonation(handler, c.Authorization.Authorizer, c.Serializer)
	handler = genericapifilters.WithAudit(handler, c.AuditBackend, c.AuditPolicyChecker, c.LongRunningFunc)
	failedHandler := genericapifilters.Unauthorized(c.Serializer, c.Authentication.SupportsBasicAuth)
	failedHandler = genericapifilters.WithFailedAuthenticationAudit(failedHandler, c.AuditBackend, c.AuditPolicyChecker)
	handler = genericapifilters.WithAuthentication(handler, c.Authentication.Authenticator, failedHandler, c.Authentication.APIAudiences)
	handler = genericfilters.WithCORS(handler, c.CorsAllowedOriginList, nil, nil, nil, "true")
	handler = genericfilters.WithTimeoutForNonLongRunningRequests(handler, c.LongRunningFunc, c.RequestTimeout)
	handler = genericfilters.WithWaitGroup(handler, c.LongRunningFunc, c.HandlerChainWaitGroup)
	handler = genericapifilters.WithRequestInfo(handler, c.RequestInfoResolver)
	if c.SecureServing != nil && !c.SecureServing.DisableHTTP2 && c.GoawayChance > 0 {
		handler = genericfilters.WithProbabilisticGoaway(handler, c.GoawayChance)
	}
	handler = genericapifilters.WithCacheControl(handler)
	handler = genericfilters.WithPanicRecovery(handler)
	return handler
}
```

主要逻辑为：

- 1、调用 `genericapiserver.NewConfig` 生成默认的 genericConfig，genericConfig 中主要配置了 `DefaultBuildHandlerChain`，`DefaultBuildHandlerChain` 中包含了认证、鉴权等一系列 http filter chain；
- 2、调用 `master.DefaultAPIResourceConfigSource` 加载需要启用的 API Resource，集群中所有的 API Resource 可以在代码的 `k8s.io/api` 目录中看到，随着版本的迭代也会不断变化；
- 3、为 genericConfig 中的部分字段设置默认值；
- 4、调用 `completedStorageFactoryConfig.New` 创建 storageFactory，后面会使用 storageFactory 为每种API Resource 创建对应的 RESTStorage；

以上主要分析 KubeAPIServerConfig 的初始化，其他两个 server config 的初始化暂且不详细分析，下面接着继续分析 server 的初始化

### APIExtensionsServer创建

APIExtensionsServer 是最先被初始化的，在 `createAPIExtensionsServer` 中调用 `apiextensionsConfig.Complete().New` 来完成 server 的初始化，其主要逻辑为：

- 1、首先调用 `c.GenericConfig.New` 按照`go-restful`的模式初始化 Container，在 `c.GenericConfig.New` 中会调用 `NewAPIServerHandler` 初始化 handler，APIServerHandler 包含了 API Server 使用的多种http.Handler 类型，包括 `go-restful` 以及 `non-go-restful`，以及在以上两者之间选择的 Director 对象，`go-restful` 用于处理已经注册的 handler，`non-go-restful` 用来处理不存在的 handler，API URI 处理的选择过程为：`FullHandlerChain-> Director ->{GoRestfulContainer， NonGoRestfulMux}`。在 `c.GenericConfig.New` 中还会调用 `installAPI`来添加包括 `/`、`/debug/*`、`/metrics`、`/version` 等路由信息。三种 server 在初始化时首先都会调用 `c.GenericConfig.New` 来初始化一个 genericServer，然后进行 API 的注册；
- 2、调用 `s.GenericAPIServer.InstallAPIGroup` 在路由中注册 API Resources，此方法的调用链非常深，主要是为了将需要暴露的 API Resource 注册到 server 中，以便能通过 http 接口进行 resource 的 REST 操作，其他几种 server 在初始化时也都会执行对应的 `InstallAPI`；
- 3、初始化 server 中需要使用的 controller，主要有 `openapiController`、`crdController`、`namingController`、`establishingController`、`nonStructuralSchemaController`、`apiApprovalController`、`finalizingControlle`r；
- 4、将需要启动的 controller 以及 informer 添加到 PostStartHook 中；

```go
func createAPIExtensionsServer(apiextensionsConfig *apiextensionsapiserver.Config, delegateAPIServer genericapiserver.DelegationTarget) (*apiextensionsapiserver.CustomResourceDefinitions, error) {
	return apiextensionsConfig.Complete().New(delegateAPIServer)
}

...
// k8s.io/kubernetes/vendor/k8s.io/apiextensions-apiserver/pkg/apiserver/apiserver.go:129
// New returns a new instance of CustomResourceDefinitions from the given config.
func (c completedConfig) New(delegationTarget genericapiserver.DelegationTarget) (*CustomResourceDefinitions, error) {
	// 1、初始化 genericServer
	genericServer, err := c.GenericConfig.New("apiextensions-apiserver", delegationTarget)
	if err != nil {
		return nil, err
	}

	s := &CustomResourceDefinitions{
		GenericAPIServer: genericServer,
	}
	// 2、初始化 APIGroup Info，APIGroup 指该 server 需要暴露的 API
	apiResourceConfig := c.GenericConfig.MergedResourceConfig
	apiGroupInfo := genericapiserver.NewDefaultAPIGroupInfo(apiextensions.GroupName, Scheme, metav1.ParameterCodec, Codecs)
	if apiResourceConfig.VersionEnabled(v1beta1.SchemeGroupVersion) {
		storage := map[string]rest.Storage{}
		// customresourcedefinitions
		customResourceDefintionStorage := customresourcedefinition.NewREST(Scheme, c.GenericConfig.RESTOptionsGetter)
		storage["customresourcedefinitions"] = customResourceDefintionStorage
		storage["customresourcedefinitions/status"] = customresourcedefinition.NewStatusREST(Scheme, customResourceDefintionStorage)

		apiGroupInfo.VersionedResourcesStorageMap[v1beta1.SchemeGroupVersion.Version] = storage
	}
	if apiResourceConfig.VersionEnabled(v1.SchemeGroupVersion) {
		storage := map[string]rest.Storage{}
		// customresourcedefinitions
		customResourceDefintionStorage := customresourcedefinition.NewREST(Scheme, c.GenericConfig.RESTOptionsGetter)
		storage["customresourcedefinitions"] = customResourceDefintionStorage
		storage["customresourcedefinitions/status"] = customresourcedefinition.NewStatusREST(Scheme, customResourceDefintionStorage)

		apiGroupInfo.VersionedResourcesStorageMap[v1.SchemeGroupVersion.Version] = storage
	}
	
	// 3、注册 APIGroup
	if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
		return nil, err
	}

	// 4、初始化需要使用的 controller
	crdClient, err := clientset.NewForConfig(s.GenericAPIServer.LoopbackClientConfig)
	if err != nil {
		// it's really bad that this is leaking here, but until we can fix the test (which I'm pretty sure isn't even testing what it wants to test),
		// we need to be able to move forward
		return nil, fmt.Errorf("failed to create clientset: %v", err)
	}
	s.Informers = externalinformers.NewSharedInformerFactory(crdClient, 5*time.Minute)
	
	...
	establishingController := establish.NewEstablishingController(s.Informers.Apiextensions().V1().CustomResourceDefinitions(), crdClient.ApiextensionsV1())
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

	crdController := NewDiscoveryController(s.Informers.Apiextensions().V1().CustomResourceDefinitions(), versionDiscoveryHandler, groupDiscoveryHandler)
	namingController := status.NewNamingConditionController(s.Informers.Apiextensions().V1().CustomResourceDefinitions(), crdClient.ApiextensionsV1())
	nonStructuralSchemaController := nonstructuralschema.NewConditionController(s.Informers.Apiextensions().V1().CustomResourceDefinitions(), crdClient.ApiextensionsV1())
	apiApprovalController := apiapproval.NewKubernetesAPIApprovalPolicyConformantConditionController(s.Informers.Apiextensions().V1().CustomResourceDefinitions(), crdClient.ApiextensionsV1())
	finalizingController := finalizer.NewCRDFinalizer(
		s.Informers.Apiextensions().V1().CustomResourceDefinitions(),
		crdClient.ApiextensionsV1(),
		crdHandler,
	)
	openapiController := openapicontroller.NewController(s.Informers.Apiextensions().V1().CustomResourceDefinitions())
	
	// 5、将 informer 以及 controller 添加到 PostStartHook 中
	s.GenericAPIServer.AddPostStartHookOrDie("start-apiextensions-informers", func(context genericapiserver.PostStartHookContext) error {
		s.Informers.Start(context.StopCh)
		return nil
	})
	s.GenericAPIServer.AddPostStartHookOrDie("start-apiextensions-controllers", func(context genericapiserver.PostStartHookContext) error {
		// OpenAPIVersionedService and StaticOpenAPISpec are populated in generic apiserver PrepareRun().
		// Together they serve the /openapi/v2 endpoint on a generic apiserver. A generic apiserver may
		// choose to not enable OpenAPI by having null openAPIConfig, and thus OpenAPIVersionedService
		// and StaticOpenAPISpec are both null. In that case we don't run the CRD OpenAPI controller.
		if s.GenericAPIServer.OpenAPIVersionedService != nil && s.GenericAPIServer.StaticOpenAPISpec != nil {
			go openapiController.Run(s.GenericAPIServer.StaticOpenAPISpec, s.GenericAPIServer.OpenAPIVersionedService, context.StopCh)
		}

		go crdController.Run(context.StopCh)
		go namingController.Run(context.StopCh)
		go establishingController.Run(context.StopCh)
		go nonStructuralSchemaController.Run(5, context.StopCh)
		go apiApprovalController.Run(5, context.StopCh)
		go finalizingController.Run(5, context.StopCh)
		return nil
	})
	// we don't want to report healthy until we can handle all CRDs that have already been registered.  Waiting for the informer
	// to sync makes sure that the lister will be valid before we begin.  There may still be races for CRDs added after startup,
	// but we won't go healthy until we can handle the ones already present.
	s.GenericAPIServer.AddPostStartHookOrDie("crd-informer-synced", func(context genericapiserver.PostStartHookContext) error {
		return wait.PollImmediateUntil(100*time.Millisecond, func() (bool, error) {
			return s.Informers.Apiextensions().V1().CustomResourceDefinitions().Informer().HasSynced(), nil
		}, context.StopCh)
	})

	return s, nil
}

// k8s.io/kubernetes/vendor/k8s.io/apiserver/pkg/server/config.go:520
// New creates a new server which logically combines the handling chain with the passed server.
// name is used to differentiate for logging. The handler chain in particular can be difficult as it starts delgating.
// delegationTarget may not be nil.
func (c completedConfig) New(name string, delegationTarget DelegationTarget) (*GenericAPIServer, error) {   
    ...
	handlerChainBuilder := func(handler http.Handler) http.Handler {
		return c.BuildHandlerChainFunc(handler, c.Config)
	}
	apiServerHandler := NewAPIServerHandler(name, c.Serializer, handlerChainBuilder, delegationTarget.UnprotectedHandler())

	s := &GenericAPIServer{
		discoveryAddresses:         c.DiscoveryAddresses,
		LoopbackClientConfig:       c.LoopbackClientConfig,
		legacyAPIGroupPrefixes:     c.LegacyAPIGroupPrefixes,
		admissionControl:           c.AdmissionControl,
		Serializer:                 c.Serializer,
		AuditBackend:               c.AuditBackend,
		Authorizer:                 c.Authorization.Authorizer,
		delegationTarget:           delegationTarget,
		EquivalentResourceRegistry: c.EquivalentResourceRegistry,
		HandlerChainWaitGroup:      c.HandlerChainWaitGroup,

		minRequestTimeout:     time.Duration(c.MinRequestTimeout) * time.Second,
		ShutdownTimeout:       c.RequestTimeout,
		ShutdownDelayDuration: c.ShutdownDelayDuration,
		SecureServingInfo:     c.SecureServing,
		ExternalAddress:       c.ExternalAddress,

		Handler: apiServerHandler,

		listedPathProvider: apiServerHandler,

		openAPIConfig: c.OpenAPIConfig,

		postStartHooks:         map[string]postStartHookEntry{},
		preShutdownHooks:       map[string]preShutdownHookEntry{},
		disabledPostStartHooks: c.DisabledPostStartHooks,

		healthzChecks:    c.HealthzChecks,
		livezChecks:      c.LivezChecks,
		readyzChecks:     c.ReadyzChecks,
		readinessStopCh:  make(chan struct{}),
		livezGracePeriod: c.LivezGracePeriod,

		DiscoveryGroupManager: discovery.NewRootAPIsHandler(c.DiscoveryAddresses, c.Serializer),

		maxRequestBodyBytes: c.MaxRequestBodyBytes,
		livezClock:          clock.RealClock{},
	}

    ...
	s.listedPathProvider = routes.ListedPathProviders{s.listedPathProvider, delegationTarget}

	installAPI(s, c.Config)
    ...

	return s, nil
}

// k8s.io/kubernetes/vendor/k8s.io/apiserver/pkg/server/handler.go:73
func NewAPIServerHandler(name string, s runtime.NegotiatedSerializer, handlerChainBuilder HandlerChainBuilderFn, notFoundHandler http.Handler) *APIServerHandler {
	nonGoRestfulMux := mux.NewPathRecorderMux(name)
	if notFoundHandler != nil {
		nonGoRestfulMux.NotFoundHandler(notFoundHandler)
	}

	gorestfulContainer := restful.NewContainer()
	gorestfulContainer.ServeMux = http.NewServeMux()
	gorestfulContainer.Router(restful.CurlyRouter{}) // e.g. for proxy/{kind}/{name}/{*}
	gorestfulContainer.RecoverHandler(func(panicReason interface{}, httpWriter http.ResponseWriter) {
		logStackOnRecover(s, panicReason, httpWriter)
	})
	gorestfulContainer.ServiceErrorHandler(func(serviceErr restful.ServiceError, request *restful.Request, response *restful.Response) {
		serviceErrorHandler(s, serviceErr, request, response)
	})

	director := director{
		name:               name,
		goRestfulContainer: gorestfulContainer,
		nonGoRestfulMux:    nonGoRestfulMux,
	}

	return &APIServerHandler{
		FullHandlerChain:   handlerChainBuilder(director),
		GoRestfulContainer: gorestfulContainer,
		NonGoRestfulMux:    nonGoRestfulMux,
		Director:           director,
	}
}

// k8s.io/kubernetes/vendor/k8s.io/apiserver/pkg/server/config.go:688
func installAPI(s *GenericAPIServer, c *Config) {
	if c.EnableIndex {
		routes.Index{}.Install(s.listedPathProvider, s.Handler.NonGoRestfulMux)
	}
	if c.EnableProfiling {
		routes.Profiling{}.Install(s.Handler.NonGoRestfulMux)
		if c.EnableContentionProfiling {
			goruntime.SetBlockProfileRate(1)
		}
		// so far, only logging related endpoints are considered valid to add for these debug flags.
		routes.DebugFlags{}.Install(s.Handler.NonGoRestfulMux, "v", routes.StringFlagPutHandler(logs.GlogSetter))
	}
	if c.EnableMetrics {
		if c.EnableProfiling {
			routes.MetricsWithReset{}.Install(s.Handler.NonGoRestfulMux)
		} else {
			routes.DefaultMetrics{}.Install(s.Handler.NonGoRestfulMux)
		}
	}

	routes.Version{Version: c.Version}.Install(s.Handler.GoRestfulContainer)

	if c.EnableDiscovery {
		s.Handler.GoRestfulContainer.Add(s.DiscoveryGroupManager.WebService())
	}
}
```

最终返回CustomResourceDefinitions(k8s.io/kubernetes/vendor/k8s.io/apiextensions-apiserver/pkg/apiserver/apiserver.go:106)：

```go
type CustomResourceDefinitions struct {
   GenericAPIServer *genericapiserver.GenericAPIServer

   // provided for easier embedding
   Informers externalinformers.SharedInformerFactory
}
```

以上是 APIExtensionsServer 的初始化流程，其中最核心方法是 `s.GenericAPIServer.InstallAPIGroup`，也就是 API 的注册过程，三种 server 中 API 的注册过程都是其核心，这个会在后续展开介绍

### KubeAPIServer创建

接下来介绍KubeAPIServer的创建过程：

```go
// k8s.io/kubernetes/cmd/kube-apiserver/app/server.go:168
// CreateServerChain creates the apiservers connected via delegation.
func CreateServerChain(completedOptions completedServerRunOptions, stopCh <-chan struct{}) (*aggregatorapiserver.APIAggregator, error) {
   nodeTunneler, proxyTransport, err := CreateNodeDialer(completedOptions)
   if err != nil {
      return nil, err
   }

   kubeAPIServerConfig, insecureServingInfo, serviceResolver, pluginInitializer, err := CreateKubeAPIServerConfig(completedOptions, nodeTunneler, proxyTransport)
   if err != nil {
      return nil, err
   }

   // If additional API servers are added, they should be gated.
   apiExtensionsConfig, err := createAPIExtensionsConfig(*kubeAPIServerConfig.GenericConfig, kubeAPIServerConfig.ExtraConfig.VersionedInformers, pluginInitializer, completedOptions.ServerRunOptions, completedOptions.MasterCount,
      serviceResolver, webhook.NewDefaultAuthenticationInfoResolverWrapper(proxyTransport, kubeAPIServerConfig.GenericConfig.EgressSelector, kubeAPIServerConfig.GenericConfig.LoopbackClientConfig))
   if err != nil {
      return nil, err
   }
   apiExtensionsServer, err := createAPIExtensionsServer(apiExtensionsConfig, genericapiserver.NewEmptyDelegate())
   if err != nil {
      return nil, err
   }

   kubeAPIServer, err := CreateKubeAPIServer(kubeAPIServerConfig, apiExtensionsServer.GenericAPIServer)
   if err != nil {
      return nil, err
   }
   ...

   return aggregatorServer, nil
}

// CreateKubeAPIServer creates and wires a workable kube-apiserver
func CreateKubeAPIServer(kubeAPIServerConfig *master.Config, delegateAPIServer genericapiserver.DelegationTarget) (*master.Master, error) {
	kubeAPIServer, err := kubeAPIServerConfig.Complete().New(delegateAPIServer)
	if err != nil {
		return nil, err
	}

	return kubeAPIServer, nil
}
```

在`CreateKubeAPIServer` 中调用了 `kubeAPIServerConfig.Complete().New` 来完成相关的初始化操作。主要逻辑为：

- 1、调用 `c.GenericConfig.New` 初始化 GenericAPIServer，其主要实现在上文已经分析过；
- 2、判断是否支持 logs 相关的路由，如果支持，则添加 `/logs` 路由；
- 3、调用 `m.InstallLegacyAPI` 将核心 API Resource 添加到路由中，对应到 apiserver 就是以 `/api` 开头的 resource；
- 4、调用 `m.InstallAPIs` 将扩展的 API Resource 添加到路由中，在 apiserver 中即是以 `/apis` 开头的 resource；

```go
// k8s.io/kubernetes/pkg/master/master.go:332
// New returns a new instance of Master from the given config.
// Certain config fields will be set to a default value if unset.
// Certain config fields must be specified, including:
//   KubeletClientConfig
func (c completedConfig) New(delegationTarget genericapiserver.DelegationTarget) (*Master, error) {
	// 1、初始化 GenericAPIServer
	s, err := c.GenericConfig.New("kube-apiserver", delegationTarget)
	if err != nil {
		return nil, err
	}

	// 2、注册 logs 相关的路由
	if c.ExtraConfig.EnableLogsSupport {
		routes.Logs{}.Install(s.Handler.GoRestfulContainer)
	}
  ...
	m := &Master{
		GenericAPIServer:          s,
		ClusterAuthenticationInfo: c.ExtraConfig.ClusterAuthenticationInfo,
	}

	// 3、安装 LegacyAPI
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
	// 4、安装 APIs
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

InstallLegacyAPI的主要功能是将 core API 注册到路由中，是 apiserver 初始化流程中最核心的方法之一，不过其调用链非常深，下面会进行深入分析。将 API 注册到路由其最终的目的就是对外提供 RESTful API 来操作对应 resource，注册 API 主要分为两步，第一步是为 API 中的每个 resource 初始化 RESTStorage 以此操作后端存储中数据的变更，第二步是为每个 resource 根据其 verbs 构建对应的路由。`m.InstallLegacyAPI` 的主要逻辑为：

- 1、调用 `legacyRESTStorageProvider.NewLegacyRESTStorage` 为 LegacyAPI 中各个资源创建 RESTStorage，RESTStorage 的目的是将每种资源的访问路径及其后端存储的操作对应起来；
- 2、初始化 `bootstrap-controller`，并将其加入到 PostStartHook 中，`bootstrap-controller` 是 apiserver 中的一个 controller，主要功能是创建系统所需要的一些 namespace 以及创建 kubernetes service 并定期触发对应的 sync 操作，apiserver 在启动后会通过调用 PostStartHook 来启动 `bootstrap-controller`；
- 3、在为资源创建完 RESTStorage 后，调用 `m.GenericAPIServer.InstallLegacyAPIGroup` 为 APIGroup 注册路由信息，`InstallLegacyAPIGroup`方法的调用链非常深，主要为`InstallLegacyAPIGroup--> installAPIResources --> InstallREST --> Install --> registerResourceHandlers`，最终核心的路由构造在`registerResourceHandlers`方法内，该方法比较复杂，其主要功能是通过上一步骤构造的 REST Storage 判断该资源可以执行哪些操作（如 create、update等），将其对应的操作存入到 action 中，每一个 action 对应一个标准的 REST 操作，如 create 对应的 action 操作为 POST、update 对应的 action 操作为PUT。最终根据 actions 数组依次遍历，对每一个操作添加一个 handler 方法，注册到 route 中去，再将 route 注册到 webservice 中去，webservice 最终会注册到 container 中，遵循 go-restful 的设计模式；

关于 `legacyRESTStorageProvider.NewLegacyRESTStorage` 以及 `m.GenericAPIServer.InstallLegacyAPIGroup` 方法的详细说明在后文中会继续进行讲解。`InstallAPIs` 与 `InstallLegacyAPI` 的主要流程是类似的，限于篇幅此处不再深入分析

### AggregatorServer创建



