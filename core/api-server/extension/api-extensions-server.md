CRD apiserver
=============

本文分析apiserver的最后一部分：CRD apiserver，在此之前先介绍CR，并展开CRD以及CRD apiserver

## Custom Resource

> > A resource is an endpoint in the Kubernetes API that stores a collection of API objects of a certain kind. For example, the built-in pods resource contains a collection of Pod objects.

> > A custom resource is an extension of the Kubernetes API that is not necessarily available in a default Kubernetes installation. It represents a customization of a particular Kubernetes installation. However, many core Kubernetes functions are now built using custom resources, making Kubernetes more modular.

> > Custom resources can appear and disappear in a running cluster through dynamic registration, and cluster admins can update custom resources independently of the cluster itself. Once a custom resource is installed, users can create and access its objects using kubectl, just as they do for built-in resources like Pods.

Custom Resource，简称CR，是Kubernetes自定义资源类型，与之相对应的就是Kubernetes内置的各种资源类型，例如Pod、Service等。利用CR我们可以定义任何想要的资源类型，例如这里TKE的`Project`等

而对于如何使用CR，官方也给出了两种方式：

> > Kubernetes provides two ways to add custom resources to your cluster:

> > CRDs are simple and can be created without any programming. API Aggregation requires programming, but allows more control over API behaviors like how data is stored and conversion between API versions. Kubernetes provides these two options to meet the needs of different users, so that neither ease of use nor flexibility is compromised.

> > Aggregated APIs are subordinate APIServers that sit behind the primary API server, which acts as a proxy. This arrangement is called API Aggregation (AA). To users, it simply appears that the Kubernetes API is extended.

> > CRDs allow users to create new types of resources without adding another APIserver. You do not need to understand API Aggregation to use CRDs.

> > Regardless of how they are installed, the new resources are referred to as Custom Resources to distinguish them from built-in Kubernetes resources (like pods).

也即Aggregated APIServer和CRDs，这两种方式各有优缺点，适用场景也不相同，如下：

- CRD更简单，不需要programming，更加轻量级；相比AA则需要专门programming并维护
- Aggregated APIServer更加灵活，可以完成很多CRD不具备的事情，例如：对存储层的CRUD定制化操作

详细比较可以参考[这里](https://github.com/kubernetes-sigs/apiserver-builder-alpha/blob/master/docs/compare_with_kubebuilder.md)

## CRD

CRD是第二种扩展Kubernetes API资源的方式，也是普遍使用的一种。这里我们将从源码角度剖析CRD的内部原理

首先我们会创建一个CRD，例子如下：

```go
apiVersion: apiextensions.k8s.io/v1beta1
kind: CustomResourceDefinition
metadata:
  name: projects.duyanghao.example.com
spec:
  group: duyanghao.example.com
  names:
    kind: Project
    listKind: ProjectList
    plural: projects
  scope: Namespaced
  version: v1
```

这个例子中创建了$GROUP=duyanghao.example.com，$VERSION=v1，资源名为Project的自定义资源

### CRD CRUD API server

通过kubectl apply上述yaml后，即创建了Project资源：

```bash
$ kubectl apply -f project.yaml   
customresourcedefinition.apiextensions.k8s.io/projects.duyanghao.example.com created
```

那么谁负责CRD资源的CRUD API接口呢？带着这个疑问我们分析代码：

```go
// CreateServerChain creates the apiservers connected via delegation.
func CreateServerChain(completedOptions completedServerRunOptions, stopCh <-chan struct{}) (*aggregatorapiserver.APIAggregator, error) {
	...
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

func createAPIExtensionsServer(apiextensionsConfig *apiextensionsapiserver.Config, delegateAPIServer genericapiserver.DelegationTarget) (*apiextensionsapiserver.CustomResourceDefinitions, error) {
	return apiextensionsConfig.Complete().New(delegateAPIServer)
}

// k8s.io/kubernetes/staging/src/k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/register.go:24
const GroupName = "apiextensions.k8s.io"

...
// k8s.io/kubernetes/staging/src/k8s.io/apiextensions-apiserver/pkg/apiserver/apiserver.go:129
// New returns a new instance of CustomResourceDefinitions from the given config.
func (c completedConfig) New(delegationTarget genericapiserver.DelegationTarget) (*CustomResourceDefinitions, error) {
	genericServer, err := c.GenericConfig.New("apiextensions-apiserver", delegationTarget)
	if err != nil {
		return nil, err
	}

	s := &CustomResourceDefinitions{
		GenericAPIServer: genericServer,
	}

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

	if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
		return nil, err
	}

	crdClient, err := clientset.NewForConfig(s.GenericAPIServer.LoopbackClientConfig)
	if err != nil {
		// it's really bad that this is leaking here, but until we can fix the test (which I'm pretty sure isn't even testing what it wants to test),
		// we need to be able to move forward
		return nil, fmt.Errorf("failed to create clientset: %v", err)
	}
	s.Informers = externalinformers.NewSharedInformerFactory(crdClient, 5*time.Minute)

	delegateHandler := delegationTarget.UnprotectedHandler()
	if delegateHandler == nil {
		delegateHandler = http.NotFoundHandler()
	}

	versionDiscoveryHandler := &versionDiscoveryHandler{
		discovery: map[schema.GroupVersion]*discovery.APIVersionHandler{},
		delegate:  delegateHandler,
	}
	groupDiscoveryHandler := &groupDiscoveryHandler{
		discovery: map[string]*discovery.APIGroupHandler{},
		delegate:  delegateHandler,
	}
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
```

APIExtensionServer 作为 Delegation 链的最后一层，是处理所有用户通过 Custom Resource Definition 定义的资源服务器。核心代码是：

```go
...
	s := &CustomResourceDefinitions{
		GenericAPIServer: genericServer,
	}

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

	if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
		return nil, err
	}
...

// k8s.io/kubernetes/staging/src/k8s.io/apiextensions-apiserver/pkg/registry/customresourcedefinition/etcd.go:40
// NewREST returns a RESTStorage object that will work against API services.
func NewREST(scheme *runtime.Scheme, optsGetter generic.RESTOptionsGetter) *REST {
	strategy := NewStrategy(scheme)

	store := &genericregistry.Store{
		NewFunc:                  func() runtime.Object { return &apiextensions.CustomResourceDefinition{} },
		NewListFunc:              func() runtime.Object { return &apiextensions.CustomResourceDefinitionList{} },
		PredicateFunc:            MatchCustomResourceDefinition,
		DefaultQualifiedResource: apiextensions.Resource("customresourcedefinitions"),

		CreateStrategy: strategy,
		UpdateStrategy: strategy,
		DeleteStrategy: strategy,
	}
	options := &generic.StoreOptions{RESTOptions: optsGetter, AttrFunc: GetAttrs}
	if err := store.CompleteWithOptions(options); err != nil {
		panic(err) // TODO: Propagate error up
	}
	return &REST{store}
}

// NewStatusREST makes a RESTStorage for status that has more limited options.
// It is based on the original REST so that we can share the same underlying store
func NewStatusREST(scheme *runtime.Scheme, rest *REST) *StatusREST {
	statusStore := *rest.Store
	statusStore.CreateStrategy = nil
	statusStore.DeleteStrategy = nil
	statusStore.UpdateStrategy = NewStatusStrategy(scheme)
	return &StatusREST{store: &statusStore}
}

type StatusREST struct {
	store *genericregistry.Store
}
```

可以看到APIExtensionServer会处理对CRD的CRUD API操作

### crdRegistrationController

在创建了CRD后，我们会发现相应的APIService资源也会随之产生：

```bash
$ kubectl get crds
NAME                                       CREATED AT
projects.duyanghao.example.com             2020-12-10T09:51:29Z

$ kubectl get APIService
NAME                                   SERVICE                      AVAILABLE   AGE
...
v1.duyanghao.example.com               Local                        True        2m2s

$ kubectl get -o yaml APIService/v1.duyanghao.example.com  
apiVersion: apiregistration.k8s.io/v1
kind: APIService
metadata:
  creationTimestamp: "2020-12-10T09:51:32Z"
  labels:
    kube-aggregator.kubernetes.io/automanaged: "true"
  name: v1.duyanghao.example.com
  resourceVersion: "39790960"
  selfLink: /apis/apiregistration.k8s.io/v1/apiservices/v1.duyanghao.example.com
  uid: 40bca9e9-4c37-49e0-98d1-d279a5c88bac
spec:
  group: duyanghao.example.com
  groupPriorityMinimum: 1000
  version: v1
  versionPriority: 100
status:
  conditions:
  - lastTransitionTime: "2020-12-10T09:51:32Z"
    message: Local APIServices are always available
    reason: Local
    status: "True"
    type: Available
```

`crdRegistrationController`：负责将 CRD GroupVersions 自动注册到 APIServices 中，下面我们进行分析：

```go
func createAggregatorServer(aggregatorConfig *aggregatorapiserver.Config, delegateAPIServer genericapiserver.DelegationTarget, apiExtensionInformers apiextensionsinformers.SharedInformerFactory) (*aggregatorapiserver.APIAggregator, error) {
	...
	autoRegistrationController := autoregister.NewAutoRegisterController(aggregatorServer.APIRegistrationInformers.Apiregistration().V1().APIServices(), apiRegistrationClient)
	apiServices := apiServicesToRegister(delegateAPIServer, autoRegistrationController)
	crdRegistrationController := crdregistration.NewCRDRegistrationController(
		apiExtensionInformers.Apiextensions().V1().CustomResourceDefinitions(),
		autoRegistrationController)

	err = aggregatorServer.GenericAPIServer.AddPostStartHook("kube-apiserver-autoregistration", func(context genericapiserver.PostStartHookContext) error {
		go crdRegistrationController.Run(5, context.StopCh)
		go func() {
			// let the CRD controller process the initial set of CRDs before starting the autoregistration controller.
			// this prevents the autoregistration controller's initial sync from deleting APIServices for CRDs that still exist.
			// we only need to do this if CRDs are enabled on this server.  We can't use discovery because we are the source for discovery.
			if aggregatorConfig.GenericConfig.MergedResourceConfig.AnyVersionForGroupEnabled("apiextensions.k8s.io") {
				crdRegistrationController.WaitForInitialSync()
			}
			autoRegistrationController.Run(5, context.StopCh)
		}()
		return nil
	})
	...
	return aggregatorServer, nil
}

type crdRegistrationController struct {
	crdLister crdlisters.CustomResourceDefinitionLister
	crdSynced cache.InformerSynced

	apiServiceRegistration AutoAPIServiceRegistration

	syncHandler func(groupVersion schema.GroupVersion) error

	syncedInitialSet chan struct{}

	// queue is where incoming work is placed to de-dup and to allow "easy" rate limited requeues on errors
	// this is actually keyed by a groupVersion
	queue workqueue.RateLimitingInterface
}

// k8s.io/kubernetes/pkg/master/controller/crdregistration/crdregistration_controller.go:62
// NewCRDRegistrationController returns a controller which will register CRD GroupVersions with the auto APIService registration
// controller so they automatically stay in sync.
func NewCRDRegistrationController(crdinformer crdinformers.CustomResourceDefinitionInformer, apiServiceRegistration AutoAPIServiceRegistration) *crdRegistrationController {
	c := &crdRegistrationController{
		crdLister:              crdinformer.Lister(),
		crdSynced:              crdinformer.Informer().HasSynced,
		apiServiceRegistration: apiServiceRegistration,
		syncedInitialSet:       make(chan struct{}),
		queue:                  workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "crd_autoregistration_controller"),
	}
	c.syncHandler = c.handleVersionUpdate

	crdinformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cast := obj.(*apiextensionsv1.CustomResourceDefinition)
			c.enqueueCRD(cast)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			// Enqueue both old and new object to make sure we remove and add appropriate API services.
			// The working queue will resolve any duplicates and only changes will stay in the queue.
			c.enqueueCRD(oldObj.(*apiextensionsv1.CustomResourceDefinition))
			c.enqueueCRD(newObj.(*apiextensionsv1.CustomResourceDefinition))
		},
		DeleteFunc: func(obj interface{}) {
			cast, ok := obj.(*apiextensionsv1.CustomResourceDefinition)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					klog.V(2).Infof("Couldn't get object from tombstone %#v", obj)
					return
				}
				cast, ok = tombstone.Obj.(*apiextensionsv1.CustomResourceDefinition)
				if !ok {
					klog.V(2).Infof("Tombstone contained unexpected object: %#v", obj)
					return
				}
			}
			c.enqueueCRD(cast)
		},
	})

	return c
}
```

下面是crdRegistrationController的核心逻辑：

```go
func (c *crdRegistrationController) Run(threadiness int, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	// make sure the work queue is shutdown which will trigger workers to end
	defer c.queue.ShutDown()

	klog.Infof("Starting crd-autoregister controller")
	defer klog.Infof("Shutting down crd-autoregister controller")

	// wait for your secondary caches to fill before starting your work
	if !cache.WaitForNamedCacheSync("crd-autoregister", stopCh, c.crdSynced) {
		return
	}

	// process each item in the list once
	if crds, err := c.crdLister.List(labels.Everything()); err != nil {
		utilruntime.HandleError(err)
	} else {
		for _, crd := range crds {
			for _, version := range crd.Spec.Versions {
				if err := c.syncHandler(schema.GroupVersion{Group: crd.Spec.Group, Version: version.Name}); err != nil {
					utilruntime.HandleError(err)
				}
			}
		}
	}
	close(c.syncedInitialSet)

	// start up your worker threads based on threadiness.  Some controllers have multiple kinds of workers
	for i := 0; i < threadiness; i++ {
		// runWorker will loop until "something bad" happens.  The .Until will then rekick the worker
		// after one second
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	// wait until we're told to stop
	<-stopCh
}

func (c *crdRegistrationController) runWorker() {
	// hot loop until we're told to stop.  processNextWorkItem will automatically wait until there's work
	// available, so we don't worry about secondary waits
	for c.processNextWorkItem() {
	}
}

// processNextWorkItem deals with one key off the queue.  It returns false when it's time to quit.
func (c *crdRegistrationController) processNextWorkItem() bool {
	// pull the next work item from queue.  It should be a key we use to lookup something in a cache
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	// you always have to indicate to the queue that you've completed a piece of work
	defer c.queue.Done(key)

	// do your work on the key.  This method will contains your "do stuff" logic
	err := c.syncHandler(key.(schema.GroupVersion))
	if err == nil {
		// if you had no error, tell the queue to stop tracking history for your key.  This will
		// reset things like failure counts for per-item rate limiting
		c.queue.Forget(key)
		return true
	}

	// there was a failure so be sure to report it.  This method allows for pluggable error handling
	// which can be used for things like cluster-monitoring
	utilruntime.HandleError(fmt.Errorf("%v failed with : %v", key, err))
	// since we failed, we should requeue the item to work on later.  This method will add a backoff
	// to avoid hotlooping on particular items (they're probably still not going to work right away)
	// and overall controller protection (everything I've done is broken, this controller needs to
	// calm down or it can starve other useful work) cases.
	c.queue.AddRateLimited(key)

	return true
}

func (c *crdRegistrationController) enqueueCRD(crd *apiextensionsv1.CustomResourceDefinition) {
	for _, version := range crd.Spec.Versions {
		c.queue.Add(schema.GroupVersion{Group: crd.Spec.Group, Version: version.Name})
	}
}
```

重点看syncHandler，如下：

```go
func (c *crdRegistrationController) handleVersionUpdate(groupVersion schema.GroupVersion) error {
	apiServiceName := groupVersion.Version + "." + groupVersion.Group

	// check all CRDs.  There shouldn't that many, but if we have problems later we can index them
	crds, err := c.crdLister.List(labels.Everything())
	if err != nil {
		return err
	}
	for _, crd := range crds {
		if crd.Spec.Group != groupVersion.Group {
			continue
		}
		for _, version := range crd.Spec.Versions {
			if version.Name != groupVersion.Version || !version.Served {
				continue
			}

			c.apiServiceRegistration.AddAPIServiceToSync(&v1.APIService{
				ObjectMeta: metav1.ObjectMeta{Name: apiServiceName},
				Spec: v1.APIServiceSpec{
					Group:                groupVersion.Group,
					Version:              groupVersion.Version,
					GroupPriorityMinimum: 1000, // CRDs should have relatively low priority
					VersionPriority:      100,  // CRDs will be sorted by kube-like versions like any other APIService with the same VersionPriority
				},
			})
			return nil
		}
	}

	c.apiServiceRegistration.RemoveAPIServiceToSync(apiServiceName)
	return nil
}

// AddAPIServiceToSyncOnStart registers an API service to sync only when the controller starts.
func (c *autoRegisterController) AddAPIServiceToSyncOnStart(in *v1.APIService) {
	c.addAPIServiceToSync(in, manageOnStart)
}

// RemoveAPIServiceToSync deletes a registered APIService.
func (c *autoRegisterController) RemoveAPIServiceToSync(name string) {
	c.apiServicesToSyncLock.Lock()
	defer c.apiServicesToSyncLock.Unlock()

	delete(c.apiServicesToSync, name)
	c.queue.Add(name)
}
```

这里会枚举所有CRDs，然后根据CRD定义的crd.Spec.Group以及crd.Spec.Versions字段构建APIService，并添加到autoRegisterController.apiServicesToSync中，由autoRegisterController进行创建以及维护操作。这也是为什么创建完CRD后，后产生对应的APIService对象

### Custom Resource的CRUD API server

在创建完CRD后，也即给kubernetes扩展了一种资源类型，这里为Project，就可以对Project进行CRUD操作了，如下：

```bash
$ kubectl get projects 
No resources found in default namespace.
```

那么对应CR的CRUD API server在哪里呢？比如这里，哪个apiserver处理Project资源的请求呢？

……

### CRD相关controller功能

APIExtensionServer 作为 Delegation 链的最后一层，是处理所有用户通过 Custom Resource Definition 定义的资源服务器

其中包含的 controller 以及功能如下所示：

- `openapiController`：将 crd 资源的变化同步至提供的 OpenAPI 文档，可通过访问 `/openapi/v2` 进行查看；
- `crdController`：负责将 crd 信息注册到 apiVersions 和 apiResources 中，两者的信息可通过 `$ kubectl api-versions` 和 `$ kubectl api-resources` 查看；
- `namingController`：检查 crd obj 中是否有命名冲突，可在 crd `.status.conditions` 中查看；
- `establishingController`：检查 crd 是否处于正常状态，可在 crd `.status.conditions` 中查看；
- `nonStructuralSchemaController`：检查 crd obj 结构是否正常，可在 crd `.status.conditions` 中查看；
- `apiApprovalController`：检查 crd 是否遵循 Kubernetes API 声明策略，可在 crd `.status.conditions` 中查看；
- `finalizingController`：类似于 finalizes 的功能，与 CRs 的删除有关；

这里我们对核心controller功能做解析：

#### crdController

```go
// New returns a new instance of CustomResourceDefinitions from the given config.
func (c completedConfig) New(delegationTarget genericapiserver.DelegationTarget) (*CustomResourceDefinitions, error) {
	genericServer, err := c.GenericConfig.New("apiextensions-apiserver", delegationTarget)
	if err != nil {
		return nil, err
	}

	s := &CustomResourceDefinitions{
		GenericAPIServer: genericServer,
	}

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

	if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
		return nil, err
	}

	crdClient, err := clientset.NewForConfig(s.GenericAPIServer.LoopbackClientConfig)
	if err != nil {
		// it's really bad that this is leaking here, but until we can fix the test (which I'm pretty sure isn't even testing what it wants to test),
		// we need to be able to move forward
		return nil, fmt.Errorf("failed to create clientset: %v", err)
	}
	s.Informers = externalinformers.NewSharedInformerFactory(crdClient, 5*time.Minute)

	delegateHandler := delegationTarget.UnprotectedHandler()
	if delegateHandler == nil {
		delegateHandler = http.NotFoundHandler()
	}

	versionDiscoveryHandler := &versionDiscoveryHandler{
		discovery: map[schema.GroupVersion]*discovery.APIVersionHandler{},
		delegate:  delegateHandler,
	}
	groupDiscoveryHandler := &groupDiscoveryHandler{
		discovery: map[string]*discovery.APIGroupHandler{},
		delegate:  delegateHandler,
	}
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
```

负责将 crd 信息注册到 apiVersions 和 apiResources 中，两者的信息可通过 `$ kubectl api-versions` 和 `$ kubectl api-resources` 查看：

```go
crdController := NewDiscoveryController(s.Informers.Apiextensions().V1().CustomResourceDefinitions(), versionDiscoveryHandler, groupDiscoveryHandler)

func NewDiscoveryController(crdInformer informers.CustomResourceDefinitionInformer, versionHandler *versionDiscoveryHandler, groupHandler *groupDiscoveryHandler) *DiscoveryController {
	c := &DiscoveryController{
		versionHandler: versionHandler,
		groupHandler:   groupHandler,
		crdLister:      crdInformer.Lister(),
		crdsSynced:     crdInformer.Informer().HasSynced,

		queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "DiscoveryController"),
	}

	crdInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addCustomResourceDefinition,
		UpdateFunc: c.updateCustomResourceDefinition,
		DeleteFunc: c.deleteCustomResourceDefinition,
	})

	c.syncFn = c.sync

	return c
}

func (c *DiscoveryController) addCustomResourceDefinition(obj interface{}) {
	castObj := obj.(*apiextensionsv1.CustomResourceDefinition)
	klog.V(4).Infof("Adding customresourcedefinition %s", castObj.Name)
	c.enqueue(castObj)
}

func (c *DiscoveryController) updateCustomResourceDefinition(oldObj, newObj interface{}) {
	castNewObj := newObj.(*apiextensionsv1.CustomResourceDefinition)
	castOldObj := oldObj.(*apiextensionsv1.CustomResourceDefinition)
	klog.V(4).Infof("Updating customresourcedefinition %s", castOldObj.Name)
	// Enqueue both old and new object to make sure we remove and add appropriate Versions.
	// The working queue will resolve any duplicates and only changes will stay in the queue.
	c.enqueue(castNewObj)
	c.enqueue(castOldObj)
}

func (c *DiscoveryController) deleteCustomResourceDefinition(obj interface{}) {
	castObj, ok := obj.(*apiextensionsv1.CustomResourceDefinition)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Couldn't get object from tombstone %#v", obj)
			return
		}
		castObj, ok = tombstone.Obj.(*apiextensionsv1.CustomResourceDefinition)
		if !ok {
			klog.Errorf("Tombstone contained object that is not expected %#v", obj)
			return
		}
	}
	klog.V(4).Infof("Deleting customresourcedefinition %q", castObj.Name)
	c.enqueue(castObj)
}

func (c *DiscoveryController) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()
	defer klog.Infof("Shutting down DiscoveryController")

	klog.Infof("Starting DiscoveryController")

	if !cache.WaitForCacheSync(stopCh, c.crdsSynced) {
		utilruntime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
		return
	}

	// only start one worker thread since its a slow moving API
	go wait.Until(c.runWorker, time.Second, stopCh)

	<-stopCh
}

func (c *DiscoveryController) runWorker() {
	for c.processNextWorkItem() {
	}
}

// processNextWorkItem deals with one key off the queue.  It returns false when it's time to quit.
func (c *DiscoveryController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.syncFn(key.(schema.GroupVersion))
	if err == nil {
		c.queue.Forget(key)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with: %v", key, err))
	c.queue.AddRateLimited(key)

	return true
}

func (c *DiscoveryController) enqueue(obj *apiextensionsv1.CustomResourceDefinition) {
	for _, v := range obj.Spec.Versions {
		c.queue.Add(schema.GroupVersion{Group: obj.Spec.Group, Version: v.Name})
	}
}
```

这里看核心逻辑：

```go
// k8s.io/kubernetes/staging/src/k8s.io/apiextensions-apiserver/pkg/apiserver/customresource_discovery_controller.go:77
func (c *DiscoveryController) sync(version schema.GroupVersion) error {

	apiVersionsForDiscovery := []metav1.GroupVersionForDiscovery{}
	apiResourcesForDiscovery := []metav1.APIResource{}
	versionsForDiscoveryMap := map[metav1.GroupVersion]bool{}

	// 获取所有CRDs  
	crds, err := c.crdLister.List(labels.Everything())
	if err != nil {
		return err
	}
	foundVersion := false
	foundGroup := false
	// 枚举CRD  
	for _, crd := range crds {
		if !apiextensionshelpers.IsCRDConditionTrue(crd, apiextensionsv1.Established) {
			continue
		}

		if crd.Spec.Group != version.Group {
			continue
		}

		foundThisVersion := false
		var storageVersionHash string
		// 枚举CRD对应Version    
		for _, v := range crd.Spec.Versions {
			if !v.Served {
				continue
			}
			// If there is any Served version, that means the group should show up in discovery
			foundGroup = true

			gv := metav1.GroupVersion{Group: crd.Spec.Group, Version: v.Name}
			if !versionsForDiscoveryMap[gv] {
				versionsForDiscoveryMap[gv] = true
				apiVersionsForDiscovery = append(apiVersionsForDiscovery, metav1.GroupVersionForDiscovery{
					GroupVersion: crd.Spec.Group + "/" + v.Name,
					Version:      v.Name,
				})
			}
			if v.Name == version.Version {
				foundThisVersion = true
			}
			if v.Storage {
				storageVersionHash = discovery.StorageVersionHash(gv.Group, gv.Version, crd.Spec.Names.Kind)
			}
		}

		if !foundThisVersion {
			continue
		}
		foundVersion = true

		// 设置可被允许的操作    
		verbs := metav1.Verbs([]string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"})
		// if we're terminating we don't allow some verbs
		if apiextensionshelpers.IsCRDConditionTrue(crd, apiextensionsv1.Terminating) {
			verbs = metav1.Verbs([]string{"delete", "deletecollection", "get", "list", "watch"})
		}
		// 根据CRD.Status field构建APIResource，并添加到apiResourcesForDiscovery中
		apiResourcesForDiscovery = append(apiResourcesForDiscovery, metav1.APIResource{
			Name:               crd.Status.AcceptedNames.Plural,
			SingularName:       crd.Status.AcceptedNames.Singular,
			Namespaced:         crd.Spec.Scope == apiextensionsv1.NamespaceScoped,
			Kind:               crd.Status.AcceptedNames.Kind,
			Verbs:              verbs,
			ShortNames:         crd.Status.AcceptedNames.ShortNames,
			Categories:         crd.Status.AcceptedNames.Categories,
			StorageVersionHash: storageVersionHash,
		})
		// 获取子资源
		subresources, err := apiextensionshelpers.GetSubresourcesForVersion(crd, version.Version)
		if err != nil {
			return err
		}
		if subresources != nil && subresources.Status != nil {
			apiResourcesForDiscovery = append(apiResourcesForDiscovery, metav1.APIResource{
				Name:       crd.Status.AcceptedNames.Plural + "/status",
				Namespaced: crd.Spec.Scope == apiextensionsv1.NamespaceScoped,
				Kind:       crd.Status.AcceptedNames.Kind,
				Verbs:      metav1.Verbs([]string{"get", "patch", "update"}),
			})
		}

		if subresources != nil && subresources.Scale != nil {
			apiResourcesForDiscovery = append(apiResourcesForDiscovery, metav1.APIResource{
				Group:      autoscaling.GroupName,
				Version:    "v1",
				Kind:       "Scale",
				Name:       crd.Status.AcceptedNames.Plural + "/scale",
				Namespaced: crd.Spec.Scope == apiextensionsv1.NamespaceScoped,
				Verbs:      metav1.Verbs([]string{"get", "patch", "update"}),
			})
		}
	}

	if !foundGroup {
		c.groupHandler.unsetDiscovery(version.Group)
		c.versionHandler.unsetDiscovery(version)
		return nil
	}

	sortGroupDiscoveryByKubeAwareVersion(apiVersionsForDiscovery)

	apiGroup := metav1.APIGroup{
		Name:     version.Group,
		Versions: apiVersionsForDiscovery,
		// the preferred versions for a group is the first item in
		// apiVersionsForDiscovery after it put in the right ordered
		PreferredVersion: apiVersionsForDiscovery[0],
	}
	c.groupHandler.setDiscovery(version.Group, discovery.NewAPIGroupHandler(Codecs, apiGroup))

	if !foundVersion {
		c.versionHandler.unsetDiscovery(version)
		return nil
	}
	c.versionHandler.setDiscovery(version, discovery.NewAPIVersionHandler(Codecs, version, discovery.APIResourceListerFunc(func() []metav1.APIResource {
		return apiResourcesForDiscovery
	})))

	return nil
}
```

这里对CRD构造了apiGroup和APIResource列表，并注册了apiGroup和apiVersion的路由：

```go
// k8s.io/kubernetes/staging/src/k8s.io/apiserver/pkg/endpoints/discovery/group.go:38
func NewAPIGroupHandler(serializer runtime.NegotiatedSerializer, group metav1.APIGroup) *APIGroupHandler {
	if keepUnversioned(group.Name) {
		// Because in release 1.1, /apis/extensions returns response with empty
		// APIVersion, we use stripVersionNegotiatedSerializer to keep the
		// response backwards compatible.
		serializer = stripVersionNegotiatedSerializer{serializer}
	}

	return &APIGroupHandler{
		serializer: serializer,
		group:      group,
	}
}

func (r *groupDiscoveryHandler) setDiscovery(group string, discovery *discovery.APIGroupHandler) {
	r.discoveryLock.Lock()
	defer r.discoveryLock.Unlock()

	r.discovery[group] = discovery
}

const APIGroupPrefix = "/apis"

func (s *APIGroupHandler) WebService() *restful.WebService {
	mediaTypes, _ := negotiation.MediaTypesForSerializer(s.serializer)
	ws := new(restful.WebService)
	ws.Path(APIGroupPrefix + "/" + s.group.Name)
	ws.Doc("get information of a group")
	ws.Route(ws.GET("/").To(s.handle).
		Doc("get information of a group").
		Operation("getAPIGroup").
		Produces(mediaTypes...).
		Consumes(mediaTypes...).
		Writes(metav1.APIGroup{}))
	return ws
}

// handle returns a handler which will return the api.GroupAndVersion of the group.
func (s *APIGroupHandler) handle(req *restful.Request, resp *restful.Response) {
	s.ServeHTTP(resp.ResponseWriter, req.Request)
}

func (s *APIGroupHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	responsewriters.WriteObjectNegotiated(s.serializer, negotiation.DefaultEndpointRestrictions, schema.GroupVersion{}, w, req, http.StatusOK, &s.group)
}
```

1、**上述代码注册了apiGroup的路由，返回某个api group下所有版本信息**，如下：

```go
apiGroup := metav1.APIGroup{
		Name:     version.Group,
		Versions: apiVersionsForDiscovery,
		// the preferred versions for a group is the first item in
		// apiVersionsForDiscovery after it put in the right ordered
		PreferredVersion: apiVersionsForDiscovery[0],
	}
```

返回如下：

```bash
$ curl http://localhost:8080/apis/apiextensions.k8s.io     
{
  "kind": "APIGroup",
  "apiVersion": "v1",
  "name": "apiextensions.k8s.io",
  "versions": [
    {
      "groupVersion": "apiextensions.k8s.io/v1",
      "version": "v1"
    },
    {
      "groupVersion": "apiextensions.k8s.io/v1beta1",
      "version": "v1beta1"
    }
  ],
  "preferredVersion": {
    "groupVersion": "apiextensions.k8s.io/v1",
    "version": "v1"
  }
}
```

2、**而如果要返回所有Kubernetes集群资源的版本信息**，则可以使用kubectl api-versions命令，对应代码如下：

```go
// New creates a new server which logically combines the handling chain with the passed server.
// name is used to differentiate for logging. The handler chain in particular can be difficult as it starts delgating.
// delegationTarget may not be nil.
func (c completedConfig) New(name string, delegationTarget DelegationTarget) (*GenericAPIServer, error) {
	if c.Serializer == nil {
		return nil, fmt.Errorf("Genericapiserver.New() called with config.Serializer == nil")
	}
	if c.LoopbackClientConfig == nil {
		return nil, fmt.Errorf("Genericapiserver.New() called with config.LoopbackClientConfig == nil")
	}
	if c.EquivalentResourceRegistry == nil {
		return nil, fmt.Errorf("Genericapiserver.New() called with config.EquivalentResourceRegistry == nil")
	}

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
	return s, nil
}

func installAPI(s *GenericAPIServer, c *Config) {
	...
	if c.EnableDiscovery {
		s.Handler.GoRestfulContainer.Add(s.DiscoveryGroupManager.WebService())
	}
}

// k8s.io/kubernetes/staging/src/k8s.io/apiserver/pkg/endpoints/discovery/root.go:59
func NewRootAPIsHandler(addresses Addresses, serializer runtime.NegotiatedSerializer) *rootAPIsHandler {
	// Because in release 1.1, /apis returns response with empty APIVersion, we
	// use stripVersionNegotiatedSerializer to keep the response backwards
	// compatible.
	serializer = stripVersionNegotiatedSerializer{serializer}

	return &rootAPIsHandler{
		addresses:  addresses,
		serializer: serializer,
		apiGroups:  map[string]metav1.APIGroup{},
	}
}

// named groups(/apis)
// k8s.io/kubernetes/staging/src/k8s.io/apiserver/pkg/server/genericapiserver.go:449
// Exposes given api groups in the API.
func (s *GenericAPIServer) InstallAPIGroups(apiGroupInfos ...*APIGroupInfo) error {
	for _, apiGroupInfo := range apiGroupInfos {
		// Do not register empty group or empty version.  Doing so claims /apis/ for the wrong entity to be returned.
		// Catching these here places the error  much closer to its origin
		if len(apiGroupInfo.PrioritizedVersions[0].Group) == 0 {
			return fmt.Errorf("cannot register handler with an empty group for %#v", *apiGroupInfo)
		}
		if len(apiGroupInfo.PrioritizedVersions[0].Version) == 0 {
			return fmt.Errorf("cannot register handler with an empty version for %#v", *apiGroupInfo)
		}
	}

	openAPIModels, err := s.getOpenAPIModels(APIGroupPrefix, apiGroupInfos...)
	if err != nil {
		return fmt.Errorf("unable to get openapi models: %v", err)
	}

	for _, apiGroupInfo := range apiGroupInfos {
		if err := s.installAPIResources(APIGroupPrefix, apiGroupInfo, openAPIModels); err != nil {
			return fmt.Errorf("unable to install api resources: %v", err)
		}

		// setup discovery
		// Install the version handler.
		// Add a handler at /apis/<groupName> to enumerate all versions supported by this group.
		apiVersionsForDiscovery := []metav1.GroupVersionForDiscovery{}
		for _, groupVersion := range apiGroupInfo.PrioritizedVersions {
			// Check the config to make sure that we elide versions that don't have any resources
			if len(apiGroupInfo.VersionedResourcesStorageMap[groupVersion.Version]) == 0 {
				continue
			}
			apiVersionsForDiscovery = append(apiVersionsForDiscovery, metav1.GroupVersionForDiscovery{
				GroupVersion: groupVersion.String(),
				Version:      groupVersion.Version,
			})
		}
		preferredVersionForDiscovery := metav1.GroupVersionForDiscovery{
			GroupVersion: apiGroupInfo.PrioritizedVersions[0].String(),
			Version:      apiGroupInfo.PrioritizedVersions[0].Version,
		}
		apiGroup := metav1.APIGroup{
			Name:             apiGroupInfo.PrioritizedVersions[0].Group,
			Versions:         apiVersionsForDiscovery,
			PreferredVersion: preferredVersionForDiscovery,
		}

		s.DiscoveryGroupManager.AddGroup(apiGroup)
		s.Handler.GoRestfulContainer.Add(discovery.NewAPIGroupHandler(s.Serializer, apiGroup).WebService())
	}
	return nil
}

func (s *rootAPIsHandler) AddGroup(apiGroup metav1.APIGroup) {
	s.lock.Lock()
	defer s.lock.Unlock()

	_, alreadyExists := s.apiGroups[apiGroup.Name]

	s.apiGroups[apiGroup.Name] = apiGroup
	if !alreadyExists {
		s.apiGroupNames = append(s.apiGroupNames, apiGroup.Name)
	}
}

// WebService returns a webservice serving api group discovery.
// Note: during the server runtime apiGroups might change.
func (s *rootAPIsHandler) WebService() *restful.WebService {
	mediaTypes, _ := negotiation.MediaTypesForSerializer(s.serializer)
	ws := new(restful.WebService)
	ws.Path(APIGroupPrefix)
	ws.Doc("get available API versions")
	ws.Route(ws.GET("/").To(s.restfulHandle).
		Doc("get available API versions").
		Operation("getAPIVersions").
		Produces(mediaTypes...).
		Consumes(mediaTypes...).
		Writes(metav1.APIGroupList{}))
	return ws
}

func (s *rootAPIsHandler) restfulHandle(req *restful.Request, resp *restful.Response) {
	s.ServeHTTP(resp.ResponseWriter, req.Request)
}

func (s *rootAPIsHandler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	orderedGroups := []metav1.APIGroup{}
	for _, groupName := range s.apiGroupNames {
		orderedGroups = append(orderedGroups, s.apiGroups[groupName])
	}

	clientIP := utilnet.GetClientIP(req)
	serverCIDR := s.addresses.ServerAddressByClientCIDRs(clientIP)
	groups := make([]metav1.APIGroup, len(orderedGroups))
	for i := range orderedGroups {
		groups[i] = orderedGroups[i]
		groups[i].ServerAddressByClientCIDRs = serverCIDR
	}

	responsewriters.WriteObjectNegotiated(s.serializer, negotiation.DefaultEndpointRestrictions, schema.GroupVersion{}, resp, req, http.StatusOK, &metav1.APIGroupList{Groups: groups})
}

// core groups(/api)
func (s *GenericAPIServer) InstallLegacyAPIGroup(apiPrefix string, apiGroupInfo *APIGroupInfo) error {
	if !s.legacyAPIGroupPrefixes.Has(apiPrefix) {
		return fmt.Errorf("%q is not in the allowed legacy API prefixes: %v", apiPrefix, s.legacyAPIGroupPrefixes.List())
	}

	openAPIModels, err := s.getOpenAPIModels(apiPrefix, apiGroupInfo)
	if err != nil {
		return fmt.Errorf("unable to get openapi models: %v", err)
	}

	if err := s.installAPIResources(apiPrefix, apiGroupInfo, openAPIModels); err != nil {
		return err
	}

	// Install the version handler.
	// Add a handler at /<apiPrefix> to enumerate the supported api versions.
	s.Handler.GoRestfulContainer.Add(discovery.NewLegacyRootAPIHandler(s.discoveryAddresses, s.Serializer, apiPrefix).WebService())

	return nil
}

func NewLegacyRootAPIHandler(addresses Addresses, serializer runtime.NegotiatedSerializer, apiPrefix string) *legacyRootAPIHandler {
	// Because in release 1.1, /apis returns response with empty APIVersion, we
	// use stripVersionNegotiatedSerializer to keep the response backwards
	// compatible.
	serializer = stripVersionNegotiatedSerializer{serializer}

	return &legacyRootAPIHandler{
		addresses:  addresses,
		apiPrefix:  apiPrefix,
		serializer: serializer,
	}
}

// AddApiWebService adds a service to return the supported api versions at the legacy /api.
func (s *legacyRootAPIHandler) WebService() *restful.WebService {
	mediaTypes, _ := negotiation.MediaTypesForSerializer(s.serializer)
	ws := new(restful.WebService)
	ws.Path(s.apiPrefix)
	ws.Doc("get available API versions")
	ws.Route(ws.GET("/").To(s.handle).
		Doc("get available API versions").
		Operation("getAPIVersions").
		Produces(mediaTypes...).
		Consumes(mediaTypes...).
		Writes(metav1.APIVersions{}))
	return ws
}

func (s *legacyRootAPIHandler) handle(req *restful.Request, resp *restful.Response) {
	clientIP := utilnet.GetClientIP(req.Request)
	apiVersions := &metav1.APIVersions{
		ServerAddressByClientCIDRs: s.addresses.ServerAddressByClientCIDRs(clientIP),
		Versions:                   []string{"v1"},
	}

	responsewriters.WriteObjectNegotiated(s.serializer, negotiation.DefaultEndpointRestrictions, schema.GroupVersion{}, resp.ResponseWriter, req.Request, http.StatusOK, apiVersions)
}
```

注意这里会注册两种api versions路径路由：core group(/api)以及named groups(/apis)，如下：

```go
# kubectl -v=8 api-versions 
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

可以看到对于kubectl api-versions命令，这里发出了两个请求，分别是https://127.0.0.1:6443/api以及https://127.0.0.1:6443/apis，并在最后将两个请求的返回结果进行了合并，如下：

```bash
$ kubectl api-versions
admissionregistration.k8s.io/v1
admissionregistration.k8s.io/v1beta1
apiextensions.k8s.io/v1
apiextensions.k8s.io/v1beta1
apiregistration.k8s.io/v1
apiregistration.k8s.io/v1beta1
apps/v1
...
v1
```

注意v1是/api接口的返回(metav1.APIVersions)；其它则是/apis的返回(metav1.APIGroup)

```go
// APIGroup contains the name, the supported versions, and the preferred version
// of a group.
type APIGroup struct {
	TypeMeta `json:",inline"`
	// name is the name of the group.
	Name string `json:"name" protobuf:"bytes,1,opt,name=name"`
	// versions are the versions supported in this group.
	Versions []GroupVersionForDiscovery `json:"versions" protobuf:"bytes,2,rep,name=versions"`
	// preferredVersion is the version preferred by the API server, which
	// probably is the storage version.
	// +optional
	PreferredVersion GroupVersionForDiscovery `json:"preferredVersion,omitempty" protobuf:"bytes,3,opt,name=preferredVersion"`
	// a map of client CIDR to server address that is serving this group.
	// This is to help clients reach servers in the most network-efficient way possible.
	// Clients can use the appropriate server address as per the CIDR that they match.
	// In case of multiple matches, clients should use the longest matching CIDR.
	// The server returns only those CIDRs that it thinks that the client can match.
	// For example: the master will return an internal IP CIDR only, if the client reaches the server using an internal IP.
	// Server looks at X-Forwarded-For header or X-Real-Ip header or request.RemoteAddr (in that order) to get the client IP.
	// +optional
	ServerAddressByClientCIDRs []ServerAddressByClientCIDR `json:"serverAddressByClientCIDRs,omitempty" protobuf:"bytes,4,rep,name=serverAddressByClientCIDRs"`
}

// APIVersions lists the versions that are available, to allow clients to
// discover the API at /api, which is the root path of the legacy v1 API.
//
// +protobuf.options.(gogoproto.goproto_stringer)=false
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type APIVersions struct {
	TypeMeta `json:",inline"`
	// versions are the api versions that are available.
	Versions []string `json:"versions" protobuf:"bytes,1,rep,name=versions"`
	// a map of client CIDR to server address that is serving this group.
	// This is to help clients reach servers in the most network-efficient way possible.
	// Clients can use the appropriate server address as per the CIDR that they match.
	// In case of multiple matches, clients should use the longest matching CIDR.
	// The server returns only those CIDRs that it thinks that the client can match.
	// For example: the master will return an internal IP CIDR only, if the client reaches the server using an internal IP.
	// Server looks at X-Forwarded-For header or X-Real-Ip header or request.RemoteAddr (in that order) to get the client IP.
	ServerAddressByClientCIDRs []ServerAddressByClientCIDR `json:"serverAddressByClientCIDRs" protobuf:"bytes,2,rep,name=serverAddressByClientCIDRs"`
}
```

3、**如果要查询某个版本下的所有资源类型**，则需要看apiVersion的注册代码：

```go
// k8s.io/kubernetes/staging/src/k8s.io/apiserver/pkg/endpoints/discovery/version.go:50
func NewAPIVersionHandler(serializer runtime.NegotiatedSerializer, groupVersion schema.GroupVersion, apiResourceLister APIResourceLister) *APIVersionHandler {
	if keepUnversioned(groupVersion.Group) {
		// Because in release 1.1, /apis/extensions returns response with empty
		// APIVersion, we use stripVersionNegotiatedSerializer to keep the
		// response backwards compatible.
		serializer = stripVersionNegotiatedSerializer{serializer}
	}

	return &APIVersionHandler{
		serializer:        serializer,
		groupVersion:      groupVersion,
		apiResourceLister: apiResourceLister,
	}
}

func (s *APIVersionHandler) AddToWebService(ws *restful.WebService) {
	mediaTypes, _ := negotiation.MediaTypesForSerializer(s.serializer)
	ws.Route(ws.GET("/").To(s.handle).
		Doc("get available resources").
		Operation("getAPIResources").
		Produces(mediaTypes...).
		Consumes(mediaTypes...).
		Writes(metav1.APIResourceList{}))
}

// handle returns a handler which will return the api.VersionAndVersion of the group.
func (s *APIVersionHandler) handle(req *restful.Request, resp *restful.Response) {
	s.ServeHTTP(resp.ResponseWriter, req.Request)
}

func (s *APIVersionHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	responsewriters.WriteObjectNegotiated(s.serializer, negotiation.DefaultEndpointRestrictions, schema.GroupVersion{}, w, req, http.StatusOK,
		&metav1.APIResourceList{GroupVersion: s.groupVersion.String(), APIResources: s.apiResourceLister.ListAPIResources()})
}

func (f APIResourceListerFunc) ListAPIResources() []metav1.APIResource {
	return f()
}

func() []metav1.APIResource {
		return apiResourcesForDiscovery
}

...
// k8s.io/kubernetes/staging/src/k8s.io/apiserver/pkg/endpoints/groupversion.go:94
// InstallREST registers the REST handlers (storage, watch, proxy and redirect) into a restful Container.
// It is expected that the provided path root prefix will serve all operations. Root MUST NOT end
// in a slash.
func (g *APIGroupVersion) InstallREST(container *restful.Container) error {
	prefix := path.Join(g.Root, g.GroupVersion.Group, g.GroupVersion.Version)
	installer := &APIInstaller{
		group:             g,
		prefix:            prefix,
		minRequestTimeout: g.MinRequestTimeout,
	}

	apiResources, ws, registrationErrors := installer.Install()
	versionDiscoveryHandler := discovery.NewAPIVersionHandler(g.Serializer, g.GroupVersion, staticLister{apiResources})
	versionDiscoveryHandler.AddToWebService(ws)
	container.Add(ws)
	return utilerrors.NewAggregate(registrationErrors)
}

// staticLister implements the APIResourceLister interface
type staticLister struct {
	list []metav1.APIResource
}

func (s staticLister) ListAPIResources() []metav1.APIResource {
	return s.list
}
```

获取某个version下的所有apiResources：

```go
$ GET http://127.0.0.1:8080/apis/apps/v1|python -m json.tool
{
    "apiVersion": "v1",
    "groupVersion": "apps/v1",
    "kind": "APIResourceList",
    "resources": [
        {
            "kind": "ControllerRevision",
            "name": "controllerrevisions",
            "namespaced": true,
            "singularName": "",
            "storageVersionHash": "85nkx63pcBU=",
            "verbs": [
                "create",
                "delete",
                "deletecollection",
                "get",
                "list",
                "patch",
                "update",
                "watch"
            ]
        },
        {
            "categories": [
                "all"
            ],
            "kind": "DaemonSet",
            "name": "daemonsets",
            "namespaced": true,
            "shortNames": [
                "ds"
            ],
            "singularName": "",
            "storageVersionHash": "dd7pWHUlMKQ=",
            "verbs": [
                "create",
                "delete",
                "deletecollection",
                "get",
                "list",
                "patch",
                "update",
                "watch"
            ]
        },
        {
            "kind": "DaemonSet",
            "name": "daemonsets/status",
            "namespaced": true,
            "singularName": "",
            "verbs": [
                "get",
                "patch",
                "update"
            ]
        },
        {
            "categories": [
                "all"
            ],
            "kind": "Deployment",
            "name": "deployments",
            "namespaced": true,
            "shortNames": [
                "deploy"
            ],
            "singularName": "",
            "storageVersionHash": "8aSe+NMegvE=",
            "verbs": [
                "create",
                "delete",
                "deletecollection",
                "get",
                "list",
                "patch",
                "update",
                "watch"
            ]
        },
        {
            "group": "autoscaling",
            "kind": "Scale",
            "name": "deployments/scale",
            "namespaced": true,
            "singularName": "",
            "verbs": [
                "get",
                "patch",
                "update"
            ],
            "version": "v1"
        },
        {
            "kind": "Deployment",
            "name": "deployments/status",
            "namespaced": true,
            "singularName": "",
            "verbs": [
                "get",
                "patch",
                "update"
            ]
        },
        {
            "categories": [
                "all"
            ],
            "kind": "ReplicaSet",
            "name": "replicasets",
            "namespaced": true,
            "shortNames": [
                "rs"
            ],
            "singularName": "",
            "storageVersionHash": "P1RzHs8/mWQ=",
            "verbs": [
                "create",
                "delete",
                "deletecollection",
                "get",
                "list",
                "patch",
                "update",
                "watch"
            ]
        },
        {
            "group": "autoscaling",
            "kind": "Scale",
            "name": "replicasets/scale",
            "namespaced": true,
            "singularName": "",
            "verbs": [
                "get",
                "patch",
                "update"
            ],
            "version": "v1"
        },
        {
            "kind": "ReplicaSet",
            "name": "replicasets/status",
            "namespaced": true,
            "singularName": "",
            "verbs": [
                "get",
                "patch",
                "update"
            ]
        },
        {
            "categories": [
                "all"
            ],
            "kind": "StatefulSet",
            "name": "statefulsets",
            "namespaced": true,
            "shortNames": [
                "sts"
            ],
            "singularName": "",
            "storageVersionHash": "H+vl74LkKdo=",
            "verbs": [
                "create",
                "delete",
                "deletecollection",
                "get",
                "list",
                "patch",
                "update",
                "watch"
            ]
        },
        {
            "group": "autoscaling",
            "kind": "Scale",
            "name": "statefulsets/scale",
            "namespaced": true,
            "singularName": "",
            "verbs": [
                "get",
                "patch",
                "update"
            ],
            "version": "v1"
        },
        {
            "kind": "StatefulSet",
            "name": "statefulsets/status",
            "namespaced": true,
            "singularName": "",
            "verbs": [
                "get",
                "patch",
                "update"
            ]
        }
    ]
}

$ GET http://127.0.0.1:8080/apis/apiextensions.k8s.io/v1|python -m json.tool
{
    "apiVersion": "v1",
    "groupVersion": "apiextensions.k8s.io/v1",
    "kind": "APIResourceList",
    "resources": [
        {
            "kind": "CustomResourceDefinition",
            "name": "customresourcedefinitions",
            "namespaced": false,
            "shortNames": [
                "crd",
                "crds"
            ],
            "singularName": "",
            "storageVersionHash": "jfWCUB31mvA=",
            "verbs": [
                "create",
                "delete",
                "deletecollection",
                "get",
                "list",
                "patch",
                "update",
                "watch"
            ]
        },
        {
            "kind": "CustomResourceDefinition",
            "name": "customresourcedefinitions/status",
            "namespaced": false,
            "singularName": "",
            "verbs": [
                "get",
                "patch",
                "update"
            ]
        }
    ]
}

$ GET http://127.0.0.1:8080/apis/duyanghao.example.com/v1|python -m json.tool
{
    "apiVersion": "v1",
    "groupVersion": "duyanghao.example.com/v1",
    "kind": "APIResourceList",
    "resources": [
        {
            "kind": "Project",
            "name": "projects",
            "namespaced": true,
            "singularName": "project",
            "storageVersionHash": "V5qrM7hF17Y=",
            "verbs": [
                "delete",
                "deletecollection",
                "get",
                "list",
                "patch",
                "create",
                "update",
                "watch"
            ]
        }
    ]
}

$ curl http://127.0.0.1:8080/api/v1?timeout=32  
{
  "kind": "APIResourceList",
  "groupVersion": "v1",
  "resources": [
    {
      "name": "bindings",
      "singularName": "",
      "namespaced": true,
      "kind": "Binding",
      "verbs": [
        "create"
      ]
    },
    {
      "name": "componentstatuses",
      "singularName": "",
      "namespaced": false,
      "kind": "ComponentStatus",
      "verbs": [
        "get",
        "list"
      ],
      "shortNames": [
        "cs"
      ]
    },
    {
      "name": "configmaps",
      "singularName": "",
      "namespaced": true,
      "kind": "ConfigMap",
      "verbs": [
        "create",
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "shortNames": [
        "cm"
      ],
      "storageVersionHash": "qFsyl6wFWjQ="
    },
    {
      "name": "endpoints",
      "singularName": "",
      "namespaced": true,
      "kind": "Endpoints",
      "verbs": [
        "create",
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "shortNames": [
        "ep"
      ],
      "storageVersionHash": "fWeeMqaN/OA="
    },
    ...
  }
```

4、**kubectl api-resources命令就是先获取所有API版本信息，然后对每一个版本调用上述接口获取该版本下的所有API资源类型**

```bash
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
I1211 15:19:47.617161   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/edge.eck.io/v1?timeout=32s
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
I1211 15:19:47.617238   15077 round_trippers.go:420] GET https://127.0.0.1:6443/apis/master.cloud.tencent.com/v1alpha1?timeout=32s
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



## 总结

