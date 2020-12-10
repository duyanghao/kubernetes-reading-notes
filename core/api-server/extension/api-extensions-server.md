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



### CRD相关controller功能

## 总结

