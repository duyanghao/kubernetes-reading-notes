kubernetes aggregated-apiserver
===============================

Table of Contents
=================

* [前言](#前言)
* [sample-apiserver启动流程](#sample-apiserver启动流程)
* [kube-apiserver与sample-apiserver的对接](#kube-apiserver与sample-apiserver的对接)
* [Local APIService产生原理](#Local APIService产生原理)
* [总结](#总结)

## 前言

这里以sample apiserver为例解析aggregated-apiserver的请求流程

如图为[apiserver-builder-alpha](https://github.com/kubernetes-sigs/apiserver-builder-alpha/blob/master/docs/concepts/api_building_overview.md)对AA的工作流解释：

![Extension apiservers](https://github.com/kubernetes-sigs/apiserver-builder-alpha/raw/master/docs/concepts/extensionserver.jpg)

## sample-apiserver启动流程

```go
func main() {
	logs.InitLogs()
	defer logs.FlushLogs()

	stopCh := genericapiserver.SetupSignalHandler()
	options := server.NewWardleServerOptions(os.Stdout, os.Stderr)
	cmd := server.NewCommandStartWardleServer(options, stopCh)
	cmd.Flags().AddGoFlagSet(flag.CommandLine)
	if err := cmd.Execute(); err != nil {
		klog.Fatal(err)
	}
}

...
// NewCommandStartWardleServer provides a CLI handler for 'start master' command
// with a default WardleServerOptions.
func NewCommandStartWardleServer(defaults *WardleServerOptions, stopCh <-chan struct{}) *cobra.Command {
	o := *defaults
	cmd := &cobra.Command{
		Short: "Launch a wardle API server",
		Long:  "Launch a wardle API server",
		RunE: func(c *cobra.Command, args []string) error {
			if err := o.Complete(); err != nil {
				return err
			}
			if err := o.Validate(args); err != nil {
				return err
			}
			if err := o.RunWardleServer(stopCh); err != nil {
				return err
			}
			return nil
		},
	}

	flags := cmd.Flags()
	o.RecommendedOptions.AddFlags(flags)
	utilfeature.DefaultMutableFeatureGate.AddFlag(flags)

	return cmd
}

// RunWardleServer starts a new WardleServer given WardleServerOptions
func (o WardleServerOptions) RunWardleServer(stopCh <-chan struct{}) error {
	config, err := o.Config()
	if err != nil {
		return err
	}

	server, err := config.Complete().New()
	if err != nil {
		return err
	}

	server.GenericAPIServer.AddPostStartHookOrDie("start-sample-server-informers", func(context genericapiserver.PostStartHookContext) error {
		config.GenericConfig.SharedInformerFactory.Start(context.StopCh)
		o.SharedInformerFactory.Start(context.StopCh)
		return nil
	})

	return server.GenericAPIServer.PrepareRun().Run(stopCh)
}
```

RunWardleServer启动WardleServer，如下：

```go
// Config returns config for the api server given WardleServerOptions
func (o *WardleServerOptions) Config() (*apiserver.Config, error) {
	// TODO have a "real" external address
	if err := o.RecommendedOptions.SecureServing.MaybeDefaultWithSelfSignedCerts("localhost", nil, []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		return nil, fmt.Errorf("error creating self-signed certificates: %v", err)
	}

	o.RecommendedOptions.Etcd.StorageConfig.Paging = utilfeature.DefaultFeatureGate.Enabled(features.APIListChunking)

	o.RecommendedOptions.ExtraAdmissionInitializers = func(c *genericapiserver.RecommendedConfig) ([]admission.PluginInitializer, error) {
		client, err := clientset.NewForConfig(c.LoopbackClientConfig)
		if err != nil {
			return nil, err
		}
		informerFactory := informers.NewSharedInformerFactory(client, c.LoopbackClientConfig.Timeout)
		o.SharedInformerFactory = informerFactory
		return []admission.PluginInitializer{wardleinitializer.New(informerFactory)}, nil
	}

	serverConfig := genericapiserver.NewRecommendedConfig(apiserver.Codecs)

	serverConfig.OpenAPIConfig = genericapiserver.DefaultOpenAPIConfig(sampleopenapi.GetOpenAPIDefinitions, openapi.NewDefinitionNamer(apiserver.Scheme))
	serverConfig.OpenAPIConfig.Info.Title = "Wardle"
	serverConfig.OpenAPIConfig.Info.Version = "0.1"

	if err := o.RecommendedOptions.ApplyTo(serverConfig); err != nil {
		return nil, err
	}

	config := &apiserver.Config{
		GenericConfig: serverConfig,
		ExtraConfig:   apiserver.ExtraConfig{},
	}
	return config, nil
}
```

返回了apiserver.Config：

```go
// Config defines the config for the apiserver
type Config struct {
	GenericConfig *genericapiserver.RecommendedConfig
	ExtraConfig   ExtraConfig
}
```

接着执行server, err := config.Complete().New()：

```go
// Complete fills in any fields not set that are required to have valid data. It's mutating the receiver.
func (cfg *Config) Complete() CompletedConfig {
	c := completedConfig{
		cfg.GenericConfig.Complete(),
		&cfg.ExtraConfig,
	}

	c.GenericConfig.Version = &version.Info{
		Major: "1",
		Minor: "0",
	}

	return CompletedConfig{&c}
}

// k8s.io/kubernetes/staging/src/k8s.io/sample-apiserver/pkg/apiserver/apiserver.go:103
// New returns a new instance of WardleServer from the given config.
func (c completedConfig) New() (*WardleServer, error) {
	genericServer, err := c.GenericConfig.New("sample-apiserver", genericapiserver.NewEmptyDelegate())
	if err != nil {
		return nil, err
	}

	s := &WardleServer{
		GenericAPIServer: genericServer,
	}

	apiGroupInfo := genericapiserver.NewDefaultAPIGroupInfo(wardle.GroupName, Scheme, metav1.ParameterCodec, Codecs)

	v1alpha1storage := map[string]rest.Storage{}
	v1alpha1storage["flunders"] = wardleregistry.RESTInPeace(flunderstorage.NewREST(Scheme, c.GenericConfig.RESTOptionsGetter))
	v1alpha1storage["fischers"] = wardleregistry.RESTInPeace(fischerstorage.NewREST(Scheme, c.GenericConfig.RESTOptionsGetter))
	apiGroupInfo.VersionedResourcesStorageMap["v1alpha1"] = v1alpha1storage

	v1beta1storage := map[string]rest.Storage{}
	v1beta1storage["flunders"] = wardleregistry.RESTInPeace(flunderstorage.NewREST(Scheme, c.GenericConfig.RESTOptionsGetter))
	apiGroupInfo.VersionedResourcesStorageMap["v1beta1"] = v1beta1storage

	if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
		return nil, err
	}

	return s, nil
}
```

这里主要看New函数，在该函数中会注册Aggregated API资源：

```go
// NewDefaultAPIGroupInfo returns an APIGroupInfo stubbed with "normal" values
// exposed for easier composition from other packages
func NewDefaultAPIGroupInfo(group string, scheme *runtime.Scheme, parameterCodec runtime.ParameterCodec, codecs serializer.CodecFactory) APIGroupInfo {
	return APIGroupInfo{
		PrioritizedVersions:          scheme.PrioritizedVersionsForGroup(group),
		VersionedResourcesStorageMap: map[string]map[string]rest.Storage{},
		// TODO unhardcode this.  It was hardcoded before, but we need to re-evaluate
		OptionsExternalVersion: &schema.GroupVersion{Version: "v1"},
		Scheme:                 scheme,
		ParameterCodec:         parameterCodec,
		NegotiatedSerializer:   codecs,
	}
}

const GroupName = "wardle.example.com"

// Info about an API group.
type APIGroupInfo struct {
	PrioritizedVersions []schema.GroupVersion
	// Info about the resources in this group. It's a map from version to resource to the storage.
	VersionedResourcesStorageMap map[string]map[string]rest.Storage
	// OptionsExternalVersion controls the APIVersion used for common objects in the
	// schema like api.Status, api.DeleteOptions, and metav1.ListOptions. Other implementors may
	// define a version "v1beta1" but want to use the Kubernetes "v1" internal objects.
	// If nil, defaults to groupMeta.GroupVersion.
	// TODO: Remove this when https://github.com/kubernetes/kubernetes/issues/19018 is fixed.
	OptionsExternalVersion *schema.GroupVersion
	// MetaGroupVersion defaults to "meta.k8s.io/v1" and is the scheme group version used to decode
	// common API implementations like ListOptions. Future changes will allow this to vary by group
	// version (for when the inevitable meta/v2 group emerges).
	MetaGroupVersion *schema.GroupVersion

	// Scheme includes all of the types used by this group and how to convert between them (or
	// to convert objects from outside of this group that are accepted in this API).
	// TODO: replace with interfaces
	Scheme *runtime.Scheme
	// NegotiatedSerializer controls how this group encodes and decodes data
	NegotiatedSerializer runtime.NegotiatedSerializer
	// ParameterCodec performs conversions for query parameters passed to API calls
	ParameterCodec runtime.ParameterCodec

	// StaticOpenAPISpec is the spec derived from the definitions of all resources installed together.
	// It is set during InstallAPIGroups, InstallAPIGroup, and InstallLegacyAPIGroup.
	StaticOpenAPISpec *spec.Swagger
}
```

apiGroupInfo.VersionedResourcesStorageMap是：API版本->API Resource->rest.Storage：

```go
	...
	v1alpha1storage := map[string]rest.Storage{}
	v1alpha1storage["flunders"] = wardleregistry.RESTInPeace(flunderstorage.NewREST(Scheme, c.GenericConfig.RESTOptionsGetter))
	v1alpha1storage["fischers"] = wardleregistry.RESTInPeace(fischerstorage.NewREST(Scheme, c.GenericConfig.RESTOptionsGetter))
	apiGroupInfo.VersionedResourcesStorageMap["v1alpha1"] = v1alpha1storage

	v1beta1storage := map[string]rest.Storage{}
	v1beta1storage["flunders"] = wardleregistry.RESTInPeace(flunderstorage.NewREST(Scheme, c.GenericConfig.RESTOptionsGetter))
	apiGroupInfo.VersionedResourcesStorageMap["v1beta1"] = v1beta1storage
	...
```

而API 的 URL 大致以 `/apis/group/version/namespaces/{namespace}/resource/{name}` 组成，结构大致如下图所示：

![img](https://github.com/duyanghao/kubernetes-reading-notes/raw/master/core/api-server/images/apis.png)

可以看到group为`wardle.example.com`，version为`v1alpha1`，resource为`flunders`和`fischers`；

以及group为`wardle.example.com`，version为`v1beta1`，resource为`flunders`

接下来就是注册API Resource了：

```go
	if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
		return nil, err
	}

// Exposes the given api group in the API.
func (s *GenericAPIServer) InstallAPIGroup(apiGroupInfo *APIGroupInfo) error {
	return s.InstallAPIGroups(apiGroupInfo)
}

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

// installAPIResources is a private method for installing the REST storage backing each api groupversionresource
func (s *GenericAPIServer) installAPIResources(apiPrefix string, apiGroupInfo *APIGroupInfo, openAPIModels openapiproto.Models) error {
	for _, groupVersion := range apiGroupInfo.PrioritizedVersions {
		if len(apiGroupInfo.VersionedResourcesStorageMap[groupVersion.Version]) == 0 {
			klog.Warningf("Skipping API %v because it has no resources.", groupVersion)
			continue
		}

		apiGroupVersion := s.getAPIGroupVersion(apiGroupInfo, groupVersion, apiPrefix)
		if apiGroupInfo.OptionsExternalVersion != nil {
			apiGroupVersion.OptionsExternalVersion = apiGroupInfo.OptionsExternalVersion
		}
		apiGroupVersion.OpenAPIModels = openAPIModels
		apiGroupVersion.MaxRequestBodyBytes = s.maxRequestBodyBytes

		if err := apiGroupVersion.InstallREST(s.Handler.GoRestfulContainer); err != nil {
			return fmt.Errorf("unable to setup API %v: %v", apiGroupInfo, err)
		}
	}

	return nil
}
```

注意这里之前会通过code-generator生成API资源类型scheme的注册代码。group为`wardle.example.com`，version为`v1alpha1`，resource为`flunders`和`fischers`)，代码如下：

```go
// k8s.io/kubernetes/staging/src/k8s.io/sample-apiserver/pkg/apis/wardle/v1alpha1/register.go
const GroupName = "wardle.example.com"

// SchemeGroupVersion is group version used to register these objects
var SchemeGroupVersion = schema.GroupVersion{Group: GroupName, Version: "v1alpha1"}

var (
	// TODO: move SchemeBuilder with zz_generated.deepcopy.go to k8s.io/api.
	// localSchemeBuilder and AddToScheme will stay in k8s.io/kubernetes.
	SchemeBuilder      runtime.SchemeBuilder
	localSchemeBuilder = &SchemeBuilder
	AddToScheme        = localSchemeBuilder.AddToScheme
)

func init() {
	// We only register manually written functions here. The registration of the
	// generated functions takes place in the generated files. The separation
	// makes the code compile even when the generated files are missing.
	localSchemeBuilder.Register(addKnownTypes, addDefaultingFuncs)
}

// Adds the list of known types to the given scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&Flunder{},
		&FlunderList{},
		&Fischer{},
		&FischerList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}

// Resource takes an unqualified resource and returns a Group qualified GroupResource
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}
```

以及group为`wardle.example.com`，version为`v1beta1`，resource为`flunders`，代码如下：

```go
// k8s.io/kubernetes/staging/src/k8s.io/sample-apiserver/pkg/apis/wardle/v1beta1/register.go
package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupName holds the API group name.
const GroupName = "wardle.example.com"

// SchemeGroupVersion is group version used to register these objects
var SchemeGroupVersion = schema.GroupVersion{Group: GroupName, Version: "v1beta1"}

var (
	// SchemeBuilder allows to add this group to a scheme.
	// TODO: move SchemeBuilder with zz_generated.deepcopy.go to k8s.io/api.
	// localSchemeBuilder and AddToScheme will stay in k8s.io/kubernetes.
	SchemeBuilder      runtime.SchemeBuilder
	localSchemeBuilder = &SchemeBuilder

	// AddToScheme adds this group to a scheme.
	AddToScheme = localSchemeBuilder.AddToScheme
)

func init() {
	// We only register manually written functions here. The registration of the
	// generated functions takes place in the generated files. The separation
	// makes the code compile even when the generated files are missing.
	localSchemeBuilder.Register(addKnownTypes)
}

// Adds the list of known types to the given scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&Flunder{},
		&FlunderList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}

// Resource takes an unqualified resource and returns a Group qualified GroupResource
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}
```

整体的目录结构如下：

```bash
staging/src/k8s.io/sample-apiserver
├── BUILD
├── CONTRIBUTING.md
├── Godeps
│   ├── OWNERS
│   └── Readme
├── LICENSE
├── OWNERS
├── README.md
├── SECURITY_CONTACTS
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
├── code-of-conduct.md
├── docs
│   └── minikube-walkthrough.md
├── go.mod
├── go.sum
├── hack
│   ├── BUILD
│   ├── boilerplate.go.txt
│   ├── build-image.sh
│   ├── custom-boilerplate.go.txt
│   ├── tools.go
│   ├── update-codegen.sh
│   └── verify-codegen.sh
├── main.go
└── pkg
    ├── admission
    │   ├── plugin
    │   │   └── banflunder
    │   │       ├── BUILD
    │   │       ├── admission.go
    │   │       └── admission_test.go
    │   └── wardleinitializer
    │       ├── BUILD
    │       ├── interfaces.go
    │       ├── wardleinitializer.go
    │       └── wardleinitializer_test.go
    ├── apis
    │   └── wardle
    │       ├── BUILD
    │       ├── doc.go
    │       ├── fuzzer
    │       │   ├── BUILD
    │       │   └── fuzzer.go
    │       ├── install
    │       │   ├── BUILD
    │       │   ├── install.go
    │       │   └── roundtrip_test.go
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

48 directories, 132 files
```

回到installAPIResources函数：

```go
const (
	// DefaultLegacyAPIPrefix is where the legacy APIs will be located.
	DefaultLegacyAPIPrefix = "/api"

	// APIGroupPrefix is where non-legacy API group will be located.
	APIGroupPrefix = "/apis"
)

// k8s.io/kubernetes/staging/src/k8s.io/apiserver/pkg/server/genericapiserver.go:405
// installAPIResources is a private method for installing the REST storage backing each api groupversionresource
func (s *GenericAPIServer) installAPIResources(apiPrefix string, apiGroupInfo *APIGroupInfo, openAPIModels openapiproto.Models) error {
	for _, groupVersion := range apiGroupInfo.PrioritizedVersions {
		if len(apiGroupInfo.VersionedResourcesStorageMap[groupVersion.Version]) == 0 {
			klog.Warningf("Skipping API %v because it has no resources.", groupVersion)
			continue
		}

		apiGroupVersion := s.getAPIGroupVersion(apiGroupInfo, groupVersion, apiPrefix)
		if apiGroupInfo.OptionsExternalVersion != nil {
			apiGroupVersion.OptionsExternalVersion = apiGroupInfo.OptionsExternalVersion
		}
		apiGroupVersion.OpenAPIModels = openAPIModels
		apiGroupVersion.MaxRequestBodyBytes = s.maxRequestBodyBytes

		if err := apiGroupVersion.InstallREST(s.Handler.GoRestfulContainer); err != nil {
			return fmt.Errorf("unable to setup API %v: %v", apiGroupInfo, err)
		}
	}

	return nil
}

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
```

这里面其实就是给上述两类API Resource注册路由以及对应的处理函数，对应的处理函数也即回过头来看completedConfig.New：

```go
// New returns a new instance of WardleServer from the given config.
func (c completedConfig) New() (*WardleServer, error) {
	...
  
	v1alpha1storage := map[string]rest.Storage{}
	v1alpha1storage["flunders"] = wardleregistry.RESTInPeace(flunderstorage.NewREST(Scheme, c.GenericConfig.RESTOptionsGetter))
	v1alpha1storage["fischers"] = wardleregistry.RESTInPeace(fischerstorage.NewREST(Scheme, c.GenericConfig.RESTOptionsGetter))
	apiGroupInfo.VersionedResourcesStorageMap["v1alpha1"] = v1alpha1storage

	v1beta1storage := map[string]rest.Storage{}
	v1beta1storage["flunders"] = wardleregistry.RESTInPeace(flunderstorage.NewREST(Scheme, c.GenericConfig.RESTOptionsGetter))
	apiGroupInfo.VersionedResourcesStorageMap["v1beta1"] = v1beta1storage

	if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
		return nil, err
	}

	return s, nil
}
```

这里分析其中一个资源对应的rest.Storage，如下：

```go
v1alpha1storage["flunders"] = wardleregistry.RESTInPeace(flunderstorage.NewREST(Scheme, c.GenericConfig.RESTOptionsGetter))

// k8s.io/kubernetes/staging/src/k8s.io/sample-apiserver/pkg/registry/wardle/flunder/etcd.go:27
// NewREST returns a RESTStorage object that will work against API services.
func NewREST(scheme *runtime.Scheme, optsGetter generic.RESTOptionsGetter) (*registry.REST, error) {
	strategy := NewStrategy(scheme)

	store := &genericregistry.Store{
		NewFunc:                  func() runtime.Object { return &wardle.Flunder{} },
		NewListFunc:              func() runtime.Object { return &wardle.FlunderList{} },
		PredicateFunc:            MatchFlunder,
		DefaultQualifiedResource: wardle.Resource("flunders"),

		CreateStrategy: strategy,
		UpdateStrategy: strategy,
		DeleteStrategy: strategy,
	}
	options := &generic.StoreOptions{RESTOptions: optsGetter, AttrFunc: GetAttrs}
	if err := store.CompleteWithOptions(options); err != nil {
		return nil, err
	}
	return &registry.REST{store}, nil
}

// MatchFischer is the filter used by the generic etcd backend to watch events
// from etcd to clients of the apiserver only interested in specific labels/fields.
func MatchFischer(label labels.Selector, field fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    field,
		GetAttrs: GetAttrs,
	}
}
```

这里，其实没有做任何对API Resource特殊的CRUD处理，除了Watch接口添加标签限制外(MatchFischer)

这些逻辑主要在k8s.io/kubernetes/staging/src/k8s.io/sample-apiserver/pkg/registry目录：

```bash
staging/src/k8s.io/sample-apiserver
├── main.go
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
└── pkg
    ├── admission
    │   ├── plugin
    │   │   └── banflunder
    │   │       ├── BUILD
    │   │       ├── admission.go
    │   │       └── admission_test.go
    │   └── wardleinitializer
    │       ├── BUILD
    │       ├── interfaces.go
    │       ├── wardleinitializer.go
    │       └── wardleinitializer_test.go
    ├── apis
    │   └── wardle
    │       ├── v1alpha1
    │       │   ├── doc.go
    │       │   ├── register.go
    │       ├── v1beta1
    │       │   ├── doc.go
    │       │   ├── register.go
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
    │   ├── informers
    │   ├── listers
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

## kube-apiserver与sample-apiserver的对接

![Extension apiservers](https://github.com/kubernetes-sigs/apiserver-builder-alpha/raw/master/docs/concepts/extensionserver.jpg)

回到这张图片，可以看到CR请求流程如下：

- 1、对于CR的API请求，先发送给Kubernetes core APIServer，代理给AA
- 2、AA接受请求，然后操作etcd，这个etcd可以与Kubernetes etcd共用，也可以单独部署一套
- 3、Custom Controller Watch core APIServer CR资源变化(注意这个时候Watch会代理给AA)
- 4、如果CR发生变化，Custom Controller接受到变化对象和相应事件，并对该CR进行相关操作，可以是CR本身，也可以是CR所关联的Kubernetes原生资源类型，例如Pod、Deployment等
- 5、如果是CR本身的CRUD操作，则走core APIServer，然后代理给AA；否则直接走core APIServer

下面我将从代码层面分析这个流程，**这里分析的核心是core kube-apiserver与extension apiserver是如何交互的？**

首先看一下sample-apiserver的部署yamls，如下：

```yaml
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

// apiservice.yaml
apiVersion: apiregistration.k8s.io/v1
kind: APIService
metadata:
  name: v1alpha1.wardle.example.com
spec:
  insecureSkipTLSVerify: true
  group: wardle.example.com
  groupPriorityMinimum: 1000
  versionPriority: 15
  service:
    name: api
    namespace: wardle
  version: v1alpha1
  
// service.yaml
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: wardle
spec:
  ports:
  - port: 443
    protocol: TCP
    targetPort: 443
  selector:
    apiserver: "true"
    
// deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wardle-server
  namespace: wardle
  labels:
    apiserver: "true"
spec:
  replicas: 1
  selector:
    matchLabels:
      apiserver: "true"
  template:
    metadata:
      labels:
        apiserver: "true"
    spec:
      serviceAccountName: apiserver
      containers:
      - name: wardle-server
        # build from staging/src/k8s.io/sample-apiserver/artifacts/simple-image/Dockerfile
        # or
        # docker pull gcr.io/kubernetes-e2e-test-images/sample-apiserver:1.17
        # docker tag gcr.io/kubernetes-e2e-test-images/sample-apiserver:1.17 kube-sample-apiserver:latest
        image: kube-sample-apiserver:latest
        imagePullPolicy: Never
        args: [ "--etcd-servers=http://localhost:2379" ]
      - name: etcd
        image: quay.io/coreos/etcd:v3.4.3

// Dockerfile
FROM fedora
ADD kube-sample-apiserver /
ENTRYPOINT ["/kube-sample-apiserver"]        
```

可以看到注册了sample apiserver的APIService资源，使用的service是wardle namespace下的api(service名称)，对应的deployment为wardle-server，使用的镜像就是sample-apiserver以及etcd。如果要创建flunder CR，使用yaml如下：

```yaml
apiVersion: wardle.example.com/v1alpha1
kind: Flunder
metadata:
  name: my-first-flunder
  labels:
    sample-label: "true"
```

这些yamls中最关键的就是apiservice.yaml，它将core kube-apiserver与extension apiserver联系在一起。这里面就会涉及kube-apiserver中AggregatorServer的controller逻辑了：

> 其中，Aggregator 通过 APIServices 对象关联到某个 Service 来进行请求的转发，其关联的 Service 类型进一步决定了请求转发形式。Aggregator 包括一个 `GenericAPIServer` 和维护自身状态的 Controller。其中 `GenericAPIServer` 主要处理 `apiregistration.k8s.io` 组下的 APIService 资源请求，controller包括：

- `apiserviceRegistrationController`：负责 APIServices 中资源的注册与删除；
- `availableConditionController`：维护 APIServices 的可用状态，包括其引用 Service 是否可用等；
- `autoRegistrationController`：用于保持 API 中存在的一组特定的 APIServices；
- `crdRegistrationController`：负责将 CRD GroupVersions 自动注册到 APIServices 中；
- `openAPIAggregationController`：将 APIServices 资源的变化同步至提供的 OpenAPI 文档；

对应要研究的是`apiserviceRegistrationController`：

```go
// k8s.io/kubernetes/cmd/kube-apiserver/app/aggregator.go:129
func createAggregatorServer(aggregatorConfig *aggregatorapiserver.Config, delegateAPIServer genericapiserver.DelegationTarget, apiExtensionInformers apiextensionsinformers.SharedInformerFactory) (*aggregatorapiserver.APIAggregator, error) {
	aggregatorServer, err := aggregatorConfig.Complete().NewWithDelegate(delegateAPIServer)
	if err != nil {
		return nil, err
	}

	// create controllers for auto-registration
	apiRegistrationClient, err := apiregistrationclient.NewForConfig(aggregatorConfig.GenericConfig.LoopbackClientConfig)
	if err != nil {
		return nil, err
	}
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
	if err != nil {
		return nil, err
	}

	err = aggregatorServer.GenericAPIServer.AddBootSequenceHealthChecks(
		makeAPIServiceAvailableHealthCheck(
			"autoregister-completion",
			apiServices,
			aggregatorServer.APIRegistrationInformers.Apiregistration().V1().APIServices(),
		),
	)
	if err != nil {
		return nil, err
	}

	return aggregatorServer, nil
}

k8s.io/kubernetes/staging/src/k8s.io/kube-aggregator/pkg/apiserver/apiserver.go:159
// NewWithDelegate returns a new instance of APIAggregator from the given config.
func (c completedConfig) NewWithDelegate(delegationTarget genericapiserver.DelegationTarget) (*APIAggregator, error) {
	...
	apisHandler := &apisHandler{
		codecs:         aggregatorscheme.Codecs,
		lister:         s.lister,
		discoveryGroup: discoveryGroup(enabledVersions),
	}
	s.GenericAPIServer.Handler.NonGoRestfulMux.Handle("/apis", apisHandler)
	s.GenericAPIServer.Handler.NonGoRestfulMux.UnlistedHandle("/apis/", apisHandler)

	apiserviceRegistrationController := NewAPIServiceRegistrationController(informerFactory.Apiregistration().V1().APIServices(), s)
	availableController, err := statuscontrollers.NewAvailableConditionController(
		informerFactory.Apiregistration().V1().APIServices(),
		c.GenericConfig.SharedInformerFactory.Core().V1().Services(),
		c.GenericConfig.SharedInformerFactory.Core().V1().Endpoints(),
		apiregistrationClient.ApiregistrationV1(),
		c.ExtraConfig.ProxyTransport,
		c.ExtraConfig.ProxyClientCert,
		c.ExtraConfig.ProxyClientKey,
		s.serviceResolver,
		c.GenericConfig.EgressSelector,
	)
	if err != nil {
		return nil, err
	}

	s.GenericAPIServer.AddPostStartHookOrDie("start-kube-aggregator-informers", func(context genericapiserver.PostStartHookContext) error {
		informerFactory.Start(context.StopCh)
		c.GenericConfig.SharedInformerFactory.Start(context.StopCh)
		return nil
	})
	s.GenericAPIServer.AddPostStartHookOrDie("apiservice-registration-controller", func(context genericapiserver.PostStartHookContext) error {
		go apiserviceRegistrationController.Run(context.StopCh)
		return nil
	})
	s.GenericAPIServer.AddPostStartHookOrDie("apiservice-status-available-controller", func(context genericapiserver.PostStartHookContext) error {
		// if we end up blocking for long periods of time, we may need to increase threadiness.
		go availableController.Run(5, context.StopCh)
		return nil
	})

	return s, nil
}
```

重点看`apiserviceRegistrationController := NewAPIServiceRegistrationController(informerFactory.Apiregistration().V1().APIServices(), s)`，如下：

```go
// k8s.io/kubernetes/vendor/k8s.io/kube-aggregator/pkg/apiserver/apiservice_controller.go:56
// NewAPIServiceRegistrationController returns a new APIServiceRegistrationController.
func NewAPIServiceRegistrationController(apiServiceInformer informers.APIServiceInformer, apiHandlerManager APIHandlerManager) *APIServiceRegistrationController {
	c := &APIServiceRegistrationController{
		apiHandlerManager: apiHandlerManager,
		apiServiceLister:  apiServiceInformer.Lister(),
		apiServiceSynced:  apiServiceInformer.Informer().HasSynced,
		queue:             workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "APIServiceRegistrationController"),
	}

	apiServiceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addAPIService,
		UpdateFunc: c.updateAPIService,
		DeleteFunc: c.deleteAPIService,
	})

	c.syncFn = c.sync

	return c
}

func (c *APIServiceRegistrationController) addAPIService(obj interface{}) {
	castObj := obj.(*v1.APIService)
	klog.V(4).Infof("Adding %s", castObj.Name)
	c.enqueue(castObj)
}

func (c *APIServiceRegistrationController) updateAPIService(obj, _ interface{}) {
	castObj := obj.(*v1.APIService)
	klog.V(4).Infof("Updating %s", castObj.Name)
	c.enqueue(castObj)
}

func (c *APIServiceRegistrationController) deleteAPIService(obj interface{}) {
	castObj, ok := obj.(*v1.APIService)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Couldn't get object from tombstone %#v", obj)
			return
		}
		castObj, ok = tombstone.Obj.(*v1.APIService)
		if !ok {
			klog.Errorf("Tombstone contained object that is not expected %#v", obj)
			return
		}
	}
	klog.V(4).Infof("Deleting %q", castObj.Name)
	c.enqueue(castObj)
}

func (c *APIServiceRegistrationController) enqueue(obj *v1.APIService) {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Errorf("Couldn't get key for object %#v: %v", obj, err)
		return
	}

	c.queue.Add(key)
}
```

通过Run在启动AggregatorServer之后执行APIServiceRegistrationController：

```go
...
	s.GenericAPIServer.AddPostStartHookOrDie("apiservice-registration-controller", func(context genericapiserver.PostStartHookContext) error {
		go apiserviceRegistrationController.Run(context.StopCh)
		return nil
	})
...

// Run starts APIServiceRegistrationController which will process all registration requests until stopCh is closed.
func (c *APIServiceRegistrationController) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting APIServiceRegistrationController")
	defer klog.Infof("Shutting down APIServiceRegistrationController")

	if !controllers.WaitForCacheSync("APIServiceRegistrationController", stopCh, c.apiServiceSynced) {
		return
	}

	// only start one worker thread since its a slow moving API and the aggregation server adding bits
	// aren't threadsafe
	go wait.Until(c.runWorker, time.Second, stopCh)

	<-stopCh
}

func (c *APIServiceRegistrationController) runWorker() {
	for c.processNextWorkItem() {
	}
}

// processNextWorkItem deals with one key off the queue.  It returns false when it's time to quit.
func (c *APIServiceRegistrationController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.syncFn(key.(string))
	if err == nil {
		c.queue.Forget(key)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with : %v", key, err))
	c.queue.AddRateLimited(key)

	return true
}
```

可以看到典型的Kubernetes controller代码结构，这里不展开分析controller数据结构细节(在kube-controller部分会深入研究)，只分析controller逻辑，其中最主要的处理函数是sync：

```go
func (c *APIServiceRegistrationController) sync(key string) error {
	apiService, err := c.apiServiceLister.Get(key)
	if apierrors.IsNotFound(err) {
		c.apiHandlerManager.RemoveAPIService(key)
		return nil
	}
	if err != nil {
		return err
	}

	return c.apiHandlerManager.AddAPIService(apiService)
}
```

首先获取apiService对象，然后执行AddAPIService操作：

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

// RemoveAPIService removes the APIService from being handled.  It is not thread-safe, so only call it on one thread at a time please.
// It's a slow moving API, so it's ok to run the controller on a single thread.
func (s *APIAggregator) RemoveAPIService(apiServiceName string) {
	version := v1helper.APIServiceNameToGroupVersion(apiServiceName)

	proxyPath := "/apis/" + version.Group + "/" + version.Version
	// v1. is a special case for the legacy API.  It proxies to a wider set of endpoints.
	if apiServiceName == legacyAPIServiceName {
		proxyPath = "/api"
	}
	s.GenericAPIServer.Handler.NonGoRestfulMux.Unregister(proxyPath)
	s.GenericAPIServer.Handler.NonGoRestfulMux.Unregister(proxyPath + "/")
	if s.openAPIAggregationController != nil {
		s.openAPIAggregationController.RemoveAPIService(apiServiceName)
	}
	delete(s.proxyHandlers, apiServiceName)

	// TODO unregister group level discovery when there are no more versions for the group
	// We don't need this right away because the handler properly delegates when no versions are present
}
```

结合yamls文件分析代码：

```yaml
// apiservice.yaml
apiVersion: apiregistration.k8s.io/v1
kind: APIService
metadata:
  name: v1alpha1.wardle.example.com
spec:
  insecureSkipTLSVerify: true
  group: wardle.example.com
  groupPriorityMinimum: 1000
  versionPriority: 15
  service:
    name: api
    namespace: wardle
  version: v1alpha1
```

构建proxyPath("/apis/" + apiService.Spec.Group + "/" + apiService.Spec.Version)以及proxyHandler：

```go
// proxyHandler provides a http.Handler which will proxy traffic to locations
// specified by items implementing Redirector.
type proxyHandler struct {
	// localDelegate is used to satisfy local APIServices
	localDelegate http.Handler

	// proxyClientCert/Key are the client cert used to identify this proxy. Backing APIServices use
	// this to confirm the proxy's identity
	proxyClientCert []byte
	proxyClientKey  []byte
	proxyTransport  *http.Transport

	// Endpoints based routing to map from cluster IP to routable IP
	serviceResolver ServiceResolver

	handlingInfo atomic.Value

	// egressSelector selects the proper egress dialer to communicate with the custom apiserver
	// overwrites proxyTransport dialer if not nil
	egressSelector *egressselector.EgressSelector
}

type proxyHandlingInfo struct {
	// local indicates that this APIService is locally satisfied
	local bool

	// name is the name of the APIService
	name string
	// restConfig holds the information for building a roundtripper
	restConfig *restclient.Config
	// transportBuildingError is an error produced while building the transport.  If this
	// is non-nil, it will be reported to clients.
	transportBuildingError error
	// proxyRoundTripper is the re-useable portion of the transport.  It does not vary with any request.
	proxyRoundTripper http.RoundTripper
	// serviceName is the name of the service this handler proxies to
	serviceName string
	// namespace is the namespace the service lives in
	serviceNamespace string
	// serviceAvailable indicates this APIService is available or not
	serviceAvailable bool
	// servicePort is the port of the service this handler proxies to
	servicePort int32
}

// k8s.io/kubernetes/staging/src/k8s.io/kube-aggregator/pkg/apiserver/handler_proxy.go:245
func (r *proxyHandler) updateAPIService(apiService *apiregistrationv1api.APIService) {
	if apiService.Spec.Service == nil {
		r.handlingInfo.Store(proxyHandlingInfo{local: true})
		return
	}

	// 根据apiService定义构建proxyHandlingInfo结构体，主要是service部分
	newInfo := proxyHandlingInfo{
		name: apiService.Name,
		restConfig: &restclient.Config{
			TLSClientConfig: restclient.TLSClientConfig{
				Insecure:   apiService.Spec.InsecureSkipTLSVerify,
				ServerName: apiService.Spec.Service.Name + "." + apiService.Spec.Service.Namespace + ".svc",
				CertData:   r.proxyClientCert,
				KeyData:    r.proxyClientKey,
				CAData:     apiService.Spec.CABundle,
			},
		},
		serviceName:      apiService.Spec.Service.Name,
		serviceNamespace: apiService.Spec.Service.Namespace,
		servicePort:      *apiService.Spec.Service.Port,
		serviceAvailable: apiregistrationv1apihelper.IsAPIServiceConditionTrue(apiService, apiregistrationv1api.Available),
	}
	if r.egressSelector != nil {
		networkContext := egressselector.Cluster.AsNetworkContext()
		var egressDialer utilnet.DialFunc
		egressDialer, err := r.egressSelector.Lookup(networkContext)
		if err != nil {
			klog.Warning(err.Error())
		} else {
			newInfo.restConfig.Dial = egressDialer
		}
	} else if r.proxyTransport != nil && r.proxyTransport.DialContext != nil {
		newInfo.restConfig.Dial = r.proxyTransport.DialContext
	}
	// 构建proxyRoundTripper
	newInfo.proxyRoundTripper, newInfo.transportBuildingError = restclient.TransportFor(newInfo.restConfig)
	if newInfo.transportBuildingError != nil {
		klog.Warning(newInfo.transportBuildingError.Error())
	}
	// 将roxyHandlingInfo存放于handlingInfo
	r.handlingInfo.Store(newInfo)
}
```

这里通过APIService的定义构建了proxyHandler，通过查看proxyHandlingInfo结构体基本就能确定proxyHander作用：将请求代理给制定APIService定义的API service服务，如下是proxyHander具体的请求处理逻辑：

```go
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

APIService共有两种类型，这里我们看一下serviceResolver：

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

	...
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
	...

	return aggregatorServer, nil
}

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
	...
	admissionConfig := &kubeapiserveradmission.Config{
		ExternalInformers:    versionedInformers,
		LoopbackClientConfig: genericConfig.LoopbackClientConfig,
		CloudConfigFile:      s.CloudProvider.CloudConfigFile,
	}
	serviceResolver = buildServiceResolver(s.EnableAggregatorRouting, genericConfig.LoopbackClientConfig.Host, versionedInformers)
	...

	return
}

// k8s.io/kubernetes/cmd/kube-apiserver/app/server.go:728
func buildServiceResolver(enabledAggregatorRouting bool, hostname string, informer clientgoinformers.SharedInformerFactory) webhook.ServiceResolver {
	var serviceResolver webhook.ServiceResolver
	if enabledAggregatorRouting {
		serviceResolver = aggregatorapiserver.NewEndpointServiceResolver(
			informer.Core().V1().Services().Lister(),
			informer.Core().V1().Endpoints().Lister(),
		)
	} else {
		serviceResolver = aggregatorapiserver.NewClusterIPServiceResolver(
			informer.Core().V1().Services().Lister(),
		)
	}
	// resolve kubernetes.default.svc locally
	if localHost, err := url.Parse(hostname); err == nil {
		serviceResolver = aggregatorapiserver.NewLoopbackServiceResolver(serviceResolver, localHost)
	}
	return serviceResolver
}

	fs.BoolVar(&s.EnableAggregatorRouting, "enable-aggregator-routing", s.EnableAggregatorRouting,
		"Turns on aggregator routing requests to endpoints IP rather than cluster IP.")
```

默认使用aggregatorClusterRouting，如下：

```go
// NewClusterIPServiceResolver returns a ServiceResolver that directly calls the
// service's cluster IP.
func NewClusterIPServiceResolver(services listersv1.ServiceLister) ServiceResolver {
	return &aggregatorClusterRouting{
		services: services,
	}
}

type aggregatorClusterRouting struct {
	services listersv1.ServiceLister
}

func (r *aggregatorClusterRouting) ResolveEndpoint(namespace, name string, port int32) (*url.URL, error) {
	return proxy.ResolveCluster(r.services, namespace, name, port)
}

func ResolveCluster(services listersv1.ServiceLister, namespace, id string, port int32) (*url.URL, error) {
	svc, err := services.Services(namespace).Get(id)
	if err != nil {
		return nil, err
	}

	switch {
	case svc.Spec.Type == v1.ServiceTypeClusterIP && svc.Spec.ClusterIP == v1.ClusterIPNone:
		return nil, fmt.Errorf(`cannot route to service with ClusterIP "None"`)
	// use IP from a clusterIP for these service types
	case svc.Spec.Type == v1.ServiceTypeClusterIP, svc.Spec.Type == v1.ServiceTypeLoadBalancer, svc.Spec.Type == v1.ServiceTypeNodePort:
		svcPort, err := findServicePort(svc, port)
		if err != nil {
			return nil, err
		}
		return &url.URL{
			Scheme: "https",
			Host:   net.JoinHostPort(svc.Spec.ClusterIP, fmt.Sprintf("%d", svcPort.Port)),
		}, nil
	case svc.Spec.Type == v1.ServiceTypeExternalName:
		return &url.URL{
			Scheme: "https",
			Host:   net.JoinHostPort(svc.Spec.ExternalName, fmt.Sprintf("%d", port)),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported service type %q", svc.Spec.Type)
	}
}

// findServicePort finds the service port by name or numerically.
func findServicePort(svc *v1.Service, port int32) (*v1.ServicePort, error) {
	for _, svcPort := range svc.Spec.Ports {
		if svcPort.Port == port {
			return &svcPort, nil
		}
	}
	return nil, errors.NewServiceUnavailable(fmt.Sprintf("no service port %d found for service %q", port, svc.Name))
}
```

可以看到对于ClusterIP，LoadBalancer以及NodePort类型service都是将Host转化为ClusterIP:Port地址；而对于ExternalName Service则转化为ExternalName:Port地址。而对于aggregatorEndpointRouting，处理如下：

```go
// NewEndpointServiceResolver returns a ServiceResolver that chooses one of the
// service's endpoints.
func NewEndpointServiceResolver(services listersv1.ServiceLister, endpoints listersv1.EndpointsLister) ServiceResolver {
	return &aggregatorEndpointRouting{
		services:  services,
		endpoints: endpoints,
	}
}

type aggregatorEndpointRouting struct {
	services  listersv1.ServiceLister
	endpoints listersv1.EndpointsLister
}

func (r *aggregatorEndpointRouting) ResolveEndpoint(namespace, name string, port int32) (*url.URL, error) {
	return proxy.ResolveEndpoint(r.services, r.endpoints, namespace, name, port)
}

// ResourceLocation returns a URL to which one can send traffic for the specified service.
func ResolveEndpoint(services listersv1.ServiceLister, endpoints listersv1.EndpointsLister, namespace, id string, port int32) (*url.URL, error) {
	svc, err := services.Services(namespace).Get(id)
	if err != nil {
		return nil, err
	}

	svcPort, err := findServicePort(svc, port)
	if err != nil {
		return nil, err
	}

	switch {
	case svc.Spec.Type == v1.ServiceTypeClusterIP, svc.Spec.Type == v1.ServiceTypeLoadBalancer, svc.Spec.Type == v1.ServiceTypeNodePort:
		// these are fine
	default:
		return nil, fmt.Errorf("unsupported service type %q", svc.Spec.Type)
	}

	eps, err := endpoints.Endpoints(namespace).Get(svc.Name)
	if err != nil {
		return nil, err
	}
	if len(eps.Subsets) == 0 {
		return nil, errors.NewServiceUnavailable(fmt.Sprintf("no endpoints available for service %q", svc.Name))
	}

	// Pick a random Subset to start searching from.
	ssSeed := rand.Intn(len(eps.Subsets))

	// Find a Subset that has the port.
	for ssi := 0; ssi < len(eps.Subsets); ssi++ {
		ss := &eps.Subsets[(ssSeed+ssi)%len(eps.Subsets)]
		if len(ss.Addresses) == 0 {
			continue
		}
		for i := range ss.Ports {
			if ss.Ports[i].Name == svcPort.Name {
				// Pick a random address.
				ip := ss.Addresses[rand.Intn(len(ss.Addresses))].IP
				port := int(ss.Ports[i].Port)
				return &url.URL{
					Scheme: "https",
					Host:   net.JoinHostPort(ip, strconv.Itoa(port)),
				}, nil
			}
		}
	}
	return nil, errors.NewServiceUnavailable(fmt.Sprintf("no endpoints available for service %q", id))
}
```

可以看到aggregatorEndpointRouting是自己随机从service对应的endpoint中选择出一个backend，然后构建Host；而aggregatorClusterRouting则是直接由clusterIP进行负载均衡

回到buildServiceResolver，我们分析最后local类型的ServiceResolver，如下：

```go
func buildServiceResolver(enabledAggregatorRouting bool, hostname string, informer clientgoinformers.SharedInformerFactory) webhook.ServiceResolver {
	var serviceResolver webhook.ServiceResolver
	if enabledAggregatorRouting {
		serviceResolver = aggregatorapiserver.NewEndpointServiceResolver(
			informer.Core().V1().Services().Lister(),
			informer.Core().V1().Endpoints().Lister(),
		)
	} else {
		serviceResolver = aggregatorapiserver.NewClusterIPServiceResolver(
			informer.Core().V1().Services().Lister(),
		)
	}
	// resolve kubernetes.default.svc locally
	if localHost, err := url.Parse(hostname); err == nil {
		serviceResolver = aggregatorapiserver.NewLoopbackServiceResolver(serviceResolver, localHost)
	}
	return serviceResolver
}

// NewLoopbackServiceResolver returns a ServiceResolver that routes
// the kubernetes/default service with port 443 to loopback.
func NewLoopbackServiceResolver(delegate ServiceResolver, host *url.URL) ServiceResolver {
	return &loopbackResolver{
		delegate: delegate,
		host:     host,
	}
}

type loopbackResolver struct {
	delegate ServiceResolver
	host     *url.URL
}

func (r *loopbackResolver) ResolveEndpoint(namespace, name string, port int32) (*url.URL, error) {
	if namespace == "default" && name == "kubernetes" && port == 443 {
		return r.host, nil
	}
	return r.delegate.ResolveEndpoint(namespace, name, port)
}
```

对于kubernetes/default service with port 443会直接转发给loopback；其它service则交给aggregatorEndpointRouting或者aggregatorClusterRouting处理

上面总结的是apiservice.Spec.Service字段非空的情形；下面我们分析apiservice.Spec.Service字段为空(也即Local SERVICE)类型的场景：

```go
// k8s.io/kubernetes/staging/src/k8s.io/kube-aggregator/pkg/apiserver/handler_proxy.go:245
func (r *proxyHandler) updateAPIService(apiService *apiregistrationv1api.APIService) {
	if apiService.Spec.Service == nil {
		r.handlingInfo.Store(proxyHandlingInfo{local: true})
		return
	}

	// 根据apiService定义构建proxyHandlingInfo结构体，主要是service部分
	newInfo := proxyHandlingInfo{
		name: apiService.Name,
		restConfig: &restclient.Config{
			TLSClientConfig: restclient.TLSClientConfig{
				Insecure:   apiService.Spec.InsecureSkipTLSVerify,
				ServerName: apiService.Spec.Service.Name + "." + apiService.Spec.Service.Namespace + ".svc",
				CertData:   r.proxyClientCert,
				KeyData:    r.proxyClientKey,
				CAData:     apiService.Spec.CABundle,
			},
		},
		serviceName:      apiService.Spec.Service.Name,
		serviceNamespace: apiService.Spec.Service.Namespace,
		servicePort:      *apiService.Spec.Service.Port,
		serviceAvailable: apiregistrationv1apihelper.IsAPIServiceConditionTrue(apiService, apiregistrationv1api.Available),
	}
	if r.egressSelector != nil {
		networkContext := egressselector.Cluster.AsNetworkContext()
		var egressDialer utilnet.DialFunc
		egressDialer, err := r.egressSelector.Lookup(networkContext)
		if err != nil {
			klog.Warning(err.Error())
		} else {
			newInfo.restConfig.Dial = egressDialer
		}
	} else if r.proxyTransport != nil && r.proxyTransport.DialContext != nil {
		newInfo.restConfig.Dial = r.proxyTransport.DialContext
	}
	// 构建proxyRoundTripper
	newInfo.proxyRoundTripper, newInfo.transportBuildingError = restclient.TransportFor(newInfo.restConfig)
	if newInfo.transportBuildingError != nil {
		klog.Warning(newInfo.transportBuildingError.Error())
	}
	// 将proxyHandlingInfo存放于handlingInfo
	r.handlingInfo.Store(newInfo)
}
```

可以看到如果apiService.Spec.Service为空，则会执行r.handlingInfo.Store(proxyHandlingInfo{local: true})操作，进行执行localDelegate.ServeHTTP：

```go
func (r *proxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
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
	...
}

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

	...
	return nil
}
```

这里我们追本溯源localDelegate.ServeHTTP，如下：

```go
// NewWithDelegate returns a new instance of APIAggregator from the given config.
func (c completedConfig) NewWithDelegate(delegationTarget genericapiserver.DelegationTarget) (*APIAggregator, error) {
	// Prevent generic API server to install OpenAPI handler. Aggregator server
	// has its own customized OpenAPI handler.
	...

	s := &APIAggregator{
		GenericAPIServer:         genericServer,
		delegateHandler:          delegationTarget.UnprotectedHandler(),
		proxyClientCert:          c.ExtraConfig.ProxyClientCert,
		proxyClientKey:           c.ExtraConfig.ProxyClientKey,
		proxyTransport:           c.ExtraConfig.ProxyTransport,
		proxyHandlers:            map[string]*proxyHandler{},
		handledGroups:            sets.String{},
		lister:                   informerFactory.Apiregistration().V1().APIServices().Lister(),
		APIRegistrationInformers: informerFactory,
		serviceResolver:          c.ExtraConfig.ServiceResolver,
		openAPIConfig:            openAPIConfig,
		egressSelector:           c.GenericConfig.EgressSelector,
	}
	...

	return s, nil
}

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
	...

	return aggregatorServer, nil
}

// k8s.io/kubernetes/staging/src/k8s.io/apiserver/pkg/server/genericapiserver.go:227
func (s *GenericAPIServer) UnprotectedHandler() http.Handler {
	// when we delegate, we need the server we're delegating to choose whether or not to use gorestful
	return s.Handler.Director
}

// k8s.io/kubernetes/staging/src/k8s.io/apiserver/pkg/server/handler.go:122
func (d director) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	path := req.URL.Path

	// check to see if our webservices want to claim this path
	for _, ws := range d.goRestfulContainer.RegisteredWebServices() {
		switch {
		case ws.RootPath() == "/apis":
			// if we are exactly /apis or /apis/, then we need special handling in loop.
			// normally these are passed to the nonGoRestfulMux, but if discovery is enabled, it will go directly.
			// We can't rely on a prefix match since /apis matches everything (see the big comment on Director above)
			if path == "/apis" || path == "/apis/" {
				klog.V(5).Infof("%v: %v %q satisfied by gorestful with webservice %v", d.name, req.Method, path, ws.RootPath())
				// don't use servemux here because gorestful servemuxes get messed up when removing webservices
				// TODO fix gorestful, remove TPRs, or stop using gorestful
				d.goRestfulContainer.Dispatch(w, req)
				return
			}

		case strings.HasPrefix(path, ws.RootPath()):
			// ensure an exact match or a path boundary match
			if len(path) == len(ws.RootPath()) || path[len(ws.RootPath())] == '/' {
				klog.V(5).Infof("%v: %v %q satisfied by gorestful with webservice %v", d.name, req.Method, path, ws.RootPath())
				// don't use servemux here because gorestful servemuxes get messed up when removing webservices
				// TODO fix gorestful, remove TPRs, or stop using gorestful
				d.goRestfulContainer.Dispatch(w, req)
				return
			}
		}
	}

	// if we didn't find a match, then we just skip gorestful altogether
	klog.V(5).Infof("%v: %v %q satisfied by nonGoRestful", d.name, req.Method, path)
	d.nonGoRestfulMux.ServeHTTP(w, req)
}
```

这里相当于回到kube-apiserver自身AggregatorServer的处理了，这里我们可以看看具体例子：

```bash
$ kubectl get APIService
NAME                                   SERVICE                      AVAILABLE   AGE
v1.                                    Local                        True        50d
v1.admissionregistration.k8s.io        Local                        True        50d
v1.apiextensions.k8s.io                Local                        True        50d
v1.apps                                Local                        True        50d
v1.auth.tkestack.io                    tke/tke-auth-api             True        50d
v1.authentication.k8s.io               Local                        True        50d
v1.authorization.k8s.io                Local                        True        50d
v1.autoscaling                         Local                        True        50d
v1.batch                               Local                        True        50d
v1.configuration.konghq.com            Local                        True        39d
v1.coordination.k8s.io                 Local                        True        50d
v1.monitor.tkestack.io                 tke/tke-monitor-api          True        50d
v1.monitoring.coreos.com               Local                        True        39d
v1.networking.k8s.io                   Local                        True        50d
v1.notify.tkestack.io                  tke/tke-notify-api           True        50d
v1.platform.tkestack.io                tke/tke-platform-api         True        50d
v1.rbac.authorization.k8s.io           Local                        True        50d
v1.scheduling.k8s.io                   Local                        True        50d
v1.storage.k8s.io                      Local                        True        50d
v1beta1.admissionregistration.k8s.io   Local                        True        50d
v1beta1.apiextensions.k8s.io           Local                        True        50d
v1beta1.authentication.k8s.io          Local                        True        50d
v1beta1.authorization.k8s.io           Local                        True        50d
v1beta1.batch                          Local                        True        50d
v1beta1.certificates.k8s.io            Local                        True        50d
v1beta1.coordination.k8s.io            Local                        True        50d
v1beta1.discovery.k8s.io               Local                        True        50d
v1beta1.events.k8s.io                  Local                        True        50d
v1beta1.extensions                     Local                        True        50d
v1beta1.metrics.k8s.io                 kube-system/metrics-server   True        50d
v1beta1.networking.k8s.io              Local                        True        50d
v1beta1.node.k8s.io                    Local                        True        50d
v1beta1.policy                         Local                        True        50d
v1beta1.rbac.authorization.k8s.io      Local                        True        50d
v1beta1.scheduling.k8s.io              Local                        True        50d
v1beta1.storage.k8s.io                 Local                        True        50d
v2beta1.autoscaling                    Local                        True        50d
v2beta2.autoscaling                    Local                        True        50d
```

Local SERVICE(apiService.Spec.Service=null)：

```yaml
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
```

other SERVICE(apiService.Spec.Service!=null)：

```yaml
$ kubectl get -o yaml APIService/v1.platform.tkestack.io
apiVersion: apiregistration.k8s.io/v1
kind: APIService
metadata:
  creationTimestamp: "2020-10-20T11:01:02Z"
  name: v1.platform.tkestack.io
  resourceVersion: "38020776"
  selfLink: /apis/apiregistration.k8s.io/v1/apiservices/v1.platform.tkestack.io
  uid: dfbb424a-8d38-4373-b105-50628f9b5902
spec:
  caBundle: xxxxxx...
  group: platform.tkestack.io
  groupPriorityMinimum: 1000
  service:
    name: tke-platform-api
    namespace: tke
    port: 443
  version: v1
  versionPriority: 5
status:
  conditions:
  - lastTransitionTime: "2020-12-08T04:48:51Z"
    message: all checks passed
    reason: Passed
    status: "True"
    type: Available
```

可以看到这些APIService都是在`apiregistration.k8s.io` group，以及`v1` version下的apiservices对象，那么这些APIService是怎么产生的，有什么作用呢？

## Local APIService产生原理

Aggregator 通过 APIServices 对象关联到某个 Service 来进行请求的转发，其关联的 Service 类型进一步决定了请求转发形式。Aggregator 包括一个 `GenericAPIServer` 和维护自身状态的 Controller。其中 `GenericAPIServer` 主要处理 `apiregistration.k8s.io` 组下的 APIService 资源请求，controller包括：

- `apiserviceRegistrationController`：负责 APIServices 中资源的注册与删除；
- `availableConditionController`：维护 APIServices 的可用状态，包括其引用 Service 是否可用等；
- `autoRegistrationController`：用于保持 API 中存在的一组特定的 APIServices；
- `crdRegistrationController`：负责将 CRD GroupVersions 自动注册到 APIServices 中；
- `openAPIAggregationController`：将 APIServices 资源的变化同步至提供的 OpenAPI 文档；

Kubernetes 中的一些附加组件，比如 metrics-server 就是通过 Aggregator 的方式进行扩展的，实际环境中可以通过使用 [apiserver-builder](https://github.com/kubernetes-sigs/apiserver-builder-alpha) 工具轻松以 Aggregator 的扩展方式创建自定义资源

这里我们看看autoRegistrationController逻辑：

```go
func createAggregatorServer(aggregatorConfig *aggregatorapiserver.Config, delegateAPIServer genericapiserver.DelegationTarget, apiExtensionInformers apiextensionsinformers.SharedInformerFactory) (*aggregatorapiserver.APIAggregator, error) {
	aggregatorServer, err := aggregatorConfig.Complete().NewWithDelegate(delegateAPIServer)
	if err != nil {
		return nil, err
	}

	// create controllers for auto-registration
	apiRegistrationClient, err := apiregistrationclient.NewForConfig(aggregatorConfig.GenericConfig.LoopbackClientConfig)
	if err != nil {
		return nil, err
	}
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
	if err != nil {
		return nil, err
	}

	err = aggregatorServer.GenericAPIServer.AddBootSequenceHealthChecks(
		makeAPIServiceAvailableHealthCheck(
			"autoregister-completion",
			apiServices,
			aggregatorServer.APIRegistrationInformers.Apiregistration().V1().APIServices(),
		),
	)
	if err != nil {
		return nil, err
	}

	return aggregatorServer, nil
}
```

展开autoRegisterController逻辑：

```go
// NewAutoRegisterController creates a new autoRegisterController.
func NewAutoRegisterController(apiServiceInformer informers.APIServiceInformer, apiServiceClient apiregistrationclient.APIServicesGetter) *autoRegisterController {
	c := &autoRegisterController{
		apiServiceLister:  apiServiceInformer.Lister(),
		apiServiceSynced:  apiServiceInformer.Informer().HasSynced,
		apiServiceClient:  apiServiceClient,
		apiServicesToSync: map[string]*v1.APIService{},

		apiServicesAtStart: map[string]bool{},

		syncedSuccessfullyLock: &sync.RWMutex{},
		syncedSuccessfully:     map[string]bool{},

		queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "autoregister"),
	}
	c.syncHandler = c.checkAPIService

	apiServiceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cast := obj.(*v1.APIService)
			c.queue.Add(cast.Name)
		},
		UpdateFunc: func(_, obj interface{}) {
			cast := obj.(*v1.APIService)
			c.queue.Add(cast.Name)
		},
		DeleteFunc: func(obj interface{}) {
			cast, ok := obj.(*v1.APIService)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					klog.V(2).Infof("Couldn't get object from tombstone %#v", obj)
					return
				}
				cast, ok = tombstone.Obj.(*v1.APIService)
				if !ok {
					klog.V(2).Infof("Tombstone contained unexpected object: %#v", obj)
					return
				}
			}
			c.queue.Add(cast.Name)
		},
	})

	return c
}

// Run starts the autoregister controller in a loop which syncs API services until stopCh is closed.
func (c *autoRegisterController) Run(threadiness int, stopCh <-chan struct{}) {
	// don't let panics crash the process
	defer utilruntime.HandleCrash()
	// make sure the work queue is shutdown which will trigger workers to end
	defer c.queue.ShutDown()

	klog.Infof("Starting autoregister controller")
	defer klog.Infof("Shutting down autoregister controller")

	// wait for your secondary caches to fill before starting your work
	if !controllers.WaitForCacheSync("autoregister", stopCh, c.apiServiceSynced) {
		return
	}

	// record APIService objects that existed when we started
	if services, err := c.apiServiceLister.List(labels.Everything()); err == nil {
		for _, service := range services {
			c.apiServicesAtStart[service.Name] = true
		}
	}

	// start up your worker threads based on threadiness.  Some controllers have multiple kinds of workers
	for i := 0; i < threadiness; i++ {
		// runWorker will loop until "something bad" happens.  The .Until will then rekick the worker
		// after one second
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	// wait until we're told to stop
	<-stopCh
}

func (c *autoRegisterController) runWorker() {
	// hot loop until we're told to stop.  processNextWorkItem will automatically wait until there's work
	// available, so we don't worry about secondary waits
	for c.processNextWorkItem() {
	}
}

// processNextWorkItem deals with one key off the queue.  It returns false when it's time to quit.
func (c *autoRegisterController) processNextWorkItem() bool {
	// pull the next work item from queue.  It should be a key we use to lookup something in a cache
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	// you always have to indicate to the queue that you've completed a piece of work
	defer c.queue.Done(key)

	// do your work on the key.  This method will contains your "do stuff" logic
	err := c.syncHandler(key.(string))
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
```

createAggregatorServer会执行apiServicesToRegister，如下：

```go
// CreateServerChain creates the apiservers connected via delegation.
func CreateServerChain(completedOptions completedServerRunOptions, stopCh <-chan struct{}) (*aggregatorapiserver.APIAggregator, error) {
	...
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

	return aggregatorServer, nil
}

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
	if err != nil {
		return nil, err
	}

	return aggregatorServer, nil
}

func apiServicesToRegister(delegateAPIServer genericapiserver.DelegationTarget, registration autoregister.AutoAPIServiceRegistration) []*v1.APIService {
	apiServices := []*v1.APIService{}

	for _, curr := range delegateAPIServer.ListedPaths() {
		if curr == "/api/v1" {
			apiService := makeAPIService(schema.GroupVersion{Group: "", Version: "v1"})
			registration.AddAPIServiceToSyncOnStart(apiService)
			apiServices = append(apiServices, apiService)
			continue
		}

		if !strings.HasPrefix(curr, "/apis/") {
			continue
		}
		// this comes back in a list that looks like /apis/rbac.authorization.k8s.io/v1alpha1
		tokens := strings.Split(curr, "/")
		if len(tokens) != 4 {
			continue
		}

		apiService := makeAPIService(schema.GroupVersion{Group: tokens[2], Version: tokens[3]})
		if apiService == nil {
			continue
		}
		registration.AddAPIServiceToSyncOnStart(apiService)
		apiServices = append(apiServices, apiService)
	}

	return apiServices
}

// k8s.io/kubernetes/staging/src/k8s.io/apiserver/pkg/server/genericapiserver.go:240
func (s *GenericAPIServer) ListedPaths() []string {
	return s.listedPathProvider.ListedPaths()
}

// k8s.io/kubernetes/staging/src/k8s.io/apiserver/pkg/server/config.go:520
// New creates a new server which logically combines the handling chain with the passed server.
// name is used to differentiate for logging. The handler chain in particular can be difficult as it starts delgating.
// delegationTarget may not be nil.
func (c completedConfig) New(name string, delegationTarget DelegationTarget) (*GenericAPIServer, error) {
	...
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

	// use the UnprotectedHandler from the delegation target to ensure that we don't attempt to double authenticator, authorize,
	// or some other part of the filter chain in delegation cases.
	if delegationTarget.UnprotectedHandler() == nil && c.EnableIndex {
		s.Handler.NonGoRestfulMux.NotFoundHandler(routes.IndexLister{
			StatusCode:   http.StatusNotFound,
			PathProvider: s.listedPathProvider,
		})
	}

	return s, nil
}

type ListedPathProviders []ListedPathProvider

// ListedPaths unions and sorts the included paths.
func (p ListedPathProviders) ListedPaths() []string {
	ret := sets.String{}
	for _, provider := range p {
		for _, path := range provider.ListedPaths() {
			ret.Insert(path)
		}
	}

	return ret.List()
}

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

// ListedPaths returns the paths that should be shown under /
func (a *APIServerHandler) ListedPaths() []string {
	var handledPaths []string
	// Extract the paths handled using restful.WebService
	for _, ws := range a.GoRestfulContainer.RegisteredWebServices() {
		handledPaths = append(handledPaths, ws.RootPath())
	}
	handledPaths = append(handledPaths, a.NonGoRestfulMux.ListedPaths()...)
	sort.Strings(handledPaths)

	return handledPaths
}
```

从上述代码可以看出ListedPaths会返回所有kube-apiserver的API Resource路径，然后交给apiServicesToRegister进行APIService的注册处理：

```go
func apiServicesToRegister(delegateAPIServer genericapiserver.DelegationTarget, registration autoregister.AutoAPIServiceRegistration) []*v1.APIService {
	apiServices := []*v1.APIService{}

	for _, curr := range delegateAPIServer.ListedPaths() {
		if curr == "/api/v1" {
			apiService := makeAPIService(schema.GroupVersion{Group: "", Version: "v1"})
			registration.AddAPIServiceToSyncOnStart(apiService)
			apiServices = append(apiServices, apiService)
			continue
		}

		if !strings.HasPrefix(curr, "/apis/") {
			continue
		}
		// this comes back in a list that looks like /apis/rbac.authorization.k8s.io/v1alpha1
		tokens := strings.Split(curr, "/")
		if len(tokens) != 4 {
			continue
		}

		apiService := makeAPIService(schema.GroupVersion{Group: tokens[2], Version: tokens[3]})
		if apiService == nil {
			continue
		}
		registration.AddAPIServiceToSyncOnStart(apiService)
		apiServices = append(apiServices, apiService)
	}

	return apiServices
}

func makeAPIService(gv schema.GroupVersion) *v1.APIService {
	apiServicePriority, ok := apiVersionPriorities[gv]
	if !ok {
		// if we aren't found, then we shouldn't register ourselves because it could result in a CRD group version
		// being permanently stuck in the APIServices list.
		klog.Infof("Skipping APIService creation for %v", gv)
		return nil
	}
	return &v1.APIService{
		ObjectMeta: metav1.ObjectMeta{Name: gv.Version + "." + gv.Group},
		Spec: v1.APIServiceSpec{
			Group:                gv.Group,
			Version:              gv.Version,
			GroupPriorityMinimum: apiServicePriority.group,
			VersionPriority:      apiServicePriority.version,
		},
	}
}
```

如果是core group(/api/v1)，则构造`v1.` apiService，如下：

```yaml
apiVersion: apiregistration.k8s.io/v1
kind: APIService
metadata:
  creationTimestamp: "2020-10-20T10:39:48Z"
  labels:
    kube-aggregator.kubernetes.io/automanaged: onstart
  name: v1.
  resourceVersion: "11"
  selfLink: /apis/apiregistration.k8s.io/v1/apiservices/v1.
  uid: 724838d6-c73a-441d-a63d-e2d179556f01
spec:
  groupPriorityMinimum: 18000
  version: v1
  versionPriority: 1
status:
  conditions:
  - lastTransitionTime: "2020-10-20T10:39:48Z"
    message: Local APIServices are always available
    reason: Local
    status: "True"
    type: Available
```

而对于named groups下的资源(/apis/$GROUP/$VERSION)，则构建由$GROUP和$VERSION构成的apiService，如下：

```yaml
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
```

这两种类型apiService都会执行registration.AddAPIServiceToSyncOnStart(apiService)，回到了autoRegisterController，如下：

```go
// AddAPIServiceToSyncOnStart registers an API service to sync only when the controller starts.
func (c *autoRegisterController) AddAPIServiceToSyncOnStart(in *v1.APIService) {
	c.addAPIServiceToSync(in, manageOnStart)
}

const (
	// AutoRegisterManagedLabel is a label attached to the APIService that identifies how the APIService wants to be synced.
	AutoRegisterManagedLabel = "kube-aggregator.kubernetes.io/automanaged"

	// manageOnStart is a value for the AutoRegisterManagedLabel that indicates the APIService wants to be synced one time when the controller starts.
	manageOnStart = "onstart"
	// manageContinuously is a value for the AutoRegisterManagedLabel that indicates the APIService wants to be synced continuously.
	manageContinuously = "true"
)

func (c *autoRegisterController) addAPIServiceToSync(in *v1.APIService, syncType string) {
	c.apiServicesToSyncLock.Lock()
	defer c.apiServicesToSyncLock.Unlock()

	apiService := in.DeepCopy()
	if apiService.Labels == nil {
		apiService.Labels = map[string]string{}
	}
	apiService.Labels[AutoRegisterManagedLabel] = syncType

	c.apiServicesToSync[apiService.Name] = apiService
	c.queue.Add(apiService.Name)
}
```

这里会将apiService打标签：kube-aggregator.kubernetes.io/automanaged=onstart，从上面的示例也可以佐证，并将apiService存放于apiServicesToSync中，最终由checkAPIService处理：

```go
// checkAPIService syncs the current APIService against a list of desired APIService objects
//
//                                                 | A. desired: not found | B. desired: sync on start | C. desired: sync always
// ------------------------------------------------|-----------------------|---------------------------|------------------------
// 1. current: lookup error                        | error                 | error                     | error
// 2. current: not found                           | -                     | create once               | create
// 3. current: no sync                             | -                     | -                         | -
// 4. current: sync on start, not present at start | -                     | -                         | -
// 5. current: sync on start, present at start     | delete once           | update once               | update once
// 6. current: sync always                         | delete                | update once               | update
func (c *autoRegisterController) checkAPIService(name string) (err error) {
	// 获取想注册的apiService  
	desired := c.GetAPIServiceToSync(name)
  // 获取实际已经创建的apiService
	curr, err := c.apiServiceLister.Get(name)

	// 下面操作成功后，将apiService标记为已经同步创建  
	// if we've never synced this service successfully, record a successful sync.
	hasSynced := c.hasSyncedSuccessfully(name)
	if !hasSynced {
		defer func() {
			if err == nil {
				c.setSyncedSuccessfully(name)
			}
		}()
	}

	switch {
	// we had a real error, just return it (1A,1B,1C)
	case err != nil && !apierrors.IsNotFound(err):
		return err

	// we don't have an entry and we don't want one (2A)
	case apierrors.IsNotFound(err) && desired == nil:
		return nil

	// local apiService正常情况    
	// the local object only wants to sync on start and has already synced (2B,5B,6B "once" enforcement)
	case isAutomanagedOnStart(desired) && hasSynced:
		return nil

	// 如果还没有发现apiService，则创建对应的apiService    
	// we don't have an entry and we do want one (2B,2C)
	case apierrors.IsNotFound(err) && desired != nil:
		_, err := c.apiServiceClient.APIServices().Create(context.TODO(), desired, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			// created in the meantime, we'll get called again
			return nil
		}
		return err

	// 对于不是autoRegisterController管理的apiService(例如aggregated apiserver)，则不进行处理
	// we aren't trying to manage this APIService (3A,3B,3C)
	case !isAutomanaged(curr):
		return nil

	// the remote object only wants to sync on start, but was added after we started (4A,4B,4C)
	case isAutomanagedOnStart(curr) && !c.apiServicesAtStart[name]:
		return nil

	// the remote object only wants to sync on start and has already synced (5A,5B,5C "once" enforcement)
	case isAutomanagedOnStart(curr) && hasSynced:
		return nil

	// 如果不是local apiService，则对该apiService进行删除操作
	// we have a spurious APIService that we're managing, delete it (5A,6A)
	case desired == nil:
		opts := metav1.DeleteOptions{Preconditions: metav1.NewUIDPreconditions(string(curr.UID))}
		err := c.apiServiceClient.APIServices().Delete(context.TODO(), curr.Name, opts)
		if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
			// deleted or changed in the meantime, we'll get called again
			return nil
		}
		return err

	// if the specs already match, nothing for us to do
	case reflect.DeepEqual(curr.Spec, desired.Spec):
		return nil
	}

	// 如果已经创建的apiService与期望的存在矛盾，则以desired.Spec结构为准，并进行更新  
	// we have an entry and we have a desired, now we deconflict.  Only a few fields matter. (5B,5C,6B,6C)
	apiService := curr.DeepCopy()
	apiService.Spec = desired.Spec
	_, err = c.apiServiceClient.APIServices().Update(context.TODO(), apiService, metav1.UpdateOptions{})
	if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
		// deleted or changed in the meantime, we'll get called again
		return nil
	}
	return err
}

// GetAPIServiceToSync gets a single API service to sync.
func (c *autoRegisterController) GetAPIServiceToSync(name string) *v1.APIService {
	c.apiServicesToSyncLock.RLock()
	defer c.apiServicesToSyncLock.RUnlock()

	return c.apiServicesToSync[name]
}

func (c *autoRegisterController) hasSyncedSuccessfully(name string) bool {
	c.syncedSuccessfullyLock.RLock()
	defer c.syncedSuccessfullyLock.RUnlock()
	return c.syncedSuccessfully[name]
}

```

注释其实已经说明了该函数功能以及可能的处理情况：

```go
// checkAPIService syncs the current APIService against a list of desired APIService objects
//
//                                                 | A. desired: not found | B. desired: sync on start | C. desired: sync always
// ------------------------------------------------|-----------------------|---------------------------|------------------------
// 1. current: lookup error                        | error                 | error                     | error
// 2. current: not found                           | -                     | create once               | create
// 3. current: no sync                             | -                     | -                         | -
// 4. current: sync on start, not present at start | -                     | -                         | -
// 5. current: sync on start, present at start     | delete once           | update once               | update once
// 6. current: sync always                         | delete                | update once               | update
```

## 总结

* aggregated server实现CR(自定义API资源) 的CRUD API接口，并可以灵活选择后端存储，可以与core kube-apiserver一起公共etcd，也可自己独立部署etcd数据库或者其它数据库。aggregated server实现的CR API路径为：/apis/$GROUP/$VERSION，具体到sample apiserver为：/apis/wardle.example.com/v1alpha1，下面的资源类型有：flunders以及fischers

* aggregated server通过部署APIService，service fields指向对应的aggregated server service实现与core kube-apiserver的集成

* aggregated server目录结构如下：

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

* apiserviceRegistrationController负责APIService资源的注册与删除。apiService有两种类型：Local(Service为空)以及Service(Service非空)。apiserviceRegistrationController负责对这两种类型apiService设置代理：Local类型会直接路由给kube-apiserver进行处理；而Service类型则会设置代理并将请求转化为对aggregated Service的请求(proxyPath := "/apis/" + apiService.Spec.Group + "/" + apiService.Spec.Version)，而请求的负载均衡策略则是优先本地访问kube-apiserver(如果service为default kubernetes service:443)=>通过service ClusterIP:Port访问(默认) 或者 通过随机选择service endpoint backend进行访问：

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
  ```

* kube-apiserver中的AggregatorServer创建过程中会根据所有kube-apiserver定义的API资源创建默认的APIService列表，名称即是$VERSION/$GROUP，这些APIService都会有标签`kube-aggregator.kubernetes.io/automanaged: onstart`，例如：v1.apps apiService。autoRegistrationController创建并维护这些列表中的APIService，也即我们看到的Local apiService；对于自定义的APIService(aggregated server)，则不会对其进行处理

