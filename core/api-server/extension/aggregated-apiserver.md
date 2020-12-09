kubernetes aggregated-apiserver
===============================

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

这些yamls中最关键的就是apiservice.yaml，它将core kube-apiserver与extension apiserver连接在一起，下面开始分析：

```go

```



