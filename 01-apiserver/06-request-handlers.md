# Table of contents
1. [overview](#overview)



# Overview
resource handler will take over after filters.
recall from **04-api-registry**.

`kubernetes/staging/src/k8s.io/apiserver/pkg/endpoints/installer.go`

```go

func (a *APIInstaller) registerResourceHandlers(path string, storage rest.Storage, ws *restful.WebService) (*metav1.APIResource, error) {
	admit := a.group.Admit

	optionsExternalVersion := a.group.GroupVersion
	if a.group.OptionsExternalVersion != nil {
		optionsExternalVersion = *a.group.OptionsExternalVersion
	}

	resource, subresource, err := splitSubresource(path)
	if err != nil {
		return nil, err
	}

	group, version := a.group.GroupVersion.Group, a.group.GroupVersion.Version
	
	...
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
	
	...
	
	switch action.Verb {
		case "GET": // Get a resource.
			var handler restful.RouteFunction
			if isGetterWithOptions {
				handler = restfulGetResourceWithOptions(getterWithOptions, reqScope, isSubresource)
			} else {
				handler = restfulGetResource(getter, exporter, reqScope)
			}
			...
			
		case "POST": // Create a resource.
			var handler restful.RouteFunction
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
			...
		case "DELETE": // Delete a resource.
			article := GetArticleForNoun(kind, " ")
			doc := "delete" + article + kind
			if isSubresource {
				doc = "delete " + subresource + " of" + article + kind
			}
			handler := metrics.InstrumentRouteFunc(action.Verb, group, version, resource, subresource, requestScope, metrics.APIServerComponent, restfulDeleteResource(gracefulDeleter, isGracefulDeleter, reqScope, admit))
		
		...	
	}
	...
}
```

# Read Handler
take `GET` as an example. it basically calls rest.Storage to do the job.


*kubernetes/staging/src/k8s.io/apiserver/pkg/endpoints/handlers/get.go*

```go
func restfulGetResourceWithOptions(r rest.GetterWithOptions, scope handlers.RequestScope, isSubresource bool) restful.RouteFunction {
	return func(req *restful.Request, res *restful.Response) {
		handlers.GetResourceWithOptions(r, &scope, isSubresource)(res.ResponseWriter, req.Request)
	}
}

// GetResourceWithOptions returns a function that handles retrieving a single resource from a rest.Storage object.
func GetResourceWithOptions(r rest.GetterWithOptions, scope *RequestScope, isSubresource bool) http.HandlerFunc {
	return getResourceHandler(scope,
		func(ctx context.Context, name string, req *http.Request, trace *utiltrace.Trace) (runtime.Object, error) {
			opts, subpath, subpathKey := r.NewGetOptions()
			trace.Step("About to process Get options")
			if err := getRequestOptions(req, scope, opts, subpath, subpathKey, isSubresource); err != nil {
				err = errors.NewBadRequest(err.Error())
				return nil, err
			}
			if trace != nil {
				trace.Step("About to Get from storage")
			}
			return r.Get(ctx, name, opts)
		})
}
```

`r rest.GetterWithOptions` is from `getterWithOptions, isGetterWithOptions := storage.(rest.GetterWithOptions)`

## rest.Storage
* storage is a `LegacyRESTStorage` object.
recall from **04-api-registry**, take `namespace` as an example.

```go
func (m *Master) InstallLegacyAPI(c *completedConfig, restOptionsGetter generic.RESTOptionsGetter, legacyRESTStorageProvider corerest.LegacyRESTStorageProvider) {
	legacyRESTStorage, apiGroupInfo, err := legacyRESTStorageProvider.NewLegacyRESTStorage(restOptionsGetter)
	...
}

func (c LegacyRESTStorageProvider) NewLegacyRESTStorage(restOptionsGetter generic.RESTOptionsGetter) (LegacyRESTStorage, genericapiserver.APIGroupInfo, error) {
	...
	namespaceStorage, namespaceStatusStorage, namespaceFinalizeStorage := namespacestore.NewREST(restOptionsGetter)
	...
}

```

* Namesapce RESTStorage contains a `genericregistry.Store` object which is the interface of etcd.

  *kubernetes/pkg/registry/core/namespace/storage/storage.go*


```go
// NewREST returns a RESTStorage object that will work against namespaces.
func NewREST(optsGetter generic.RESTOptionsGetter) (*REST, *StatusREST, *FinalizeREST) {
	store := &genericregistry.Store{
		NewFunc:                  func() runtime.Object { return &api.Namespace{} },
		NewListFunc:              func() runtime.Object { return &api.NamespaceList{} },
		PredicateFunc:            namespace.MatchNamespace,
		DefaultQualifiedResource: api.Resource("namespaces"),

		CreateStrategy:      namespace.Strategy,
		UpdateStrategy:      namespace.Strategy,
		DeleteStrategy:      namespace.Strategy,
		ReturnDeletedObject: true,

		ShouldDeleteDuringUpdate: ShouldDeleteNamespaceDuringUpdate,

		TableConvertor: printerstorage.TableConvertor{TableGenerator: printers.NewTableGenerator().With(printersinternal.AddHandlers)},
	}
	options := &generic.StoreOptions{RESTOptions: optsGetter, AttrFunc: namespace.GetAttrs}
	if err := store.CompleteWithOptions(options); err != nil {
		panic(err) // TODO: Propagate error up
	}

	statusStore := *store
	statusStore.UpdateStrategy = namespace.StatusStrategy

	finalizeStore := *store
	finalizeStore.UpdateStrategy = namespace.FinalizeStrategy

	return &REST{store: store, status: &statusStore}, &StatusREST{store: &statusStore}, &FinalizeREST{store: &finalizeStore}
}

func (r *REST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	return r.store.Get(ctx, name, options)
}
```


* `r.store.Get` calls `Storage.Get` to do the job

  *kubernetes/staging/src/k8s.io/apiserver/pkg/registry/generic/registry/store.go*

```go
type Store struct {
	...
	// Storage is the interface for the underlying storage for the
	// resource. It is wrapped into a "DryRunnableStorage" that will
	// either pass-through or simply dry-run.
	Storage DryRunnableStorage
	...
}

// Get retrieves the item from storage.
func (e *Store) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	obj := e.NewFunc()
	key, err := e.KeyFunc(ctx, name)
	if err != nil {
		return nil, err
	}
	if err := e.Storage.Get(ctx, key, options.ResourceVersion, obj, false); err != nil {
		return nil, storeerr.InterpretGetError(err, e.qualifiedResourceFromContext(ctx), name)
	}
	if e.Decorator != nil {
		if err := e.Decorator(obj); err != nil {
			return nil, err
		}
	}
	return obj, nil
}
```

* DryRunnableStorage just calls `Storage.Get` which is `storage.Interface`

  */kubernetes/staging/src/k8s.io/apiserver/pkg/registry/generic/registry/dryrun.go*

```go
type DryRunnableStorage struct {
	Storage storage.Interface
	Codec   runtime.Codec
}

func (s *DryRunnableStorage) Get(ctx context.Context, key string, resourceVersion string, objPtr runtime.Object, ignoreNotFound bool) error {
	return s.Storage.Get(ctx, key, resourceVersion, objPtr, ignoreNotFound)
}
```

  *kubernetes/staging/src/k8s.io/apiserver/pkg/storage/interfaces.go*
  
```go
// Interface offers a common interface for object marshaling/unmarshaling operations and
// hides all the storage-related operations behind it.
type Interface interface {
	...
	// return a zero object of the requested type, or an error, depending on ignoreNotFound.
	// Treats empty responses and nil response nodes exactly like a not found error.
	// The returned contents may be delayed, but it is guaranteed that they will
	// be have at least 'resourceVersion'.
	Get(ctx context.Context, key string, resourceVersion string, objPtr runtime.Object, ignoreNotFound bool) error
	...
}
```

## Storage.Interface

* so what's this `Storage storage.Interface`? 
  
  it's created in `store.CompleteWithOptions`

```go
// NewREST returns a RESTStorage object that will work against namespaces.
func NewREST(optsGetter generic.RESTOptionsGetter) (*REST, *StatusREST, *FinalizeREST) {
    ...
	options := &generic.StoreOptions{RESTOptions: optsGetter, AttrFunc: namespace.GetAttrs}
	if err := store.CompleteWithOptions(options); err != nil {
		panic(err) // TODO: Propagate error up
	}
   ...
}
```
*kubernetes/staging/src/k8s.io/apiserver/pkg/registry/generic/registry/store.go*

we can see it's from `opts.Decorator`.

```go
// CompleteWithOptions updates the store with the provided options and
// defaults common fields.
func (e *Store) CompleteWithOptions(options *generic.StoreOptions) error {
	...
	opts, err := options.RESTOptions.GetRESTOptions(e.DefaultQualifiedResource)
	...
	if e.Storage.Storage == nil {
		e.Storage.Codec = opts.StorageConfig.Codec
		e.Storage.Storage, e.DestroyFunc = opts.Decorator(
			opts.StorageConfig,
			prefix,
			keyFunc,
			e.NewFunc,
			e.NewListFunc,
			attrFunc,
			triggerFunc,
		)
	...
	}
	return nil
}
```

## StoreOptions

* what's this options `*generic.StoreOptions`?

  recall from **02-master-config**,  it's from master generic config.
  
  ```go
  type Config struct {
    ...
    	// RESTOptionsGetter is used to construct RESTStorage types via the generic registry.
    	RESTOptionsGetter genericregistry.RESTOptionsGetter
	...
  }
  
  func buildGenericConfig(s *options.ServerRunOptions, proxyTransport *http.Transport, ) (
	...
	    storageFactoryConfig := kubeapiserver.NewStorageFactoryConfig()
		storageFactoryConfig.ApiResourceConfig = genericConfig.MergedResourceConfig
		completedStorageFactoryConfig, err := storageFactoryConfig.Complete(s.Etcd)
		if err != nil {
			lastErr = err
			return
		}
		storageFactory, lastErr = completedStorageFactoryConfig.New()
		if lastErr != nil {
			return
		}
		if lastErr = s.Etcd.ApplyWithStorageFactoryTo(storageFactory, genericConfig); lastErr != nil {
			return
		}
	...
  )
  ```
  
  *kubernetes/staging/src/k8s.io/apiserver/pkg/server/options/etcd.go*
  
  `RESTOptionsGetter` is ` &StorageFactoryRestOptionsFactory`,
  
  ```go
  func (s *EtcdOptions) ApplyWithStorageFactoryTo(factory serverstorage.StorageFactory, c *server.Config) error {
		if err := s.addEtcdHealthEndpoint(c); err != nil {
			return err
		}
		c.RESTOptionsGetter = &StorageFactoryRestOptionsFactory{Options: *s, StorageFactory: factory}
		return nil
	}
	
  func (f *StorageFactoryRestOptionsFactory) GetRESTOptions(resource schema.GroupResource) (generic.RESTOptions, error) {
		storageConfig, err := f.StorageFactory.NewConfig(resource)
		if err != nil {
			return generic.RESTOptions{}, fmt.Errorf("unable to find storage destination for %v, due to %v", resource, err.Error())
		}
		
		ret := generic.RESTOptions{
			StorageConfig:           storageConfig,
			Decorator:               generic.UndecoratedStorage,
			DeleteCollectionWorkers: f.Options.DeleteCollectionWorkers,
			EnableGarbageCollection: f.Options.EnableGarbageCollection,
			ResourcePrefix:          f.StorageFactory.ResourcePrefix(resource),
			CountMetricPollPeriod:   f.Options.StorageConfig.CountMetricPollPeriod,
		}
		if f.Options.EnableWatchCache {
			sizes, err := ParseWatchCacheSizes(f.Options.WatchCacheSizes)
			if err != nil {
				return generic.RESTOptions{}, err
			}
			cacheSize, ok := sizes[resource]
			if !ok {
				cacheSize = f.Options.DefaultWatchCacheSize
			}
			// depending on cache size this might return an undecorated storage
			ret.Decorator = genericregistry.StorageWithCacher(cacheSize)
		}
	
		return ret, nil
	}
  ```
  
  so `opts` is `ret ` from `(f *StorageFactoryRestOptionsFactory) GetRESTOptions`.
  
  ```go
	func (e *Store) CompleteWithOptions(options *generic.StoreOptions) error {
		...
		opts, err := options.RESTOptions.GetRESTOptions(e.DefaultQualifiedResource)
		...
	}
	```
	
## Storage

* Decorator

  there're two types of decorators
  * `UndecoratedStorage` operate etcd directly
  * `StorageWithCache` operate cache

  by default cache is enabled
  
  ```go
	func NewServerRunOptions() *ServerRunOptions {
		s := ServerRunOptions{
			...
			Etcd: genericoptions.NewEtcdOptions(storagebackend.NewDefaultConfig(kubeoptions.DefaultEtcdPathPrefix, nil)),
		...
	}
	
	func NewEtcdOptions(backendConfig *storagebackend.Config) *EtcdOptions {
		options := &EtcdOptions{
			StorageConfig:           *backendConfig,
			DefaultStorageMediaType: "application/json",
			DeleteCollectionWorkers: 1,
			EnableGarbageCollection: true,
			EnableWatchCache:        true,
			DefaultWatchCacheSize:   100,
		}
		options.StorageConfig.CountMetricPollPeriod = time.Minute
		return options
	}
  ```
  
* StorageWithCache
  
  *kubernetes/staging/src/k8s.io/apiserver/pkg/registry/generic/registry/storage_factory.go*

  ```go
	// Creates a cacher based given storageConfig.
	func StorageWithCacher(capacity int) generic.StorageDecorator {
		return func(
			storageConfig *storagebackend.Config,
			resourcePrefix string,
			keyFunc func(obj runtime.Object) (string, error),
			newFunc func() runtime.Object,
			newListFunc func() runtime.Object,
			getAttrsFunc storage.AttrFunc,
			triggerFunc storage.TriggerPublisherFunc) (storage.Interface, factory.DestroyFunc) {
	
			s, d := generic.NewRawStorage(storageConfig)
			if capacity <= 0 {
				klog.V(5).Infof("Storage caching is disabled for %T", newFunc())
				return s, d
			}
			if klog.V(5) {
				klog.Infof("Storage caching is enabled for %T with capacity %v", newFunc(), capacity)
			}
	
			// TODO: we would change this later to make storage always have cacher and hide low level KV layer inside.
			// Currently it has two layers of same storage interface -- cacher and low level kv.
			cacherConfig := cacherstorage.Config{
				CacheCapacity:        capacity,
				Storage:              s,
				Versioner:            etcdstorage.APIObjectVersioner{},
				ResourcePrefix:       resourcePrefix,
				KeyFunc:              keyFunc,
				NewFunc:              newFunc,
				NewListFunc:          newListFunc,
				GetAttrsFunc:         getAttrsFunc,
				TriggerPublisherFunc: triggerFunc,
				Codec:                storageConfig.Codec,
			}
			cacher := cacherstorage.NewCacherFromConfig(cacherConfig)
			destroyFunc := func() {
				cacher.Stop()
				d()
			}
	
			// TODO : Remove RegisterStorageCleanup below when PR
			// https://github.com/kubernetes/kubernetes/pull/50690
			// merges as that shuts down storage properly
			RegisterStorageCleanup(destroyFunc)
	
			return cacher, destroyFunc
		}
	}
  ```
  *kubernetes/staging/src/k8s.io/apiserver/pkg/storage/cacher/cacher.go*

  cacher is from `NewCacherFromConfig` which is `Cacher`.
  
  for Get function if resourceVersion is not specified, serve it from etcd directly, otherwise from cache. 
  
  storage and cache details will be covered in **07-storage-and-cache**.
  
  ```go
	// Cacher is responsible for serving WATCH and LIST requests for a given
	// resource from its internal cache and updating its cache in the background
	// based on the underlying storage contents.
	// Cacher implements storage.Interface (although most of the calls are just
	// delegated to the underlying storage).
	type Cacher struct {
		...
	}
	
	// Get implements storage.Interface.
	func (c *Cacher) Get(ctx context.Context, key string, resourceVersion string, objPtr runtime.Object, ignoreNotFound bool) error {
		if resourceVersion == "" {
			// If resourceVersion is not specified, serve it from underlying
			// storage (for backward compatibility).
			return c.storage.Get(ctx, key, resourceVersion, objPtr, ignoreNotFound)
		}
		// If resourceVersion is specified, serve it from cache.
		// It's guaranteed that the returned value is at least that
		// fresh as the given resourceVersion.
		getRV, err := c.versioner.ParseResourceVersion(resourceVersion)
		...
	}
	
	func NewCacherFromConfig(config Config) *Cacher {
		...	
		return cacher
	}
  ```
  
## Conclusion

eventually api restful handler will call `Cacher` functions,
depends on request method, it serves from etcd directly or from cache.

```go
// handlers
func (a *APIInstaller) registerResourceHandlers(path string, storage rest.Storage, ws *restful.WebService) (*metav1.APIResource, error) {
  	...
	  	switch action.Verb {
		case "GET": // Get a resource.
			var handler restful.RouteFunction
			if isGetterWithOptions {
				handler = restfulGetResourceWithOptions(getterWithOptions, reqScope, isSubresource)
			} else {
				handler = restfulGetResource(getter, exporter, reqScope)
			}
		case "POST":
			...
		case "DELETE":
			...
		...
	}
}
	
// actual functions
func (c *Cacher) Create(ctx context.Context, key string, obj, out runtime.Object, ttl uint64) error {
	return c.storage.Create(ctx, key, obj, out, ttl)
}	
func (c *Cacher) Delete(ctx context.Context, key string, out runtime.Object, preconditions *storage.Preconditions, validateDeletion storage.ValidateObjectFunc) error {
	return c.storage.Delete(ctx, key, out, preconditions, validateDeletion)
}
...
```

# Write Handler

basically same with read handler, but there're two differences

## Admission Control
write handlers check admission first. take POST as an example:

```go
func restfulCreateResource(r rest.Creater, scope handlers.RequestScope, admit admission.Interface) restful.RouteFunction {
	return func(req *restful.Request, res *restful.Response) {
		handlers.CreateResource(r, &scope, admit)(res.ResponseWriter, req.Request)
	}
}

// CreateResource returns a function that will handle a resource creation.
func CreateResource(r rest.Creater, scope *RequestScope, admission admission.Interface) http.HandlerFunc {
	return createHandler(&namedCreaterAdapter{r}, scope, admission, false)
}

func createHandler(r rest.NamedCreater, scope *RequestScope, admit admission.Interface, includeName bool) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		...
		
		admit = admission.WithAudit(admit, ae)
		audit.LogRequestObject(ae, obj, scope.Resource, scope.Subresource, scope.Serializer)

		userInfo, _ := request.UserFrom(ctx)
		admissionAttributes := admission.NewAttributesRecord(obj, nil, scope.Kind, namespace, name, scope.Resource, scope.Subresource, admission.Create, options, dryrun.IsDryRun(options.DryRun), userInfo)
		if mutatingAdmission, ok := admit.(admission.MutationInterface); ok && mutatingAdmission.Handles(admission.Create) {
			err = mutatingAdmission.Admit(admissionAttributes, scope)
			if err != nil {
				scope.err(err, w, req)
				return
			}
		}

		...
		trace.Step("About to store object in database")
		result, err := finishRequest(timeout, func() (runtime.Object, error) {
			return r.Create(
				ctx,
				name,
				obj,
				rest.AdmissionToValidateObjectFunc(admit, admissionAttributes, scope),
				options,
			)
		})
		...
	}
}
```

### Admit

admit is from GenericAPIServer admissionControl

```go
func (a *APIInstaller) registerResourceHandlers(path string, storage rest.Storage, ws *restful.WebService) (*metav1.APIResource, error) {
	admit := a.group.Admit
	...
}

func (s *GenericAPIServer) getAPIGroupVersion(apiGroupInfo *APIGroupInfo, groupVersion schema.GroupVersion, apiPrefix string) *genericapi.APIGroupVersion {
	storage := make(map[string]rest.Storage)
	for k, v := range apiGroupInfo.VersionedResourcesStorageMap[groupVersion.Version] {
		storage[strings.ToLower(k)] = v
	}
	version := s.newAPIGroupVersion(apiGroupInfo, groupVersion)
	version.Root = apiPrefix
	version.Storage = storage
	return version
}

func (s *GenericAPIServer) newAPIGroupVersion(apiGroupInfo *APIGroupInfo, groupVersion schema.GroupVersion) *genericapi.APIGroupVersion {
	return &genericapi.APIGroupVersion{
		...

		Admit:                        s.admissionControl,
		MinRequestTimeout:            s.minRequestTimeout,
		EnableAPIResponseCompression: s.enableAPIResponseCompression,
		Authorizer:                   s.Authorizer,
	}
}
```

recall from **01-entry**,  admit is a `chainAdmissionHandler` which includes all loaded admit plugins.

```go
// BuildGenericConfig takes the master server options and produces the genericapiserver.Config associated with it
func buildGenericConfig(
	s *options.ServerRunOptions,
	proxyTransport *http.Transport){
	...
	err = s.Admission.ApplyTo(
		genericConfig,
		versionedInformers,
		kubeClientConfig,
		pluginInitializers...)
	if err != nil {
		lastErr = fmt.Errorf("failed to initialize admission: %v", err)
	}
	...
}

// ApplyTo adds the admission chain to the server configuration.
// Kube-apiserver just call generic AdmissionOptions.ApplyTo.
func (a *AdmissionOptions) ApplyTo(
	c *server.Config,
	informers informers.SharedInformerFactory,
	kubeAPIServerClientConfig *rest.Config,
	pluginInitializers ...admission.PluginInitializer,
) error {
	if a == nil {
		return nil
	}

	if a.PluginNames != nil {
		// pass PluginNames to generic AdmissionOptions
		a.GenericAdmission.EnablePlugins, a.GenericAdmission.DisablePlugins = computePluginNames(a.PluginNames, a.GenericAdmission.RecommendedPluginOrder)
	}

	return a.GenericAdmission.ApplyTo(c, informers, kubeAPIServerClientConfig, pluginInitializers...)
}

// ApplyTo adds the admission chain to the server configuration.
// In case admission plugin names were not provided by a custer-admin they will be prepared from the recommended/default values.
// In addition the method lazily initializes a generic plugin that is appended to the list of pluginInitializers
// note this method uses:
//  genericconfig.Authorizer
func (a *AdmissionOptions) ApplyTo(
	c *server.Config,
	informers informers.SharedInformerFactory,
	kubeAPIServerClientConfig *rest.Config,
	pluginInitializers ...admission.PluginInitializer,
) error {
	...

	admissionChain, err := a.Plugins.NewFromPlugins(pluginNames, pluginsConfigProvider, initializersChain, a.Decorators)
	if err != nil {
		return err
	}

	c.AdmissionControl = admissionmetrics.WithStepMetrics(admissionChain)
	return nil
}

// NewFromPlugins returns an admission.Interface that will enforce admission control decisions of all
// the given plugins.
func (ps *Plugins) NewFromPlugins(pluginNames []string, configProvider ConfigProvider, pluginInitializer PluginInitializer, decorator Decorator) (Interface, error) {
	...
	return newReinvocationHandler(chainAdmissionHandler(handlers)), nil
}

```

### chainAdmissionHandler
*kubernetes/staging/src/k8s.io/apiserver/pkg/admission/chain.go*

```go
// chainAdmissionHandler is an instance of admission.NamedHandler that performs admission control using
// a chain of admission handlers
type chainAdmissionHandler []Interface

// NewChainHandler creates a new chain handler from an array of handlers. Used for testing.
func NewChainHandler(handlers ...Interface) chainAdmissionHandler {
	return chainAdmissionHandler(handlers)
}

// Admit performs an admission control check using a chain of handlers, and returns immediately on first error
func (admissionHandler chainAdmissionHandler) Admit(a Attributes, o ObjectInterfaces) error {
	for _, handler := range admissionHandler {
		if !handler.Handles(a.GetOperation()) {
			continue
		}
		if mutator, ok := handler.(MutationInterface); ok {
			err := mutator.Admit(a, o)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Handles will return true if any of the handlers handles the given operation
func (admissionHandler chainAdmissionHandler) Handles(operation Operation) bool {
	for _, handler := range admissionHandler {
		if handler.Handles(operation) {
			return true
		}
	}
	return false
}

```

so it calls chainAdmissionHandler `Admit` and `Handles` functions.

```go
	if mutatingAdmission, ok := admit.(admission.MutationInterface); ok && mutatingAdmission.Handles(admission.Create) {
		err = mutatingAdmission.Admit(admissionAttributes, scope)
		if err != nil {
			scope.err(err, w, req)
			return
		}
	}
```

in each function, chainAdmissionHandler just invokes each plugin function,
and returns error if one fails.

### Default Admission Plugins

default admission controllers are defined in *kubernetes/plugin/pkg/admission*

```go
// DefaultOffAdmissionPlugins get admission plugins off by default for kube-apiserver.
func DefaultOffAdmissionPlugins() sets.String {
	defaultOnPlugins := sets.NewString(
		lifecycle.PluginName,                    //NamespaceLifecycle
		limitranger.PluginName,                  //LimitRanger
		serviceaccount.PluginName,               //ServiceAccount
		setdefault.PluginName,                   //DefaultStorageClass
		resize.PluginName,                       //PersistentVolumeClaimResize
		defaulttolerationseconds.PluginName,     //DefaultTolerationSeconds
		mutatingwebhook.PluginName,              //MutatingAdmissionWebhook
		validatingwebhook.PluginName,            //ValidatingAdmissionWebhook
		resourcequota.PluginName,                //ResourceQuota
		storageobjectinuseprotection.PluginName, //StorageObjectInUseProtection
	)

	...
}
```

## No Cache
write handlers operate etcd directly

```go
func (c *Cacher) Create(ctx context.Context, key string, obj, out runtime.Object, ttl uint64) error {
	return c.storage.Create(ctx, key, obj, out, ttl)
}	
func (c *Cacher) Delete(ctx context.Context, key string, out runtime.Object, preconditions *storage.Preconditions, validateDeletion storage.ValidateObjectFunc) error {
	return c.storage.Delete(ctx, key, out, preconditions, validateDeletion)
}
...
```
