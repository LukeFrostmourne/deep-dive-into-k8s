# Table of contents
1. [Overview](#overview)
2. [UndecoratedStorage](#UndecoratedStorage)
   * [Get](#Get)
   * [Create](#Create)
   * [Watch](#Watch)
3. [StorageWithCacher](#StorageWithCacher)
   * [Initialization](#NewCacherFromConfig)
     * [Cacher](#Cacher)
     * [Reflector](#Reflector)
     * [startCaching](#startCaching)
     * [dispatchEvents](#dispatchEvents)
   * [Functions](#functions)
     * [Get](#Get)
     * [Watch](#Watch)



# Overview
recall from **06-request-handlers**, there're storage type: `UndecoratedStorage` and `StorageWithCache`

# UndecoratedStorage
it basically is a [etcdv3 client](https://github.com/etcd-io/etcd/tree/master/clientv3)

*kubernetes/staging/src/k8s.io/apiserver/pkg/registry/generic/storage_decorator.go*

```go
// UndecoratedStorage returns the given a new storage from the given config
// without any decoration.
func UndecoratedStorage(
	config *storagebackend.Config,
	resourcePrefix string,
	keyFunc func(obj runtime.Object) (string, error),
	newFunc func() runtime.Object,
	newListFunc func() runtime.Object,
	getAttrsFunc storage.AttrFunc,
	trigger storage.TriggerPublisherFunc) (storage.Interface, factory.DestroyFunc) {
	return NewRawStorage(config)
}

// NewRawStorage creates the low level kv storage. This is a work-around for current
// two layer of same storage interface.
// TODO: Once cacher is enabled on all registries (event registry is special), we will remove this method.
func NewRawStorage(config *storagebackend.Config) (storage.Interface, factory.DestroyFunc) {
	s, d, err := factory.Create(*config)
	if err != nil {
		klog.Fatalf("Unable to create storage backend: config (%v), err (%v)", config, err)
	}
	return s, d
}
```

*kubernetes/staging/src/k8s.io/apiserver/pkg/storage/storagebackend/factory*

```go
// Create creates a storage backend based on given config.
func Create(c storagebackend.Config) (storage.Interface, DestroyFunc, error) {
	switch c.Type {
	case "etcd2":
		return nil, nil, fmt.Errorf("%v is no longer a supported storage backend", c.Type)
	case storagebackend.StorageTypeUnset, storagebackend.StorageTypeETCD3:
		return newETCD3Storage(c)
	default:
		return nil, nil, fmt.Errorf("unknown storage type: %s", c.Type)
	}
}

func newETCD3Storage(c storagebackend.Config) (storage.Interface, DestroyFunc, error) {
	stopCompactor, err := startCompactorOnce(c.Transport, c.CompactionInterval)
	if err != nil {
		return nil, nil, err
	}

	client, err := newETCD3Client(c.Transport)
	...
	transformer := c.Transformer
	if transformer == nil {
		transformer = value.IdentityTransformer
	}
	return etcd3.New(client, c.Codec, c.Prefix, transformer, c.Paging), destroyFunc, nil
}
```

*kubernetes/staging/src/k8s.io/apiserver/pkg/storage/etcd3/store.go*

`store` implemented all functions of `storage.Interface`

```go
// New returns an etcd3 implementation of storage.Interface.
func New(c *clientv3.Client, codec runtime.Codec, prefix string, transformer value.Transformer, pagingEnabled bool) storage.Interface {
	return newStore(c, pagingEnabled, codec, prefix, transformer)
}

func newStore(c *clientv3.Client, pagingEnabled bool, codec runtime.Codec, prefix string, transformer value.Transformer) *store {
	versioner := etcd.APIObjectVersioner{}
	result := &store{
		client:        c,
		codec:         codec,
		versioner:     versioner,
		transformer:   transformer,
		pagingEnabled: pagingEnabled,
		// for compatibility with etcd2 impl.
		// no-op for default prefix of '/registry'.
		// keeps compatibility with etcd2 impl for custom prefixes that don't start with '/'
		pathPrefix:   path.Join("/", prefix),
		watcher:      newWatcher(c, codec, versioner, transformer),
		leaseManager: newDefaultLeaseManager(c),
	}
	return result
}
```

## Get

```go
// Get implements storage.Interface.Get.
func (s *store) Get(ctx context.Context, key string, resourceVersion string, out runtime.Object, ignoreNotFound bool) error {
	...
	getResp, err := s.client.KV.Get(ctx, key, s.getOps...)
	...

	data, _, err := s.transformer.TransformFromStorage(kv.Value, authenticatedDataString(key))
	if err != nil {
		return storage.NewInternalError(err.Error())
	}

	return decode(s.codec, s.versioner, data, out, kv.ModRevision)
}
```
basical 3 steps,

1. get from etcd by etcdv3 client
2. transfom
	
	by default `IdentityTransformer` is used.
	
	*kubernetes/staging/src/k8s.io/apiserver/pkg/storage/value/encrypt/identity/identity.go*
	
	```go
	// identityTransformer performs no transformation on provided data, but validates
	// that the data is not encrypted data during TransformFromStorage
	type identityTransformer struct{}
	
	// NewEncryptCheckTransformer returns an identityTransformer which returns an error
	// on attempts to read encrypted data
	func NewEncryptCheckTransformer() value.Transformer {
		return identityTransformer{}
	}
	
	// TransformFromStorage returns the input bytes if the data is not encrypted
	func (identityTransformer) TransformFromStorage(b []byte, context value.Context) ([]byte, bool, error) {
		// identityTransformer has to return an error if the data is encoded using another transformer.
		// JSON data starts with '{'. Protobuf data has a prefix 'k8s[\x00-\xFF]'.
		// Prefix 'k8s:enc:' is reserved for encrypted data on disk.
		if bytes.HasPrefix(b, []byte("k8s:enc:")) {
			return []byte{}, false, fmt.Errorf("identity transformer tried to read encrypted data")
		}
		return b, false, nil
	}
	```
3. decode
	
	```go
	// decode decodes value of bytes into object. It will also set the object resource version to rev.
	// On success, objPtr would be set to the object.
	func decode(codec runtime.Codec, versioner storage.Versioner, value []byte, objPtr runtime.Object, rev int64) error {
		if _, err := conversion.EnforcePtr(objPtr); err != nil {
			panic("unable to convert output object to pointer")
		}
		_, _, err := codec.Decode(value, nil, objPtr)
		if err != nil {
			return err
		}
		// being unable to set the version does not prevent the object from being extracted
		versioner.UpdateObject(objPtr, uint64(rev))
		return nil
	}
	```
	it simple inovkes `codec.Decode`, recall form **02-master-config**. codec is `legacyscheme.Codecs`.
	
	*kubernetes/pkg/api/legacyscheme/scheme.go*
	
	```go
	package legacyscheme
	
	var (	
		// Codecs provides access to encoding and decoding for the scheme
		Codecs = serializer.NewCodecFactory(Scheme)
	)
	```
	Codecs is a CodecFactory which is a wrapper of Serializer.
	
	*kubernetes/staging/src/k8s.io/apimachinery/pkg/runtime/serializer/codec_factory.go*
	
	```go
	// support 3 serialier types: json, yaml, protobuf
	func newSerializersForScheme(scheme *runtime.Scheme, mf json.MetaFactory) []serializerType {
		jsonSerializer := json.NewSerializer(mf, scheme, scheme, false)
		jsonPrettySerializer := json.NewSerializer(mf, scheme, scheme, true)
		yamlSerializer := json.NewYAMLSerializer(mf, scheme, scheme)
		serializer := protobuf.NewSerializer(scheme, scheme)
		raw := protobuf.NewRawSerializer(scheme, scheme)
		...
	}

	// CodecFactory provides methods for retrieving codecs and serializers for specific
	// versions and content types.
	type CodecFactory struct {
		scheme      *runtime.Scheme
		serializers []serializerType
		universal   runtime.Decoder
		accepts     []runtime.SerializerInfo
	
		legacySerializer runtime.Serializer
	}
	
	func NewCodecFactory(scheme *runtime.Scheme) CodecFactory {
		serializers := newSerializersForScheme(scheme, json.DefaultMetaFactory)
		return newCodecFactory(scheme, serializers)
	}
	
	// newCodecFactory is a helper for testing that allows a different metafactory to be specified.
	func newCodecFactory(scheme *runtime.Scheme, serializers []serializerType) CodecFactory {
		...
	
		return CodecFactory{
			scheme:      scheme,
			serializers: serializers,
			universal:   recognizer.NewDecoder(decoders...),
			accepts: accepts,
			legacySerializer: legacySerializer,
		}
	}
	```
	
	protobuf is default type
	
	*kubernetes/staging/src/k8s.io/apimachinery/pkg/runtime/serializer/protobuf/protobuf.go*
	
	```go
	// Decode attempts to convert the provided data into a protobuf message, extract the stored schema kind, apply the provided default
	// gvk, and then load that data into an object matching the desired schema kind or the provided into. If into is *runtime.Unknown,
	// the raw data will be extracted and no decoding will be performed. If into is not registered with the typer, then the object will
	// be straight decoded using normal protobuf unmarshalling (the MarshalTo interface). If into is provided and the original data is
	// not fully qualified with kind/version/group, the type of the into will be used to alter the returned gvk. On success or most
	// errors, the method will return the calculated schema kind.
	func (s *Serializer) Decode(originalData []byte, gvk *schema.GroupVersionKind, into runtime.Object) (runtime.Object, *schema.GroupVersionKind, error) {
		if versioned, ok := into.(*runtime.VersionedObjects); ok {
			into = versioned.Last()
			obj, actual, err := s.Decode(originalData, gvk, into)
			if err != nil {
				return nil, actual, err
			}
			// the last item in versioned becomes into, so if versioned was not originally empty we reset the object
			// array so the first position is the decoded object and the second position is the outermost object.
			// if there were no objects in the versioned list passed to us, only add ourselves.
			if into != nil && into != obj {
				versioned.Objects = []runtime.Object{obj, into}
			} else {
				versioned.Objects = []runtime.Object{obj}
			}
			return versioned, actual, err
		}
		...
		return unmarshalToObject(s.typer, s.creater, &actual, into, unk.Raw)
	}
	```
	
## Create

```go
// Create implements storage.Interface.Create.
func (s *store) Create(ctx context.Context, key string, obj, out runtime.Object, ttl uint64) error {
	...
	data, err := runtime.Encode(s.codec, obj)
	...
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
	...
}
```

1. encode
2. transform
3. create

## Watch

```go
// Watch implements storage.Interface.Watch.
func (s *store) Watch(ctx context.Context, key string, resourceVersion string, pred storage.SelectionPredicate) (watch.Interface, error) {
	return s.watch(ctx, key, resourceVersion, pred, false)
}

// WatchList implements storage.Interface.WatchList.
func (s *store) WatchList(ctx context.Context, key string, resourceVersion string, pred storage.SelectionPredicate) (watch.Interface, error) {
	return s.watch(ctx, key, resourceVersion, pred, true)
}

func (s *store) watch(ctx context.Context, key string, rv string, pred storage.SelectionPredicate, recursive bool) (watch.Interface, error) {
	rev, err := s.versioner.ParseResourceVersion(rv)
	if err != nil {
		return nil, err
	}
	key = path.Join(s.pathPrefix, key)
	return s.watcher.Watch(ctx, key, int64(rev), recursive, pred)
}
```
*kubernetes/staging/src/k8s.io/apiserver/pkg/storage/etcd3/watcher.go*

etcd watch event -> incomingEventChan -> resultChan

```go
// Watch watches on a key and returns a watch.Interface that transfers relevant notifications.
// If rev is zero, it will return the existing object(s) and then start watching from
// the maximum revision+1 from returned objects.
// If rev is non-zero, it will watch events happened after given revision.
// If recursive is false, it watches on given key.
// If recursive is true, it watches any children and directories under the key, excluding the root key itself.
// pred must be non-nil. Only if pred matches the change, it will be returned.
func (w *watcher) Watch(ctx context.Context, key string, rev int64, recursive bool, pred storage.SelectionPredicate) (watch.Interface, error) {
	if recursive && !strings.HasSuffix(key, "/") {
		key += "/"
	}
	wc := w.createWatchChan(ctx, key, rev, recursive, pred)
	go wc.run()
	return wc, nil
}

func (w *watcher) createWatchChan(ctx context.Context, key string, rev int64, recursive bool, pred storage.SelectionPredicate) *watchChan {
	wc := &watchChan{
		watcher:           w,
		key:               key,
		initialRev:        rev,
		recursive:         recursive,
		internalPred:      pred,
		incomingEventChan: make(chan *event, incomingBufSize),
		resultChan:        make(chan watch.Event, outgoingBufSize),
		errChan:           make(chan error, 1),
	}
	if pred.Empty() {
		// The filter doesn't filter out any object.
		wc.internalPred = storage.Everything
	}
	wc.ctx, wc.cancel = context.WithCancel(ctx)
	return wc
}

// watchChan implements watch.Interface.
type watchChan struct {
	watcher           *watcher
	key               string
	initialRev        int64
	recursive         bool
	internalPred      storage.SelectionPredicate
	ctx               context.Context
	cancel            context.CancelFunc
	incomingEventChan chan *event
	resultChan        chan watch.Event
	errChan           chan error
}

func (wc *watchChan) run() {
	watchClosedCh := make(chan struct{})
	// invoke etcdclientv3 watch, save event to incomingEventChan
	go wc.startWatching(watchClosedCh)

	var resultChanWG sync.WaitGroup
	resultChanWG.Add(1)
	// get event from incomingEventChan and put it in resultChan
	go wc.processEvent(&resultChanWG)

	select {
	case err := <-wc.errChan:
		if err == context.Canceled {
			break
		}
		errResult := transformErrorToEvent(err)
		if errResult != nil {
			// error result is guaranteed to be received by user before closing ResultChan.
			select {
			case wc.resultChan <- *errResult:
			case <-wc.ctx.Done(): // user has given up all results
			}
		}
	case <-watchClosedCh:
	case <-wc.ctx.Done(): // user cancel
	}

	// We use wc.ctx to reap all goroutines. Under whatever condition, we should stop them all.
	// It's fine to double cancel.
	wc.cancel()

	// we need to wait until resultChan wouldn't be used anymore
	resultChanWG.Wait()
	close(wc.resultChan)
}

```	 

# StorageWithCacher

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
		...
	
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


## NewCacherFromConfig

cacher is generated from `NewCacherFromConfig`.

*kubernetes/staging/src/k8s.io/apiserver/pkg/storage/cacher/cacher.go*

```go
// NewCacherFromConfig creates a new Cacher responsible for servicing WATCH and LIST requests from
// its internal cache and updating its cache in the background based on the
// given configuration.
func NewCacherFromConfig(config Config) *Cacher {
	stopCh := make(chan struct{})
	obj := config.NewFunc()
	// Give this error when it is constructed rather than when you get the
	// first watch item, because it's much easier to track down that way.
	if err := runtime.CheckCodec(config.Codec, obj); err != nil {
		panic("storage codec doesn't seem to match given type: " + err.Error())
	}

	clock := clock.RealClock{}
	cacher := &Cacher{
		ready:       newReady(),
		storage:     config.Storage,
		objectType:  reflect.TypeOf(obj),
		versioner:   config.Versioner,
		newFunc:     config.NewFunc,
		triggerFunc: config.TriggerPublisherFunc,
		watcherIdx:  0,
		watchers: indexedWatchers{
			allWatchers:   make(map[int]*cacheWatcher),
			valueWatchers: make(map[string]watchersMap),
		},
		// TODO: Figure out the correct value for the buffer size.
		incoming:              make(chan watchCacheEvent, 100),
		dispatchTimeoutBudget: newTimeBudget(stopCh),
		// We need to (potentially) stop both:
		// - wait.Until go-routine
		// - reflector.ListAndWatch
		// and there are no guarantees on the order that they will stop.
		// So we will be simply closing the channel, and synchronizing on the WaitGroup.
		stopCh:               stopCh,
		clock:                clock,
		timer:                time.NewTimer(time.Duration(0)),
		bookmarkWatchers:     newTimeBucketWatchers(clock),
		watchBookmarkEnabled: utilfeature.DefaultFeatureGate.Enabled(features.WatchBookmark),
	}

	// Ensure that timer is stopped.
	if !cacher.timer.Stop() {
		// Consume triggered (but not yet received) timer event
		// so that future reuse does not get a spurious timeout.
		<-cacher.timer.C
	}

	watchCache := newWatchCache(
		config.CacheCapacity, config.KeyFunc, cacher.processEvent, config.GetAttrsFunc, config.Versioner)
	listerWatcher := NewCacherListerWatcher(config.Storage, config.ResourcePrefix, config.NewListFunc)
	reflectorName := "storage/cacher.go:" + config.ResourcePrefix

	reflector := cache.NewNamedReflector(reflectorName, listerWatcher, obj, watchCache, 0)
	// Configure reflector's pager to for an appropriate pagination chunk size for fetching data from
	// storage. The pager falls back to full list if paginated list calls fail due to an "Expired" error.
	reflector.WatchListPageSize = storageWatchListPageSize

	cacher.watchCache = watchCache
	cacher.reflector = reflector

	go cacher.dispatchEvents()

	cacher.stopWg.Add(1)
	go func() {
		defer cacher.stopWg.Done()
		defer cacher.terminateAllWatchers()
		wait.Until(
			func() {
				if !cacher.isStopped() {
					cacher.startCaching(stopCh)
				}
			}, time.Second, stopCh,
		)
	}()

	return cacher
}
```

### Cacher
*kubernetes/staging/src/k8s.io/apiserver/pkg/storage/cacher/cacher.go*

* watchCache: cache layer
* storage: underlying layer, `UndecoratedStorage`
* watcher: watch object from storage
* relector: put resutl from watcher to watchCache 
  
```go
// Cacher is responsible for serving WATCH and LIST requests for a given
// resource from its internal cache and updating its cache in the background
// based on the underlying storage contents.
// Cacher implements storage.Interface (although most of the calls are just
// delegated to the underlying storage).
type Cacher struct {
	// HighWaterMarks for performance debugging.
	// Important: Since HighWaterMark is using sync/atomic, it has to be at the top of the struct due to a bug on 32-bit platforms
	// See: https://golang.org/pkg/sync/atomic/ for more information
	incomingHWM storage.HighWaterMark
	// Incoming events that should be dispatched to watchers.
	incoming chan watchCacheEvent

	sync.RWMutex

	// Before accessing the cacher's cache, wait for the ready to be ok.
	// This is necessary to prevent users from accessing structures that are
	// uninitialized or are being repopulated right now.
	// ready needs to be set to false when the cacher is paused or stopped.
	// ready needs to be set to true when the cacher is ready to use after
	// initialization.
	ready *ready

	// Underlying storage.Interface.
	storage storage.Interface

	// Expected type of objects in the underlying cache.
	objectType reflect.Type

	// "sliding window" of recent changes of objects and the current state.
	watchCache *watchCache
	reflector  *cache.Reflector

	// Versioner is used to handle resource versions.
	versioner storage.Versioner
	
	// watchers is mapping from the value of trigger function that a
	// watcher is interested into the watchers
	watcherIdx int
	watchers   indexedWatchers

	...
}
```

#### watchCache

it uses [client-go cache.Store](k8s.io/client-go/tools/cache) for caching and implements storage.Interface.

*kubernetes/staging/src/k8s.io/apiserver/pkg/storage/cacher/watch_cache.go*

* cache is for events(Get, Add ...)
* store is for objects

```go
type watchCache struct {
	...
	// Condition on which lists are waiting for the fresh enough
	// resource version.
	cond *sync.Cond
	...
	// cache is used a cyclic buffer - its first element (with the smallest
	// resourceVersion) is defined by startIndex, its last element is defined
	// by endIndex (if cache is full it will be startIndex + capacity).
	// Both startIndex and endIndex can be greater than buffer capacity -
	// you should always apply modulo capacity to get an index in cache array.
	
	cache      []*watchCacheEvent
	startIndex int
	endIndex   int

	// store will effectively support LIST operation from the "end of cache
	// history" i.e. from the moment just after the newest cached watched event.
	// It is necessary to effectively allow clients to start watching at now.
	// NOTE: We assume that <store> is thread-safe.
	store cache.Store

	...
	eventHandler func(*watchCacheEvent)
}

func newWatchCache(
	capacity int,
	keyFunc func(runtime.Object) (string, error),
	eventHandler func(*watchCacheEvent),
	getAttrsFunc func(runtime.Object) (labels.Set, fields.Set, error),
	versioner storage.Versioner) *watchCache {
	wc := &watchCache{
		capacity:            capacity,
		keyFunc:             keyFunc,
		getAttrsFunc:        getAttrsFunc,
		cache:               make([]*watchCacheEvent, capacity),
		startIndex:          0,
		endIndex:            0,
		store:               cache.NewStore(storeElementKey),
		resourceVersion:     0,
		listResourceVersion: 0,
		eventHandler:        eventHandler,
		clock:               clock.RealClock{},
		versioner:           versioner,
	}
	wc.cond = sync.NewCond(wc.RLocker())
	return wc
}
```

#### Reflector
*kubernetes/staging/src/k8s.io/client-go/tools/cache/reflector.go*

```go
// Reflector watches a specified resource and causes all changes to be reflected in the given store.
type Reflector struct {
	// name identifies this reflector. By default it will be a file:line if possible.
	name string
	// metrics tracks basic metric information about the reflector
	metrics *reflectorMetrics

	// The type of object we expect to place in the store.
	expectedType reflect.Type
	// The destination to sync up with the watch source
	store Store
	// listerWatcher is used to perform lists and watches.
	listerWatcher ListerWatcher
	...
}

```
reflector initializatin

```go
listerWatcher := NewCacherListerWatcher(config.Storage, config.ResourcePrefix, config.NewListFunc)
reflectorName := "storage/cacher.go:" + config.ResourcePrefix

reflector := cache.NewNamedReflector(reflectorName, listerWatcher, obj, watchCache, 0)

// NewNamedReflector same as NewReflector, but with a specified name for logging
func NewNamedReflector(name string, lw ListerWatcher, expectedType interface{}, store Store, resyncPeriod time.Duration) *Reflector {
	r := &Reflector{
		name:          name,
		listerWatcher: lw,
		store:         store,
		expectedType:  reflect.TypeOf(expectedType),
		period:        time.Second,
		resyncPeriod:  resyncPeriod,
		clock:         &clock.RealClock{},
	}
	return r
}
```
listWacher

```go
// cacherListerWatcher opaques storage.Interface to expose cache.ListerWatcher.
type cacherListerWatcher struct {
	storage        storage.Interface
	resourcePrefix string
	newListFunc    func() runtime.Object
}

// NewCacherListerWatcher returns a storage.Interface backed ListerWatcher.
func NewCacherListerWatcher(storage storage.Interface, resourcePrefix string, newListFunc func() runtime.Object) cache.ListerWatcher {
	return &cacherListerWatcher{
		storage:        storage,
		resourcePrefix: resourcePrefix,
		newListFunc:    newListFunc,
	}
}
```

### startCaching

caching is started when creating Cacher.

* stop all watchers
* start ListAndWatch

```go
func (c *Cacher) startCaching(stopChannel <-chan struct{}) {
	...
	c.terminateAllWatchers()
	if err := c.reflector.ListAndWatch(stopChannel); err != nil {
		klog.Errorf("unexpected ListAndWatch error: %v", err)
	}
}
```

#### reflector.ListAndWatch

```go
// ListAndWatch first lists all items and get the resource version at the moment of call,
// and then use the resource version to watch.
// It returns error if ListAndWatch didn't even try to initialize watch.
func (r *Reflector) ListAndWatch(stopCh <-chan struct{}) error {
	klog.V(3).Infof("Listing and watching %v from %s", r.expectedType, r.name)
	var resourceVersion string

	// Explicitly set "0" as resource version - it's fine for the List()
	// to be served from cache and potentially be delayed relative to
	// etcd contents. Reflector framework will catch up via Watch() eventually.
	options := metav1.ListOptions{ResourceVersion: "0"}
	
	# list
	if err := func() error {
		initTrace := trace.New("Reflector " + r.name + " ListAndWatch")
		defer initTrace.LogIfLong(10 * time.Second)
		var list runtime.Object
		var err error
		listCh := make(chan struct{}, 1)
		panicCh := make(chan interface{}, 1)
		# list
		go func() {
			defer func() {
				if r := recover(); r != nil {
					panicCh <- r
				}
			}()
			// Attempt to gather list in chunks, if supported by listerWatcher, if not, the first
			// list request will return the full response.
			pager := pager.New(pager.SimplePageFunc(func(opts metav1.ListOptions) (runtime.Object, error) {
				return r.listerWatcher.List(opts)
			}))
			if r.WatchListPageSize != 0 {
				pager.PageSize = r.WatchListPageSize
			}
			// Pager falls back to full list if paginated list calls fail due to an "Expired" error.
			list, err = pager.List(context.Background(), options)
			close(listCh)
		}()
		select {
		case <-stopCh:
			return nil
		case r := <-panicCh:
			panic(r)
		case <-listCh:
		}
		...
	}(); err != nil {
		return err
	}
	
	...
	
	
	# watch
	for {
		...

		w, err := r.listerWatcher.Watch(options)
		...

		if err := r.watchHandler(w, &resourceVersion, resyncerrc, stopCh); err != nil {
			if err != errorStopRequested {
				klog.Warningf("%s: watch of %v ended with: %v", r.name, r.expectedType, err)
			}
			return nil
		}
	}
}
```

#### listerWatcher List and Watch
it simply calls storage List and Watch functions,

storage is `UndecoratedStorage`, so it eventually calls etcdv3 clietn list and watch functions as I alreadly described above.

```go
// Implements cache.ListerWatcher interface.
func (lw *cacherListerWatcher) List(options metav1.ListOptions) (runtime.Object, error) {
	list := lw.newListFunc()
	pred := storage.SelectionPredicate{
		Label:    labels.Everything(),
		Field:    fields.Everything(),
		Limit:    options.Limit,
		Continue: options.Continue,
	}

	if err := lw.storage.List(context.TODO(), lw.resourcePrefix, "", pred, list); err != nil {
		return nil, err
	}
	return list, nil
}

// Implements cache.ListerWatcher interface.
func (lw *cacherListerWatcher) Watch(options metav1.ListOptions) (watch.Interface, error) {
	return lw.storage.WatchList(context.TODO(), lw.resourcePrefix, options.ResourceVersion, storage.Everything)
}
```

#### watchHandler

1. get result from `UndecoratedStorage` resultChan.
2. check event type
3. call `watchCache` event handlers

```go
// watchHandler watches w and keeps *resourceVersion up to date.
func (r *Reflector) watchHandler(w watch.Interface, resourceVersion *string, errc chan error, stopCh <-chan struct{}) error {
	...

loop:
	for {
		select {
		case <-stopCh:
			return errorStopRequested
		case err := <-errc:
			return err
		case event, ok := <-w.ResultChan():
			...
			switch event.Type {
			case watch.Added:
				err := r.store.Add(event.Object)
				if err != nil {
					utilruntime.HandleError(fmt.Errorf("%s: unable to add watch event object (%#v) to store: %v", r.name, event.Object, err))
				}
			case watch.Modified:
				err := r.store.Update(event.Object)
				if err != nil {
					utilruntime.HandleError(fmt.Errorf("%s: unable to update watch event object (%#v) to store: %v", r.name, event.Object, err))
				}
			case watch.Deleted:
				// TODO: Will any consumers need access to the "last known
				// state", which is passed in event.Object? If so, may need
				// to change this.
				err := r.store.Delete(event.Object)
				if err != nil {
					utilruntime.HandleError(fmt.Errorf("%s: unable to delete watch event object (%#v) from store: %v", r.name, event.Object, err))
				}
			case watch.Bookmark:
				// A `Bookmark` means watch has synced here, just update the resourceVersion
			default:
				utilruntime.HandleError(fmt.Errorf("%s: unable to understand watch event %#v", r.name, event))
			}
			*resourceVersion = newResourceVersion
			r.setLastSyncResourceVersion(newResourceVersion)
			eventCount++
		}
	}

	watchDuration := r.clock.Since(start)
	if watchDuration < 1*time.Second && eventCount == 0 {
		return fmt.Errorf("very short watch: %s: Unexpected watch close - watch lasted less than a second and no items received", r.name)
	}
	klog.V(4).Infof("%s: Watch close - %v total %v items received", r.name, r.expectedType, eventCount)
	return nil
}
```

#### processEvent

1. extract data from watch event
2. construct watchCacheEvent
3. update wachCache store and cache
4. add watchCacheEvent to `incoming` channel

```go
// Add takes runtime.Object as an argument.
func (w *watchCache) Add(obj interface{}) error {
	object, resourceVersion, err := w.objectToVersionedRuntimeObject(obj)
	if err != nil {
		return err
	}
	event := watch.Event{Type: watch.Added, Object: object}

	f := func(elem *storeElement) error { return w.store.Add(elem) }
	return w.processEvent(event, resourceVersion, f)
}

// processEvent is safe as long as there is at most one call to it in flight
// at any point in time.
func (w *watchCache) processEvent(event watch.Event, resourceVersion uint64, updateFunc func(*storeElement) error) error {
	...
	
	// consturct watchEvent from event
	watchCacheEvent := &watchCacheEvent{
		Type:            event.Type,
		Object:          elem.Object,
		ObjLabels:       elem.Labels,
		ObjFields:       elem.Fields,
		Key:             key,
		ResourceVersion: resourceVersion,
	}

	if err := func() error {
		...

		/* 
			add event to cache,
			w.cache[w.endIndex%w.capacity] = event
		*/
		w.updateCache(watchCacheEvent)
		w.resourceVersion = resourceVersion
		defer w.cond.Broadcast()
		/*
			update cache.Store, for add event, add this object to store
			func(elem *storeElement) error { return w.store.Add(elem) } 
		*/
		return updateFunc(elem)
	}(); err != nil {
		return err
	}

	/*
		call catcher eventHandler,
		eventHandler is Cacher processEvent function.
	*/
	if w.eventHandler != nil {
		w.eventHandler(watchCacheEvent)
	}
	return nil
}

func (c *Cacher) processEvent(event *watchCacheEvent) {
	if curLen := int64(len(c.incoming)); c.incomingHWM.Update(curLen) {
		// Monitor if this gets backed up, and how much.
		klog.V(1).Infof("cacher (%v): %v objects queued in incoming channel.", c.objectType.String(), curLen)
	}
	c.incoming <- *event
}
```

### dispatchEvents

starWatching adds events to `incoming` channle, dispatchEvents is the consumer.

```go
func (c *Cacher) dispatchEvents() {
	// Jitter to help level out any aggregate load.
	bookmarkTimer := c.clock.NewTimer(wait.Jitter(time.Second, 0.25))
	// Stop the timer when watchBookmarkFeatureGate is not enabled.
	if !c.watchBookmarkEnabled && !bookmarkTimer.Stop() {
		<-bookmarkTimer.C()
	}
	defer bookmarkTimer.Stop()

	lastProcessedResourceVersion := uint64(0)
	for {
		select {
		case event, ok := <-c.incoming:
			if !ok {
				return
			}
			c.dispatchEvent(&event)
			lastProcessedResourceVersion = event.ResourceVersion
		case <-bookmarkTimer.C():
			bookmarkTimer.Reset(wait.Jitter(time.Second, 0.25))
			// Never send a bookmark event if we did not see an event here, this is fine
			// because we don't provide any guarantees on sending bookmarks.
			if lastProcessedResourceVersion == 0 {
				continue
			}
			bookmarkEvent := &watchCacheEvent{
				Type:            watch.Bookmark,
				Object:          c.newFunc(),
				ResourceVersion: lastProcessedResourceVersion,
			}
			if err := c.versioner.UpdateObject(bookmarkEvent.Object, bookmarkEvent.ResourceVersion); err != nil {
				klog.Errorf("failure to set resourceVersion to %d on bookmark event %+v", bookmarkEvent.ResourceVersion, bookmarkEvent.Object)
				continue
			}
			c.dispatchEvent(bookmarkEvent)
		case <-c.stopCh:
			return
		}
	}
}
```

#### dispatchEvent
put `watchCacheEvent` to all watchers in Cacher. its consumer is `Cacher Watch` function which will be described below.

```go
func (c *Cacher) dispatchEvent(event *watchCacheEvent) {
	c.startDispatching(event)
	defer c.finishDispatching()
	// Watchers stopped after startDispatching will be delayed to finishDispatching,

	// Since add() can block, we explicitly add when cacher is unlocked.
	if event.Type == watch.Bookmark {
		for _, watcher := range c.watchersBuffer {
			watcher.nonblockingAdd(event)
		}
	} else {
		for _, watcher := range c.watchersBuffer {
			watcher.add(event, c.timer, c.dispatchTimeoutBudget)
		}
	}
}

// startDispatching chooses watchers potentially interested in a given event
// a marks dispatching as true.
func (c *Cacher) startDispatching(event *watchCacheEvent) {
	...

	// Iterate over "allWatchers" no matter what the trigger function is.
	for _, watcher := range c.watchers.allWatchers {
		c.watchersBuffer = append(c.watchersBuffer, watcher)
	}
	...
}

func (c *cacheWatcher) nonblockingAdd(event *watchCacheEvent) bool {
	// If we can't send it, don't block on it.
	select {
	case c.input <- event:
		return true
	default:
		return false
	}
}

func (c *cacheWatcher) add(event *watchCacheEvent, timer *time.Timer, budget *timeBudget) {
	// Try to send the event immediately, without blocking.
	if c.nonblockingAdd(event) {
		return
	}

	// OK, block sending, but only for up to <timeout>.
	// cacheWatcher.add is called very often, so arrange
	// to reuse timers instead of constantly allocating.
	startTime := time.Now()
	timeout := budget.takeAvailable()

	timer.Reset(timeout)

	select {
	case c.input <- event:
		if !timer.Stop() {
			// Consume triggered (but not yet received) timer event
			// so that future reuse does not get a spurious timeout.
			<-timer.C
		}
	case <-timer.C:
		// This means that we couldn't send event to that watcher.
		// Since we don't want to block on it infinitely,
		// we simply terminate it.
		klog.V(1).Infof("Forcing watcher close due to unresponsiveness: %v", reflect.TypeOf(event.Object).String())
		c.forget()
	}

	budget.returnUnused(timeout - time.Since(startTime))
}

```

## functions
write functions are same with `UndecoratedStorage` functions

### Get

* if cache not ready or version not specified, get from underlying
* otherwise get from watchCache store

```go
// Get implements storage.Interface.
func (c *Cacher) Get(ctx context.Context, key string, resourceVersion string, objPtr runtime.Object, ignoreNotFound bool) error {
	if resourceVersion == "" {
		// If resourceVersion is not specified, serve it from underlying
		// storage (for backward compatibility).
		return c.storage.Get(ctx, key, resourceVersion, objPtr, ignoreNotFound)
	}

	...

	obj, exists, readResourceVersion, err := c.watchCache.WaitUntilFreshAndGet(getRV, key, nil)
	...
}

// WaitUntilFreshAndGet returns a pointers to <storeElement> object.
func (w *watchCache) WaitUntilFreshAndGet(resourceVersion uint64, key string, trace *utiltrace.Trace) (interface{}, bool, uint64, error) {
	err := w.waitUntilFreshAndBlock(resourceVersion, trace)
	defer w.RUnlock()
	if err != nil {
		return nil, false, 0, err
	}
	value, exists, err := w.store.GetByKey(key)
	return value, exists, w.resourceVersion, err
}
```

### Watch
every time `Watch` function is invoked, it adds a new watcher to watchers.
As I explained above, `dispatchEvent` publishes events to all watchers. 

```go
// Watch implements storage.Interface.
func (c *Cacher) Watch(ctx context.Context, key string, resourceVersion string, pred storage.SelectionPredicate) (watch.Interface, error) {
	watchRV, err := c.versioner.ParseResourceVersion(resourceVersion)
	if err != nil {
		return nil, err
	}

	c.ready.wait()

	...
	watcher := newCacheWatcher(chanSize, filterWithAttrsFunction(key, pred), emptyFunc, c.versioner, deadline, pred.AllowWatchBookmarks, c.objectType)

	...

	func() {
		c.Lock()
		defer c.Unlock()
		// Update watcher.forget function once we can compute it.
		watcher.forget = forgetWatcher(c, c.watcherIdx, triggerValue, triggerSupported)
		c.watchers.addWatcher(watcher, c.watcherIdx, triggerValue, triggerSupported)

		// Add it to the queue only when server and client support watch bookmarks.
		if c.watchBookmarkEnabled && watcher.allowWatchBookmarks {
			c.bookmarkWatchers.addWatcher(watcher)
		}
		c.watcherIdx++
	}()

	go watcher.process(ctx, initEvents, watchRV)
	return watcher, nil
}
```

#### newCacheWatcher

```go
// cacheWatcher implements watch.Interface
type cacheWatcher struct {
	sync.Mutex
	input     chan *watchCacheEvent
	result    chan watch.Event
	done      chan struct{}
	filter    filterWithAttrsFunc
	stopped   bool
	forget    func()
	versioner storage.Versioner
	// The watcher will be closed by server after the deadline,
	// save it here to send bookmark events before that.
	deadline            time.Time
	allowWatchBookmarks bool
	// Object type of the cache watcher interests
	objectType reflect.Type
}

func newCacheWatcher(chanSize int, filter filterWithAttrsFunc, forget func(), versioner storage.Versioner, deadline time.Time, allowWatchBookmarks bool, objectType reflect.Type) *cacheWatcher {
	return &cacheWatcher{
		input:               make(chan *watchCacheEvent, chanSize),
		result:              make(chan watch.Event, chanSize),
		done:                make(chan struct{}),
		filter:              filter,
		stopped:             false,
		forget:              forget,
		versioner:           versioner,
		deadline:            deadline,
		allowWatchBookmarks: allowWatchBookmarks,
		objectType:          objectType,
	}
}
```

#### watcher.process
event is sent to `cacheWatcher.result` channel.

```go
func (c *cacheWatcher) process(ctx context.Context, initEvents []*watchCacheEvent, resourceVersion uint64) {
	...

	defer close(c.result)
	defer c.Stop()
	for {
		select {
		case event, ok := <-c.input:
			if !ok {
				return
			}
			// only send events newer than resourceVersion
			if event.ResourceVersion > resourceVersion {
				c.sendWatchCacheEvent(event)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (c *cacheWatcher) sendWatchCacheEvent(event *watchCacheEvent) {
	watchEvent := c.convertToWatchEvent(event)
	...
	select {
	case <-c.done:
		return
	default:
	}

	select {
	case c.result <- *watchEvent:
	case <-c.done:
	}
}
```

#### end consumer
so who is the consumer of `cacheWatcher.result`?

this time start from http handler. 

```go
case "LIST": // List all resources of a kind.
			doc := "list objects of kind " + kind
			if isSubresource {
				doc = "list " + subresource + " of objects of kind " + kind
			}
			handler := metrics.InstrumentRouteFunc(action.Verb, group, version, resource, subresource, requestScope, metrics.APIServerComponent, restfulListResource(lister, watcher, reqScope, false, a.minRequestTimeout))
			
			
func restfulListResource(r rest.Lister, rw rest.Watcher, scope handlers.RequestScope, forceWatch bool, minRequestTimeout time.Duration) restful.RouteFunction {
	return func(req *restful.Request, res *restful.Response) {
		handlers.ListResource(r, rw, &scope, forceWatch, minRequestTimeout)(res.ResponseWriter, req.Request)
	}
}
```
dive into ListResource, rw is the store which is mentioned in **06-request-handler**. 

```go
func ListResource(r rest.Lister, rw rest.Watcher, scope *RequestScope, forceWatch bool, minRequestTimeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		...
		
		if opts.Watch || forceWatch {
			if rw == nil {
				scope.err(errors.NewMethodNotSupported(scope.Resource.GroupResource(), "watch"), w, req)
				return
			}
			..
			watcher, err := rw.Watch(ctx, &opts)
			if err != nil {
				scope.err(err, w, req)
				return
			}
			requestInfo, _ := request.RequestInfoFrom(ctx)
			metrics.RecordLongRunning(req, requestInfo, metrics.APIServerComponent, func() {
				serveWatch(watcher, scope, outputMediaType, req, w, timeout)
			})
			return
		}

		...
	}
}

```

events finally go to serveWatch.

```go
// serveWatch will serve a watch response.
// TODO: the functionality in this method and in WatchServer.Serve is not cleanly decoupled.
func serveWatch(watcher watch.Interface, scope *RequestScope, mediaTypeOptions negotiation.MediaTypeOptions, req *http.Request, w http.ResponseWriter, timeout time.Duration) {
	...
	server := &WatchServer{
		Watching: watcher,
		Scope:    scope,
		...
	}

	server.ServeHTTP(w, req)
}

// ServeHTTP serves a series of encoded events via HTTP with Transfer-Encoding: chunked
// or over a websocket connection.
func (s *WatchServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	...
	var unknown runtime.Unknown
	internalEvent := &metav1.InternalEvent{}
	outEvent := &metav1.WatchEvent{}
	buf := &bytes.Buffer{}
	ch := s.Watching.ResultChan()
	for {
		select {
		case <-cn.CloseNotify():
			return
		case <-timeoutCh:
			return
		case event, ok := <-ch:
			if !ok {
				// End of results.
				return
			}
			...
			buf.Reset()
		}
	}
}
```
