# Table of contents
1. [overview](#overview)




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

## Delete

## List

## Watch
	 

# StorageWithCache
