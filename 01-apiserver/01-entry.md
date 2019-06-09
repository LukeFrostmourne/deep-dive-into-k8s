# main
*cmd/kube-apiserver/apiserver.go*

```go
func main() {
	rand.Seed(time.Now().UnixNano())
	
	// generate start command
	command := app.NewAPIServerCommand()
	logs.InitLogs()
	// make sure logs are always recorded even apiserver crash
	defer logs.FlushLogs()

	if err := command.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
```
# start apiserver
*cmd/kube-apiserver/app/server.go*

```go
// use cobra to generate CLI
func NewAPIServerCommand() *cobra.Command {
   	s := options.NewServerRunOptions()
	cmd := &cobra.Command{
		Use: "kube-apiserver",
		...
		RunE: func(cmd *cobra.Command, args []string) error {
			...
			// set default options
			completedOptions, err := Complete(s)
			...
			// call Run when calling cmd.Execute()
			return Run(completedOptions, genericapiserver.SetupSignalHandler())
		},
	}

	fs := cmd.Flags()
	namedFlagSets := s.Flags()
	verflag.AddFlags(namedFlagSets.FlagSet("global"))
	globalflag.AddGlobalFlags(namedFlagSets.FlagSet("global"), cmd.Name())
	options.AddCustomGlobalFlags(namedFlagSets.FlagSet("generic"))
	for _, f := range namedFlagSets.FlagSets {
		fs.AddFlagSet(f)
	}

	usageFmt := "Usage:\n  %s\n"
	cols, _, _ := term.TerminalSize(cmd.OutOrStdout())
	cmd.SetUsageFunc(func(cmd *cobra.Command) error {
		fmt.Fprintf(cmd.OutOrStderr(), usageFmt, cmd.UseLine())
		cliflag.PrintSections(cmd.OutOrStderr(), namedFlagSets, cols)
		return nil
	})
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n\n"+usageFmt, cmd.Long, cmd.UseLine())
		cliflag.PrintSections(cmd.OutOrStdout(), namedFlagSets, cols)
	})

	return cmd
}

// Run starts apiserver and takes a channel as parameter,
// it will stop apiserver when reciving stop signal.
func Run(completeOptions completedServerRunOptions, stopCh <-chan struct{}) error {
   ...
	server, err := CreateServerChain(completeOptions, stopCh)
	...
	return server.PrepareRun().Run(stopCh)
}

// it creates a GenericAPIServer object which is defined in
// k8s.io/apiserver/pkg/server/genericapiserver.go.
// GenericAPIServer represents a running apiserver which contains state. 
func CreateServerChain(completedOptions completedServerRunOptions, stopCh <-chan struct{}) (*genericapiserver.GenericAPIServer, error) {
	// SSH tunnels are currently deprecated 
	nodeTunneler, proxyTransport, err := CreateNodeDialer(completedOptions)
	...
	// generate apiserver configuration
	kubeAPIServerConfig, insecureServingInfo, serviceResolver, pluginInitializer, admissionPostStartHook, err := CreateKubeAPIServerConfig(completedOptions, nodeTunneler, proxyTransport)
	
	// create master object(pkg/master/master.go) which represents the kube-apiserver.
	kubeAPIServer, err := CreateKubeAPIServer(kubeAPIServerConfig, apiExtensionsServer.GenericAPIServer, admissionPostStartHook)
	...
	return aggregatorServer.GenericAPIServer, nil
}

func CreateKubeAPIServerConfig(
	s completedServerRunOptions,
	nodeTunneler tunneler.Tunneler,
	proxyTransport *http.Transport,
) (
	config *master.Config,
	insecureServingInfo *genericapiserver.DeprecatedInsecureServingInfo,
	serviceResolver aggregatorapiserver.ServiceResolver,
	pluginInitializers []admission.PluginInitializer,
	admissionPostStartHook genericapiserver.PostStartHookFunc,
	lastErr error,
) {
	...
	/*
		genericConfig: apiserver configuration including requestTimeout, maxBodySize, authenticator and authorizator .etc ,
			defined in k8s.io/apiserver/pkg/server/config.go.
		versionedInformers: client go informer with 10 mins sync duration.
		insecureServingInfo: http server info.
		serviceResolver: a interface to create service url,
			defined in k8s.io/apiserver/pkg/util/webhook/serviceresolver.go
		pluginInitializers, admissionPostStartHook: to enable default admission plugin.
		storageFactory: storage configuration including etcd options.
	*/
	genericConfig, versionedInformers, insecureServingInfo, serviceResolver, pluginInitializers, admissionPostStartHook, storageFactory, lastErr = buildGenericConfig(s.ServerRunOptions, proxyTransport)
	...
	
	// check etcd connectivity
	if _, port, err := net.SplitHostPort(s.Etcd.StorageConfig.Transport.ServerList[0]); err == nil && port != "0" && len(port) != 0 {
		if err := utilwait.PollImmediate(etcdRetryInterval, etcdRetryLimit*etcdRetryInterval, preflight.EtcdConnection{ServerList: s.Etcd.StorageConfig.Transport.ServerList}.CheckEtcdServers); err != nil {
			lastErr = fmt.Errorf("error waiting for etcd connection: %v", err)
			return
		}
	}
	
	// get service ip range, certificate information from server options
	...
	
	config = &master.Config{
		GenericConfig: genericConfig,
		ExtraConfig: master.ExtraConfig{
			...
		},
	}
	return
}

```
