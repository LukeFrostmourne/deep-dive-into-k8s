# Cluster-autoscaler Architecture

# Overview



Once CA starts it runs a metrics handler to serve and metrics and two go-routines  to do scaling job by using `StaticAutoscaler` , also it’s using client-go for leader election. You can run multiple replicas but only one is active.

```go
func main() {
	...

	go func() {
		pathRecorderMux := mux.NewPathRecorderMux("cluster-autoscaler")
		defaultMetricsHandler := legacyregistry.Handler().ServeHTTP
		pathRecorderMux.HandleFunc("/metrics", func(w http.ResponseWriter, req *http.Request) {
			defaultMetricsHandler(w, req)
		})
		...
	}()

	if !leaderElection.LeaderElect {
		run(healthCheck, debuggingSnapshotter)
	} else {
		...
	}
}

func run(healthCheck *metrics.HealthCheck, debuggingSnapshotter debuggingsnapshot.DebuggingSnapshotter) {
	autoscaler, err := buildAutoscaler(debuggingSnapshotter)
	...
	if err := autoscaler.Start(); err != nil {
		klog.Fatalf("Failed to autoscaler background components: %v", err)
	}

	// Autoscale ad infinitum.
	for {
		select {
		case <-time.After(*scanInterval):
			{
				err := autoscaler.RunOnce(loopStart)
				....
			}
		}
	}
}
```

# Nodegroups Caching

The scaler is a `StaticAutoscaler` object, eventually it invokes `ClusterStateRegistry.Start()` 

```go
// NewStaticAutoscaler creates an instance of Autoscaler filled with provided parameters
func NewStaticAutoscaler(
	opts config.AutoscalingOptions,
	...) *StaticAutoscaler {
	...
	clusterStateRegistry := clusterstate.NewClusterStateRegistry(autoscalingContext.CloudProvider, clusterStateConfig, autoscalingContext.LogRecorder, backoff)
	...
}

func (a *StaticAutoscaler) Start() error {
	a.clusterStateRegistry.Start()
	return nil
}

func (csr *ClusterStateRegistry) Start() {
	csr.cloudProviderNodeInstancesCache.Start(csr.interrupt)
}
```

ClusterStateRegistry is a structure to keep track the current state of the cluster.

```go
type ClusterStateRegistry struct {
	...
	cloudProviderNodeInstances         map[string][]cloudprovider.Instance
	previousCloudProviderNodeInstances map[string][]cloudprovider.Instance
	cloudProviderNodeInstancesCache    *utils.CloudProviderNodeInstancesCache
	...
}

func NewClusterStateRegistry(cloudProvider cloudprovider.CloudProvider, config ClusterStateRegistryConfig, logRecorder *utils.LogEventRecorder, backoff backoff.Backoff) *ClusterStateRegistry {
	...

	return &ClusterStateRegistry{
		...
		cloudProviderNodeInstancesCache: utils.NewCloudProviderNodeInstancesCache(cloudProvider),
		...
	}
}
```

## AWSCloudProvider

provider is decided by flag

```go
cloudProviderFlag        = flag.String("cloud-provider", cloudBuilder.DefaultCloudProvider,
		"Cloud provider type. Available values: ["+strings.Join(cloudBuilder.AvailableCloudProviders, ",")+"]")
```

each provider must implement CloudProvider interface, we are using the AWS provider.

```go
// NewAutoscaler creates an autoscaler of an appropriate type according to the parameters
func NewAutoscaler(opts AutoscalerOptions) (Autoscaler, errors.AutoscalerError) {
	err := initializeDefaultOptions(&opts)
	if err != nil {
		return nil, errors.ToAutoscalerError(errors.InternalError, err)
	}
	return NewStaticAutoscaler(
		...
		opts.CloudProvider,
		...
		opts.DebuggingSnapshotter), nil
}

// Initialize default options if not provided.
func initializeDefaultOptions(opts *AutoscalerOptions) error {
	...
	if opts.CloudProvider == nil {
		opts.CloudProvider = cloudBuilder.NewCloudProvider(opts.AutoscalingOptions)
	}
	...
}

// BuildAwsCloudProvider builds CloudProvider implementation for AWS.
func BuildAwsCloudProvider(awsManager *AwsManager, resourceLimiter *cloudprovider.ResourceLimiter) (cloudprovider.CloudProvider, error) {
	aws := &awsCloudProvider{
		awsManager:      awsManager,
		resourceLimiter: resourceLimiter,
	}
	return aws, nil
}
// awsCloudProvider implements CloudProvider interface.
type awsCloudProvider struct {
	awsManager      *AwsManager
	resourceLimiter *cloudprovider.ResourceLimiter
}

```

## CloudProviderNodeInstancesCache

It keeps a cache of EC2 instances of each nodegroup.

```go
type cloudProviderNodeInstancesCacheEntry struct {
	instances   []cloudprovider.Instance
	refreshTime time.Time
}

// CloudProviderNodeInstancesCache caches cloud provider node instances.
type CloudProviderNodeInstancesCache struct {
	sync.Mutex
	cloudProviderNodeInstances map[string]*cloudProviderNodeInstancesCacheEntry
	cloudProvider              cloudprovider.CloudProvider
}

// NewCloudProviderNodeInstancesCache creates new cache instance.
func NewCloudProviderNodeInstancesCache(cloudProvider cloudprovider.CloudProvider) *CloudProviderNodeInstancesCache {
	return &CloudProviderNodeInstancesCache{
		cloudProviderNodeInstances: map[string]*cloudProviderNodeInstancesCacheEntry{},
		cloudProvider:              cloudProvider,
	}
}
```

The Start function simply refreshes the cache.

```go
// Refresh refreshes cache.
func (cache *CloudProviderNodeInstancesCache) Refresh() {
	klog.Infof("Start refreshing cloud provider node instances cache")
	refreshStart := time.Now()

	nodeGroups := cache.cloudProvider.NodeGroups()
	cache.removeEntriesForNonExistingNodeGroupsLocked(nodeGroups)
	for _, nodeGroup := range nodeGroups {
		nodeGroupInstances, err := nodeGroup.Nodes()
		if err != nil {
			klog.Errorf("Failed to get cloud provider node instance for node group %v, error %v", nodeGroup.Id(), err)
		}
		cache.updateCacheEntryLocked(nodeGroup, &cloudProviderNodeInstancesCacheEntry{nodeGroupInstances, time.Now()})
	}
	klog.Infof("Refresh cloud provider node instances cache finished, refresh took %v", time.Now().Sub(refreshStart))
}

// Start starts components running in background.
func (cache *CloudProviderNodeInstancesCache) Start(interrupt chan struct{}) {
	go wait.Until(func() {
		cache.Refresh()
	}, CloudProviderNodeInstancesCacheRefreshInterval, interrupt)
}
```

### get ASGs

It gets the ASG list with filters. A ASG cache is created inside to store the ASG data.

discovery config is from `-node-group-auto-discovery=asg:tag=[k8s.io/cluster-autoscaler/enabled,k8s.io/cluster-autoscaler]` 

```go
// NodeGroups returns all node groups configured for this cloud provider.
func (aws *awsCloudProvider) NodeGroups() []cloudprovider.NodeGroup {
	asgs := aws.awsManager.getAsgs()
	ngs := make([]cloudprovider.NodeGroup, 0, len(asgs))
	for _, asg := range asgs {
		ngs = append(ngs, &AwsNodeGroup{
			asg:        asg,
			awsManager: aws.awsManager,
		})
	}

	return ngs
}

func (m *AwsManager) getAsgs() map[AwsRef]*asg {
	return m.asgCache.Get()
}

func newASGCache(awsService *awsWrapper, explicitSpecs []string, autoDiscoverySpecs []asgAutoDiscoveryConfig) (*asgCache, error) {
	registry := &asgCache{
		...
		asgAutoDiscoverySpecs: autoDiscoverySpecs,
		...
	}
}
```

### keep nodes cache updated

- remove the ASG from cache which is already removed from AWS
    
    ```go
    func (cache *CloudProviderNodeInstancesCache) removeEntriesForNonExistingNodeGroupsLocked(nodeGroups []cloudprovider.NodeGroup) {
    	...
    	for nodeGroupId := range cache.cloudProviderNodeInstances {
    		if !nodeGroupExists[nodeGroupId] {
    			delete(cache.cloudProviderNodeInstances, nodeGroupId)
    		}
    	}
    }
    ```
    
- update cache, the key is the ASG name and values are all the EC2 instances in this ASG
    
    ```go
    func (cache *CloudProviderNodeInstancesCache) updateCacheEntryLocked(nodeGroup cloudprovider.NodeGroup, cacheEntry *cloudProviderNodeInstancesCacheEntry) {
    	cache.Lock()
    	defer cache.Unlock()
    	cache.cloudProviderNodeInstances[nodeGroup.Id()] = cacheEntry
    }
    
    // Id returns asg id.
    func (ng *AwsNodeGroup) Id() string {
    	return ng.asg.Name
    }
    ```
    

<aside>
💡 If there are too many ASG in one cluster it could be a performance issue. one idea is to use a dedicated CA for dedicated ASGs.

</aside>

# Scaling

CA does scaling every `scan-interval`  (10s by default),

```go
func run(healthCheck *metrics.HealthCheck, debuggingSnapshotter debuggingsnapshot.DebuggingSnapshotter) {
	...

	// Autoscale ad infinitum.
	for {
		select {
		case <-time.After(*scanInterval):
			{
				err := autoscaler.RunOnce(loopStart)
				...
			}
		}
	}
}
```

## Find unscheduled pods

There are many steps to determine unscheduled pods due to resource capacity. CA does a lot validation to make sure the scaling be really necessary. 

Then CA will try to scale unless

- No unscheduled pod
- All ASG have max nodes
- All the unscheduled pods are newly created

```go
if len(unschedulablePodsToHelp) == 0 {
		scaleUpStatus.Result = status.ScaleUpNotNeeded
		klog.V(1).Info("No unschedulable pods")
	} else if a.MaxNodesTotal > 0 && len(readyNodes) >= a.MaxNodesTotal {
		scaleUpStatus.Result = status.ScaleUpNoOptionsAvailable
		klog.V(1).Info("Max total nodes in cluster reached")
	} else if allPodsAreNew(unschedulablePodsToHelp, currentTime) {
		// The assumption here is that these pods have been created very recently and probably there
		// is more pods to come. In theory we could check the newest pod time but then if pod were created
		// slowly but at the pace of 1 every 2 seconds then no scale up would be triggered for long time.
		// We also want to skip a real scale down (just like if the pods were handled).
		a.processorCallbacks.DisableScaleDownForLoop()
		scaleUpStatus.Result = status.ScaleUpInCooldown
```

## Scaling out

```go
	scaleUpStatus, typedErr = ScaleUp(autoscalingContext, a.processors, a.clusterStateRegistry, unschedulablePodsToHelp, readyNodes, daemonsets, nodeInfosForGroups, a.ignoredTaints)
		...
	if a.processors != nil && a.processors.ScaleUpStatusProcessor != nil {
			a.processors.ScaleUpStatusProcessor.Process(autoscalingContext, scaleUpStatus)
			scaleUpStatusProcessorAlreadyCalled = true
	}
```

The `ScaleUp` function is the core function to do the job.

### update cluster state

```go
func (a *StaticAutoscaler) updateClusterState(allNodes []*apiv1.Node, nodeInfosForGroups map[string]*schedulerframework.NodeInfo, currentTime time.Time) errors.AutoscalerError {
	err := a.clusterStateRegistry.UpdateNodes(allNodes, nodeInfosForGroups, currentTime)
	if err != nil {
		klog.Errorf("Failed to update node registry: %v", err)
		a.scaleDownPlanner.CleanUpUnneededNodes()
		return errors.ToAutoscalerError(errors.CloudProviderError, err)
	}
	core_utils.UpdateClusterStateMetrics(a.clusterStateRegistry)

	return nil
}
```

- update nodes
    
    ```go
    // UpdateNodes updates the state of the nodes in the ClusterStateRegistry and recalculates the stats
    func (csr *ClusterStateRegistry) UpdateNodes(nodes []*apiv1.Node, nodeInfosForGroups map[string]*schedulerframework.NodeInfo, currentTime time.Time) error {
    	...
    	csr.updateScaleRequests(currentTime)
    	return nil
    }
    ```
    
- check provisioning timeout
    
    target node group will marked failed
    
    ```go
    // To be executed under a lock.
    func (csr *ClusterStateRegistry) updateScaleRequests(currentTime time.Time) {
    	// clean up stale backoff info
    	csr.backoff.RemoveStaleBackoffData(currentTime)
    
    	for nodeGroupName, scaleUpRequest := range csr.scaleUpRequests {
    		...
    
    		if scaleUpRequest.ExpectedAddTime.Before(currentTime) {
    			klog.Warningf("Scale-up timed out for node group %v after %v",
    				nodeGroupName, currentTime.Sub(scaleUpRequest.Time))
    			csr.logRecorder.Eventf(apiv1.EventTypeWarning, "ScaleUpTimedOut",
    				"Nodes added to group %s failed to register within %v",
    				scaleUpRequest.NodeGroup.Id(), currentTime.Sub(scaleUpRequest.Time))
    			csr.registerFailedScaleUpNoLock(scaleUpRequest.NodeGroup, metrics.Timeout, cloudprovider.OtherErrorClass, "timeout", currentTime)
    			delete(csr.scaleUpRequests, nodeGroupName)
    		}
    	}
    	...
    }
    ```
    

### check limits

CA checks if the required resource exceeds limits or not

```go
resourceLimiter, errCP := context.CloudProvider.GetResourceLimiter()
scaleUpResourcesLeft, errLimits := computeScaleUpResourcesLeftLimits(context, processors, nodeGroups, nodeInfos, nodesFromNotAutoscaledGroups, resourceLimiter)
```

the limits is from options, there’s no limit by default

```go
maxNodesTotal            = flag.Int("max-nodes-total", 0, "Maximum number of nodes in all node groups. Cluster autoscaler will not grow the cluster beyond this number.")
	coresTotal               = flag.String("cores-total", minMaxFlagString(0, config.DefaultMaxClusterCores), "Minimum and maximum number of cores in cluster, in the format <min>:<max>. Cluster autoscaler will not scale the cluster beyond these numbers.")
	memoryTotal              = flag.String("memory-total", minMaxFlagString(0, config.DefaultMaxClusterMemory), "Minimum and maximum number of gigabytes of memory in cluster, in the format <min>:<max>. Cluster autoscaler will not scale the cluster beyond these numbers.")
```

### get the insufficient resource amount

- upcoming nodes
    
    CA scans every 10s but node provision takes 2m, if upcoming nodes are enough then no need to add more.
    
    ```go
    // GetUpcomingNodes returns how many new nodes will be added shortly to the node groups or should become ready soon.
    // The function may overestimate the number of nodes.
    func (csr *ClusterStateRegistry) GetUpcomingNodes() map[string]int {
    	csr.Lock()
    	defer csr.Unlock()
    
    	result := make(map[string]int)
    	for _, nodeGroup := range csr.cloudProvider.NodeGroups() {
    		id := nodeGroup.Id()
    		readiness := csr.perNodeGroupReadiness[id]
    		ar := csr.acceptableRanges[id]
    		// newNodes is the number of nodes that
    		newNodes := ar.CurrentTarget - (readiness.Ready + readiness.Unready + readiness.LongUnregistered)
    		if newNodes <= 0 {
    			// Negative value is unlikely but theoretically possible.
    			continue
    		}
    		result[id] = newNodes
    	}
    	return result
    }
    ```
    
- processors.NodeGroupListProcessor is skipped since the default one is empty
    
    ```go
    // Process processes lists of unschedulable and scheduled pods before scaling of the cluster.
    func (p *NoOpNodeGroupListProcessor) Process(context *context.AutoscalingContext, nodeGroups []cloudprovider.NodeGroup, nodeInfos map[string]*schedulerframework.NodeInfo,
    	unschedulablePods []*apiv1.Pod) ([]cloudprovider.NodeGroup, map[string]*schedulerframework.NodeInfo, error) {
    	return nodeGroups, nodeInfos, nil
    }
    ```
    
- find all possible options for pending nodes
    
    <aside>
    💡 e.g. There’s a pending pod without any node selector, then memory-ondemand, memeory-spot, general… are all options.
    
    </aside>
    
    - group similar pods
        
        ```go
        // buildPodEquivalenceGroups prepares pod groups with equivalent scheduling properties.
        func buildPodEquivalenceGroups(pods []*apiv1.Pod) []*podEquivalenceGroup {
        	podEquivalenceGroups := []*podEquivalenceGroup{}
        	for _, pods := range groupPodsBySchedulingProperties(pods) {
        		podEquivalenceGroups = append(podEquivalenceGroups, &podEquivalenceGroup{
        			pods:             pods,
        			schedulingErrors: map[string]status.Reasons{},
        			schedulable:      false,
        		})
        	}
        	return podEquivalenceGroups
        }
        ```
        
        it gets the ownerReference of the pods, if they have the same owner then check the label and specs. 
        
        By doing this it avoids checking all pending pods unnecessarily.  But it was an issue in case of spark pods, the labels are not identical 
        
        ```yaml
        	labels:
            app: dataset-demo-4
            attemptId: 40b8e95b6021e4a3ea77763fe7d725d2d
            jobType: spark
            podType: executor
            spark-app-selector: spark-387ab2e26fcf4705b86e687b3f0d3b3c
            spark-exec-id: '78'
            spark-exec-resourceprofile-id: '0'
            spark-role: executor
            team: Data-Platform-SH_Non-Shared
          ownerReferences:
            - apiVersion: v1
              kind: Pod
              name: dataset-demo-4-0b8e95b6-021e-4a3e-a777-63fe7d725d2d
              uid: 00b3c838-d5ec-4eaf-a254-a76f8dc16448
              controller: true
        ```
        
    - check each ASG to get all available options
        
        ```go
        for _, nodeGroup := range nodeGroups {
        		...
        
        	// capacity check
        		scaleUpResourcesDelta, err := computeScaleUpResourcesDelta(context, processors, nodeInfo, nodeGroup, resourceLimiter)
        		if err != nil {
        			klog.Errorf("Skipping node group %s; error getting node group resources: %v", nodeGroup.Id(), err)
        			skippedNodeGroups[nodeGroup.Id()] = notReadyReason
        			continue
        		}
        		checkResult := scaleUpResourcesLeft.checkScaleUpDeltaWithinLimits(scaleUpResourcesDelta)
        		...
        
         // filter check
        		option, err := computeExpansionOption(context, podEquivalenceGroups, nodeGroup, nodeInfo, upcomingNodes)
        		if err != nil {
        			return scaleUpError(&status.ScaleUpStatus{}, errors.ToAutoscalerError(errors.InternalError, err))
        		}
        ...
        	}
        ```
        
        - it check capacity and instance types of each ASG to see if pending pods can be scheduled
            
            `resultScaleUpDelta` indicates how much new CPU and memory can be added
            
            ```go
            func computeScaleUpResourcesDelta(context *context.AutoscalingContext, processors *ca_processors.AutoscalingProcessors,
            	nodeInfo *schedulerframework.NodeInfo, nodeGroup cloudprovider.NodeGroup, resourceLimiter *cloudprovider.ResourceLimiter) (scaleUpResourcesDelta, errors.AutoscalerError) {
            	resultScaleUpDelta := make(scaleUpResourcesDelta)
            
            	nodeCPU, nodeMemory := getNodeInfoCoresAndMemory(nodeInfo)
            	resultScaleUpDelta[cloudprovider.ResourceNameCores] = nodeCPU
            	resultScaleUpDelta[cloudprovider.ResourceNameMemory] = nodeMemory
            	...
            	return resultScaleUpDelta, nil
            }
            ```
            
        - filter will all plugins
            
            this is the most time consuming part which runs kube-scheduler filters
            
            ```go
            func computeExpansionOption(context *context.AutoscalingContext, podEquivalenceGroups []*podEquivalenceGroup, nodeGroup cloudprovider.NodeGroup, nodeInfo *schedulerframework.NodeInfo, upcomingNodes []*schedulerframework.NodeInfo) (expander.Option, error) {
            ....
            	for _, eg := range podEquivalenceGroups {
            		samplePod = eg.pods[0]
            		if err := context.PredicateChecker.CheckPredicates(context.ClusterSnapshot, samplePod, nodeInfo.Node().Name); err == nil {
            			// add pods to option
            			option.Pods = append(option.Pods, eg.pods...)
            			// mark pod group as (theoretically) schedulable
            			eg.schedulable = true
            			klog.V(1).Infof("Pod %s can be scheduled on %s along with similar %d pods", samplePod.Name, nodeGroup.Id(), len(eg.pods))
            		} else {
            			klog.V(2).Infof("Pod %s can't be scheduled on %s, predicate checking error: %v", samplePod.Name, nodeGroup.Id(), err.VerboseMessage())
            			if podCount := len(eg.pods); podCount > 1 {
            				klog.V(2).Infof("%d other pods similar to %s can't be scheduled on %s", podCount-1, samplePod.Name, nodeGroup.Id())
            			}
            			eg.schedulingErrors[nodeGroup.Id()] = err
            		}
            	}
            ...
            	return option, nil
            }
            ```
            
            if the pods are not well grouped, this process would take very long since it runs all filters against each pod.
            
            ```bash
            I1017 08:10:33.187686       1 scale_up.go:300] Pod xx can be scheduled on xx along with similar 1 pods
            ```
            
        
        **total time = (ASG count) x (pod group count) x (filter time)**
        
    - collect all the options
        
        ```bash
        I1017 08:10:21.185725       1 scale_up.go:477] Get all options to decide the best
        I1017 08:10:21.185736       1 scale_up.go:479] Candidate ASG A 1
        I1017 08:10:21.185744       1 scale_up.go:479] Candidate ASG B 2
        I1017 08:10:21.185754       1 scale_up.go:479] Candidate ASG C 101
        ...
        ```
        

### find the best candidate nodegroups to scale

- get the best option
    
    it decides the best option based on the strategy
    
    ```go
    // ExpanderStrategyFromStrings creates an expander.Strategy according to the names of the expanders passed in
    // take in whole opts and access stuff here
    func ExpanderStrategyFromStrings(expanderFlags []string, cloudProvider cloudprovider.CloudProvider,
    	autoscalingKubeClients *context.AutoscalingKubeClients, kubeClient kube_client.Interface,
    	configNamespace string, GRPCExpanderCert string, GRPCExpanderURL string) (expander.Strategy, errors.AutoscalerError) {
    	var filters []expander.Filter
    	seenExpanders := map[string]struct{}{}
    	strategySeen := false
    	for i, expanderFlag := range expanderFlags {
    		...
    		switch expanderFlag {
    		...
    		case expander.PriorityBasedExpanderName:
    			// It seems other listers do the same here - they never receive the termination msg on the ch.
    			// This should be currently OK.
    			stopChannel := make(chan struct{})
    			lister := kubernetes.NewConfigMapListerForNamespace(kubeClient, stopChannel, configNamespace)
    			filters = append(filters, priority.NewFilter(lister.ConfigMaps(configNamespace), autoscalingKubeClients.Recorder))
    		}
    	}
    	return newChainStrategy(filters, random.NewStrategy()), nil
    }
    
    func (c *chainStrategy) BestOption(options []expander.Option, nodeInfo map[string]*schedulerframework.NodeInfo) *expander.Option {
    	filteredOptions := options
    	for _, filter := range c.filters {
    		filteredOptions = filter.BestOptions(filteredOptions, nodeInfo)
    		if len(filteredOptions) == 1 {
    			return &filteredOptions[0]
    		}
    	}
    
    	// return a random one if there are multiple options
    	return c.fallback.BestOption(filteredOptions, nodeInfo)
    }
    ```
    
- priority expander
    
    it basically add the nodegroups to an array by the order of the priority which is defined in the configmap
    
    ```go
    type Option struct {
    	NodeGroup cloudprovider.NodeGroup
    	NodeCount int
    	Debug     string
    	Pods      []*apiv1.Pod
    }
    
    func (p *priority) BestOptions(expansionOptions []expander.Option, nodeInfo map[string]*schedulerframework.NodeInfo) []expander.Option {
    	...
    	maxPrio := -1
    	best := []expander.Option{}
    	for _, option := range expansionOptions {
    		id := option.NodeGroup.Id()
    		found := false
    		for prio, nameRegexpList := range priorities {
    			if !p.groupIDMatchesList(id, nameRegexpList) {
    				continue
    			}
    			found = true
    			if prio < maxPrio {
    				continue
    			}
    			if prio > maxPrio {
    				maxPrio = prio
    				best = nil
    			}
    			best = append(best, option)
    
    		}
    	}
    
    	...
    	return best
    }
    ```
    
    ```yaml
    		1:
          - .*
        5:
          - .*A
          - .*B
	  - .*C
       
    ```
    
    It only returns the option with the highest priority.
    
    ```bash
    I1017 08:10:21.187053       1 priority.go:163] priority expander: B chosen as the highest available
    I1017 08:10:21.187073       1 priority.go:163] priority expander: C chosen as the highest available

    I1017 08:10:21.187111       1 scale_up.go:484] Best option to resize: A
    ```
    
    CA will always tries to scale up the ASG with highest priority, so if there are two types of workloads e.g. spark pods and presto pods, presto pods won’t trigger the scale-out unless all the spark pods are scheduled(or prescheduled).
    
- balanced between similar ASG
    

### scale up

scale out each target nodegroup

```go
		for _, info := range scaleUpInfos {bv
			typedErr := executeScaleUp(context, clusterStateRegistry, info, gpu.GetGpuTypeForMetrics(gpuLabel, availableGPUTypes, nodeInfo.Node(), nil), now)
			...
		}

		clusterStateRegistry.Recalculate()

func executeScaleUp(context *context.AutoscalingContext, clusterStateRegistry *clusterstate.ClusterStateRegistry, info nodegroupset.ScaleUpInfo, gpuType string, now time.Time) errors.AutoscalerError {
	klog.V(0).Infof("Scale-up: setting group %s size to %d", info.Group.Id(), info.NewSize)
	context.LogRecorder.Eventf(apiv1.EventTypeNormal, "ScaledUpGroup",
		"Scale-up: setting group %s size to %d instead of %d (max: %d)", info.Group.Id(), info.NewSize, info.CurrentSize, info.MaxSize)
	increase := info.NewSize - info.CurrentSize
	if err := info.Group.IncreaseSize(increase); err != nil {
		context.LogRecorder.Eventf(apiv1.EventTypeWarning, "FailedToScaleUpGroup", "Scale-up failed for group %s: %v", info.Group.Id(), err)
		aerr := errors.ToAutoscalerError(errors.CloudProviderError, err).AddPrefix("failed to increase node group size: ")
		clusterStateRegistry.RegisterFailedScaleUp(info.Group, metrics.FailedScaleUpReason(string(aerr.Type())), now)
		return aerr
	}
	clusterStateRegistry.RegisterOrUpdateScaleUp(
		info.Group,
		increase,
		time.Now())
	metrics.RegisterScaleUp(increase, gpuType)
	context.LogRecorder.Eventf(apiv1.EventTypeNormal, "ScaledUpGroup",
		"Scale-up: group %s size set to %d instead of %d (max: %d)", info.Group.Id(), info.NewSize, info.CurrentSize, info.MaxSize)
	return nil
}
```

- increase ASG desired size
    
    If the action fails, target ASG will be marked as failed
    
    ```go
    // RegisterFailedScaleUp should be called after getting error from cloudprovider
    // when trying to scale-up node group. It will mark this group as not safe to autoscale
    // for some time.
    func (csr *ClusterStateRegistry) RegisterFailedScaleUp(nodeGroup cloudprovider.NodeGroup, reason metrics.FailedScaleUpReason, currentTime time.Time) {
    	csr.Lock()
    	defer csr.Unlock()
    	csr.registerFailedScaleUpNoLock(nodeGroup, reason, cloudprovider.OtherErrorClass, string(reason), currentTime)
    }
    
    func (csr *ClusterStateRegistry) registerFailedScaleUpNoLock(nodeGroup cloudprovider.NodeGroup, reason metrics.FailedScaleUpReason, errorClass cloudprovider.InstanceErrorClass, errorCode string, currentTime time.Time) {
    	csr.scaleUpFailures[nodeGroup.Id()] = append(csr.scaleUpFailures[nodeGroup.Id()], ScaleUpFailure{NodeGroup: nodeGroup, Reason: reason, Time: currentTime})
    	metrics.RegisterFailedScaleUp(reason)
    	csr.backoffNodeGroup(nodeGroup, errorClass, errorCode, currentTime)
    }
    ```
    
    these nodegroups won’t be selected until some time 
    
    ```go
    // IsNodeGroupSafeToScaleUp returns true if node group can be scaled up now.
    func (csr *ClusterStateRegistry) IsNodeGroupSafeToScaleUp(nodeGroup cloudprovider.NodeGroup, now time.Time) bool {
    	if !csr.IsNodeGroupHealthy(nodeGroup.Id()) {
    		return false
    	}
    	return !csr.backoff.IsBackedOff(nodeGroup, csr.nodeInfosForGroups[nodeGroup.Id()], now)
    }
    // IsBackedOff returns true if execution is backed off for the given node group.
    func (b *exponentialBackoff) IsBackedOff(nodeGroup cloudprovider.NodeGroup, nodeInfo *schedulerframework.NodeInfo, currentTime time.Time) bool {
    	backoffInfo, found := b.backoffInfo[b.nodeGroupKey(nodeGroup)]
    	return found && backoffInfo.backoffUntil.After(currentTime)
    }
    
    nodeGroupBackoffResetTimeout = flag.Duration("node-group-backoff-reset-timeout", 3*time.Hour,
    		"nodeGroupBackoffResetTimeout is the time after last failed scale-up when the backoff duration is reset.")
    
    ```
    
- update scaling result
    
    it updates the expected provision time(`-max-node-provision-time=5m`) for each nodegroup
    
    ```go
    func (csr *ClusterStateRegistry) RegisterOrUpdateScaleUp(nodeGroup cloudprovider.NodeGroup, delta int, currentTime time.Time) {
    	csr.Lock()
    	defer csr.Unlock()
    	csr.registerOrUpdateScaleUpNoLock(nodeGroup, delta, currentTime)
    }
    
    func (csr *ClusterStateRegistry) registerOrUpdateScaleUpNoLock(nodeGroup cloudprovider.NodeGroup, delta int, currentTime time.Time) {
    	scaleUpRequest, found := csr.scaleUpRequests[nodeGroup.Id()]
    	if !found && delta > 0 {
    		scaleUpRequest = &ScaleUpRequest{
    			NodeGroup:       nodeGroup,
    			Increase:        delta,
    			Time:            currentTime,
    			ExpectedAddTime: currentTime.Add(csr.config.MaxNodeProvisionTime),
    		}
    		csr.scaleUpRequests[nodeGroup.Id()] = scaleUpRequest
    		return
    	}
    	...
    	if delta > 0 {
    		// if we are actually adding new nodes shift Time and ExpectedAddTime
    		scaleUpRequest.Time = currentTime
    		scaleUpRequest.ExpectedAddTime = currentTime.Add(csr.config.MaxNodeProvisionTime)
    	}
    }
    ```
    

## Scaling in

CA will do scaling-in if `scale-down-enabled` is true(by default).

### get [pod distribution budget](https://kubernetes.io/docs/concepts/workloads/pods/disruptions/#pod-disruption-budgets)

```go
		pdbs, err := pdbLister.List()
		if err != nil {
			scaleDownStatus.Result = status.ScaleDownError
			klog.Errorf("Failed to list pod disruption budgets: %v", err)
			return errors.ToAutoscalerError(errors.ApiCallError, err)
		}
```

### get candidates

```go
			scaleDownCandidates, err = a.processors.ScaleDownNodeProcessor.GetScaleDownCandidates(
				autoscalingContext, allNodes)
			if err != nil {
				klog.Error(err)
				return err
			}
			podDestinations, err = a.processors.ScaleDownNodeProcessor.GetPodDestinationCandidates(autoscalingContext, allNodes)
			if err != nil {
				klog.Error(err)
				return err
			}
```

processors are initialized when creating scaler.

```go
// NewPreFilteringScaleDownNodeProcessor returns a new PreFilteringScaleDownNodeProcessor.
func NewPreFilteringScaleDownNodeProcessor() *PreFilteringScaleDownNodeProcessor {
	return &PreFilteringScaleDownNodeProcessor{}
}
```

- skip nodes when the size is lower than ASG min size
    
    ```go
    func (n *PreFilteringScaleDownNodeProcessor) GetScaleDownCandidates(ctx *context.AutoscalingContext,
    	nodes []*apiv1.Node) ([]*apiv1.Node, errors.AutoscalerError) {
    	result := make([]*apiv1.Node, 0, len(nodes))
    
    	nodeGroupSize := utils.GetNodeGroupSizeMap(ctx.CloudProvider)
    
    	for _, node := range nodes {
    		nodeGroup, err := ctx.CloudProvider.NodeGroupForNode(node)
    		...
    		if size <= nodeGroup.MinSize() {
    			klog.V(1).Infof("Skipping %s - node group min size reached", node.Name)
    			continue
    		}
    		result = append(result, node)
    	}
    	return result, nil
    }
    ```
    
- get nodes for rescheduling
    
    but it just returns all the nodes
    
    ```go
    // GetPodDestinationCandidates returns nodes that potentially could act as destinations for pods
    // that would become unscheduled after a scale down.
    func (n *PreFilteringScaleDownNodeProcessor) GetPodDestinationCandidates(ctx *context.AutoscalingContext,
    	nodes []*apiv1.Node) ([]*apiv1.Node, errors.AutoscalerError) {
    	return nodes, nil
    }
    ```
    

### update cluster state

the scale down related objects are initialized.

```go
	ndt := deletiontracker.NewNodeDeletionTracker(0 * time.Second)
	scaleDown := legacy.NewScaleDown(autoscalingContext, processors, clusterStateRegistry, ndt)
	actuator := actuation.NewActuator(autoscalingContext, clusterStateRegistry, ndt)
	scaleDownWrapper := legacy.NewScaleDownWrapper(scaleDown, actuator)
	processorCallbacks.scaleDownPlanner = scaleDownWrapper
```

update the `unneededNodes` based on utilization.

```go
// UpdateClusterState updates unneeded nodes in the underlying ScaleDown.
func (p *ScaleDownWrapper) UpdateClusterState(podDestinations, scaleDownCandidates []*apiv1.Node, actuationStatus scaledown.ActuationStatus, pdbs []*policyv1.PodDisruptionBudget, currentTime time.Time) errors.AutoscalerError {
	p.sd.CleanUp(currentTime)
	p.pdbs = pdbs
	return p.sd.UpdateUnneededNodes(podDestinations, scaleDownCandidates, currentTime, pdbs)
}

// ScaleDown is responsible for maintaining the state needed to perform unneeded node removals.
type ScaleDown struct {
	context              *context.AutoscalingContext
	processors           *processors.AutoscalingProcessors
	clusterStateRegistry *clusterstate.ClusterStateRegistry
	unneededNodes        map[string]time.Time
	unneededNodesList    []*apiv1.Node
	unremovableNodes     *unremovable.Nodes
	podLocationHints     map[string]string
	nodeUtilizationMap   map[string]utilization.Info
	usageTracker         *simulator.UsageTracker
	nodeDeletionTracker  *deletiontracker.NodeDeletionTracker
	removalSimulator     *simulator.RemovalSimulator
}
```

- check utilization
    
    threshold is from `scale-down-utilization-threshold` (0.5 by default), utilization is based on pods requests not actual usage.
    
    ```go
    func (sd *ScaleDown) checkNodeUtilization(timestamp time.Time, node *apiv1.Node, nodeInfo *schedulerframework.NodeInfo) (simulator.UnremovableReason, *utilization.Info) {
    	...
    
    	utilInfo, err := utilization.Calculate(node, nodeInfo, sd.context.IgnoreDaemonSetsUtilization, sd.context.IgnoreMirrorPodsUtilization, sd.context.CloudProvider.GPULabel(), timestamp)
    	...
    
    	underutilized, err := sd.isNodeBelowUtilizationThreshold(node, nodeGroup, utilInfo)
    	...
    
    	return simulator.NoReason, &utilInfo
    }
    
    func calculateUtilizationOfResource(node *apiv1.Node, nodeInfo *schedulerframework.NodeInfo, resourceName apiv1.ResourceName, skipDaemonSetPods, skipMirrorPods bool, currentTime time.Time) (float64, error) {
    	...
    	return float64(podsRequest.MilliValue()) / float64(nodeAllocatable.MilliValue()-daemonSetAndMirrorPodsUtilization.MilliValue()), nil
    }
    ```
    
- find empty nodes (if the daemonset pods requests is higher than 0.5, the node still can be a candidate)

### ScaleDown CD

```go
scaleDownInCooldown := a.processorCallbacks.disableScaleDownForLoop ||
a.lastScaleUpTime.Add(a.ScaleDownDelayAfterAdd).After(currentTime) ||
a.lastScaleDownFailTime.Add(a.ScaleDownDelayAfterFailure).After(currentTime) ||
a.lastScaleDownDeleteTime.Add(a.ScaleDownDelayAfterDelete).After(currentTime)

scaleDownDelayAfterAdd = flag.Duration("scale-down-delay-after-add", 10*time.Minute,
		"How long after scale up that scale down evaluation resumes")
scaleDownDelayAfterDelete = flag.Duration("scale-down-delay-after-delete", 0,
		"How long after node deletion that scale down evaluation resumes, defaults to scanInterval")
scaleDownDelayAfterFailure = flag.Duration("scale-down-delay-after-failure", 3*time.Minute,
		"How long after scale down failure that scale down evaluation resumes")
```

<aside>
💡 CA won’t scale in if it just scaled up(10 minutes by default), but it doesn’t distinguish node groups. this value should be less than `scaleDownUnneededTime`

</aside>

### get targets

```go
func (p *ScaleDownWrapper) NodesToDelete(currentTime time.Time) (empty, needDrain []*apiv1.Node) {
	empty, drain, result, err := p.sd.NodesToDelete(currentTime, p.pdbs)
	p.lastNodesToDeleteResult = result
	p.lastNodesToDeleteErr = err
	return empty, drain
}
```

- nodes without ASG will be skipped
    
    ```go
    		nodeGroup, err := sd.context.CloudProvider.NodeGroupForNode(node)
    		if err != nil {
    			klog.Errorf("Error while checking node group for %s: %v", node.Name, err)
    			sd.unremovableNodes.AddReason(node, simulator.UnexpectedError)
    			continue
    		}
    		if nodeGroup == nil || reflect.ValueOf(nodeGroup).IsNil() {
    			klog.V(4).Infof("Skipping %s - no node group config", node.Name)
    			sd.unremovableNodes.AddReason(node, simulator.NotAutoscaled)
    			continue
    		} 
    ```
    
- filter by `ScaleDownUnneededTime`
    
    ```go
    			unneededTime, err := sd.processors.NodeGroupConfigProcessor.GetScaleDownUnneededTime(sd.context, nodeGroup)
    			if err != nil {
    				klog.Errorf("Error trying to get ScaleDownUnneededTime for node %s (in group: %s)", node.Name, nodeGroup.Id())
    				continue
    			}
    			if !unneededSince.Add(unneededTime).Before(currentTime) {
    				sd.unremovableNodes.AddReason(node, simulator.NotUnneededLongEnough)
    				continue
    			}
    ```
    
- check resource limits (ignored since we are no’t setting any limits)
    
    ```go
    scaleDownResourcesDelta, err := sd.computeScaleDownResourcesDelta(sd.context. scaleDownResourcesLeft.checkScaleDownDeltaWithinLimits(scaleDownResourcesDelta)
    ```
    
- find empty nodes
    
    if the node only has daemonset pods running, then it’s empty
    
    ```go
    emptyNodesToRemove := sd.getEmptyNodesToRemove(candidateNames, scaleDownResourcesLeft, currentTime)
    emptyNodesToRemove = sd.processors.ScaleDownSetProcessor.GetNodesToRemove(sd.context, emptyNodesToRemove, sd.context.MaxEmptyBulkDelete)
    
    func (r *RemovalSimulator) FindEmptyNodesToRemove(candidates []string, timestamp time.Time) []string {
    	result := make([]string, 0)
    	for _, node := range candidates {
    		nodeInfo, err := r.clusterSnapshot.NodeInfos().Get(node)
    		if err != nil {
    			klog.Errorf("Can't retrieve node %s from snapshot, err: %v", node, err)
    			continue
    		}
    		// Should block on all pods.
    		podsToRemove, _, _, err := FastGetPodsToMove(nodeInfo, true, true, nil, timestamp)
    		if err == nil && len(podsToRemove) == 0 {
    			result = append(result, node)
    		}
    	}
    	return result
    }
    ```
    
- check if the pods can be rescheduled to somewhere else including pdbs checking
    
    ```go
    func (r *RemovalSimulator) CheckNodeRemoval(
    	nodeName string,
    	destinationMap map[string]bool,
    	oldHints map[string]string,
    	newHints map[string]string,
    	timestamp time.Time,
    	pdbs []*policyv1.PodDisruptionBudget,
    ) (*NodeToBeRemoved, *UnremovableNode) {
    	...
    
    	podsToRemove, daemonSetPods, blockingPod, err := DetailedGetPodsForMove(nodeInfo, *skipNodesWithSystemPods,
    		*skipNodesWithLocalStorage, r.listers, int32(*minReplicaCount), pdbs, timestamp)
    	...
    
    	err = r.findPlaceFor(nodeName, podsToRemove, destinationMap, oldHints, newHints, timestamp)
    	...
    }
    ```
    

### remove nodes

- empty nodes will be removed directly
- non empty nodes will be tainted and drained first
- deletion is asynchronous

```go
// StartDeletion triggers a new deletion process.
func (a *Actuator) StartDeletion(empty, drain []*apiv1.Node, currentTime time.Time) (*status.ScaleDownStatus, errors.AutoscalerError) {
	defer func() { metrics.UpdateDuration(metrics.ScaleDownNodeDeletion, time.Now().Sub(currentTime)) }()
	...
	emptyScaledDown, err := a.taintSyncDeleteAsyncEmpty(emptyToDelete)
	scaleDownStatus.ScaledDownNodes = append(scaleDownStatus.ScaledDownNodes, emptyScaledDown...)
	err = a.taintNodesSync(drainToDelete)
	...
	drainScaledDown := a.deleteAsyncDrain(drainToDelete)
	scaleDownStatus.ScaledDownNodes = append(scaleDownStatus.ScaledDownNodes, drainScaledDown...)

	scaleDownStatus.Result = status.ScaleDownNodeDeleteStarted
	return scaleDownStatus, nil
}
```