# KEDA DeepDive


## Overview

[KEDA](https://keda.sh/) is a Kubernetes-based Event Driven Autoscaler with making use of [Horizontal Pod Autoscaler](https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/). 

With KEDA you can easily do auto scaling by all kinds of scalers such as cron, queue etc.

[KubeCon + CloudNative North America 2023: Exploring KEDA's Graduation and Advancem...](https://kccncna2023.sched.com/event/1R2nn/exploring-kedas-graduation-and-advancements-in-event-driven-scaling-zbynek-roubalik-kedify)

## Deployments

```bash
$ kubectl get deploy -n keda
NAME                              READY   UP-TO-DATE   AVAILABLE   AGE
keda-operator                     1/1     1            1           3h9m
keda-operator-metrics-apiserver   1/1     1            1           3h9m
```

two deployments

- keda-operator: do the scaling job.
- keda-operator-metrics-apiserver: expose custom metrics to the Horizontal Pod Autoscaler for scaling.

we will dive into details in the next section.

## CRDs

```bash
clustertriggerauthentications.keda.sh                       2021-11-04T05:39:59Z
scaledjobs.keda.sh                                          2021-11-04T05:40:00Z
scaledobjects.keda.sh                                       2021-11-04T05:39:59Z
triggerauthentications.keda.sh                              2021-11-04T05:39:59Z
```

- `ScaledObjects` represent the desired mapping between an event source (e.g. Rabbit MQ) and the Kubernetes Deployment, StatefulSet or any Custom Resource that defines `/scale` subresource.
- `ScaledJobs` represent the mapping between event source and Kubernetes Job.
- `ScaledObject`/`ScaledJob` may also reference a `TriggerAuthentication` or `ClusterTriggerAuthentication` which contains the authentication configuration or secrets to monitor the event source.

## AWS IAM Config

some scalers like cloudwatch, SQS require access to AWS.

- Policy
    
    ```json
    {
        "Statement": [
            {
                "Action": [
                    "sqs:GetQueueAttributes",
                    "sqs:GetQueueUrl",
                    "sqs:ListDeadLetterSourceQueues",
                    "sqs:ListQueues"
                    "sqs:ListQueues",
                    "cloudwatch:GetMetricData"
                ],
                "Effect": "Allow",
                "Resource": "*"
            }
        ]
    }
    ```
    
- Relations
    
    ```json
    "Statement": [
        {
          "Sid": "",
          "Effect": "Allow",
          "Principal": {
            "Federated": "xxxxx"
          },
          "Action": "sts:AssumeRoleWithWebIdentity",
          "Condition": {
            "StringEquals": {
              "xxxx"
            }
          }
        }
    ```
    

## Architecture

[KEDA | KEDA Concepts](https://keda.sh/docs/2.4/concepts/#architecture)

KEDA is a standard k8s operator following k8s operator pattern design.

### keda-operator

[https://whimsical.com/keda-VPPLzLWZoQLfndkUSzxs65](https://whimsical.com/keda-VPPLzLWZoQLfndkUSzxs65)

1. [main.go](https://github.com/kedacore/keda/blob/main/main.go#L114) starts all the controllers
    
    ```go
    // initialize all the controllers
    if err = (&kedacontrollers.ScaledObjectReconciler{
    		Client:            mgr.GetClient(),
    		Scheme:            mgr.GetScheme(),
    		GlobalHTTPTimeout: globalHTTPTimeout,
    		Recorder:          eventRecorder,
    	}).SetupWithManager(mgr); err != nil {
    		setupLog.Error(err, "unable to create controller", "controller", "ScaledObject")
    		os.Exit(1)
    	}
    ...
    
    // use "sigs.k8s.io/controller-runtime" to start controllers
    if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
    		setupLog.Error(err, "problem running manager")
    		os.Exit(1)
    	}
    ```
    
2. take [scaledobject_controller](https://github.com/kedacore/keda/blob/main/controllers/keda/scaledobject_controller.go) as an example.
    
    ```go
    // SetupWithManager initializes the ScaledObjectReconciler instance and starts a new controller managed by the passed Manager instance.
    func (r *ScaledObjectReconciler) SetupWithManager(mgr ctrl.Manager) error {
    	...
    
    	// Create Scale Client
    	scaleClient := initScaleClient(mgr, clientset)
    	r.scaleClient = scaleClient
    
    	// Init the rest of ScaledObjectReconciler
    	r.restMapper = mgr.GetRESTMapper()
    	r.scaledObjectsGenerations = &sync.Map{}
    	r.scaleHandler = scaling.NewScaleHandler(mgr.GetClient(), r.scaleClient, mgr.GetScheme(), r.GlobalHTTPTimeout, r.Recorder)
    
    	...
    }
    
    func initScaleClient(mgr manager.Manager, clientset *discovery.DiscoveryClient) scale.ScalesGetter {
    	scaleKindResolver := scale.NewDiscoveryScaleKindResolver(clientset)
    	return scale.New(
    		clientset.RESTClient(), mgr.GetRESTMapper(),
    		dynamic.LegacyAPIPathResolverFunc,
    		scaleKindResolver,
    	)
    }
    ```
    
    `ScaledHandler` is created here with the `scaleClient` which is [client-go scale client](https://pkg.go.dev/k8s.io/client-go/scale).
    
    This client will be used for actual [scaling work](https://github.com/kedacore/keda/blob/main/pkg/scaling/scale_handler.go).
    
    ```go
    func NewScaleHandler(client client.Client, scaleClient scale.ScalesGetter, reconcilerScheme *runtime.Scheme, globalHTTPTimeout time.Duration, recorder record.EventRecorder) ScaleHandler {
    	return &scaleHandler{
    		client:            client,
    		logger:            logf.Log.WithName("scalehandler"),
    		scaleLoopContexts: &sync.Map{},
    		scaleExecutor:     executor.NewScaleExecutor(client, scaleClient, reconcilerScheme, recorder),
    		globalHTTPTimeout: globalHTTPTimeout,
    		recorder:          recorder,
    	}
    }
    ```
    
3. [Reconcile](https://github.com/kedacore/keda/blob/main/controllers/keda/scaledobject_controller.go#L138) will be invoked
    
    ```go
    func (r *ScaledObjectReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    	reqLogger := log.FromContext(ctx)
    
    	// Fetch the ScaledObject instance
    	scaledObject := &kedav1alpha1.ScaledObject{}
    	...
    	// reconcile ScaledObject and set status appropriately
    	msg, err := r.reconcileScaledObject(ctx, reqLogger, scaledObject)
    ...
    }
    ```
    
    It gets the [target objects](https://keda.sh/docs/2.4/concepts/scaling-deployments/#scaledobject-spec), then call reconcileScaledObject to handle.
    
    ```go
    func (r *ScaledObjectReconciler) reconcileScaledObject(ctx context.Context, logger logr.Logger, scaledObject *kedav1alpha1.ScaledObject) (string, error) {
    	// Check scale target Name is specified
    	if scaledObject.Spec.ScaleTargetRef.Name == "" {
    		err := fmt.Errorf("ScaledObject.spec.scaleTargetRef.name is missing")
    		return "ScaledObject doesn't have correct scaleTargetRef specification", err
    	}
    
    	 ...
    	// Create a new HPA or update existing one according to ScaledObject
    	newHPACreated, err := r.ensureHPAForScaledObjectExists(ctx, logger, scaledObject, &gvkr)
    	if err != nil {
    		return "Failed to ensure HPA is correctly created for ScaledObject", err
    	}
    	...
    
    	// Notify ScaleHandler if a new HPA was created or if ScaledObject was updated
    	if newHPACreated || scaleObjectSpecChanged {
    		if r.requestScaleLoop(logger, scaledObject) != nil {
    			return "Failed to start a new scale loop with scaling logic", err
    		}
    		logger.Info("Initializing Scaling logic according to ScaledObject Specification")
    	}
    	return "ScaledObject is defined correctly and is ready for scaling", nil
    }
    ```
    
    reconcileScaledObject basically does 3 things:
    
    - condition checking
    - create HPA
    - start loop to scale
    
    Eventually HPA is created [here](https://github.com/kedacore/keda/blob/main/controllers/keda/hpa.go#L62), not sure why it's not using client-go.
    
    ```go
    	func (r *ScaledObjectReconciler) newHPAForScaledObject(ctx context.Context, logger logr.Logger, scaledObject *kedav1alpha1.ScaledObject, gvkr *kedav1alpha1.GroupVersionKindResource) (*autoscalingv2beta2.HorizontalPodAutoscaler, error) {
    		...
    		hpa := &autoscalingv2beta2.HorizontalPodAutoscaler{
    				Spec: autoscalingv2beta2.HorizontalPodAutoscalerSpec{
    					MinReplicas: getHPAMinReplicas(scaledObject),
    					MaxReplicas: getHPAMaxReplicas(scaledObject),
    					Metrics:     scaledObjectMetricSpecs,
    					Behavior:    behavior,
    					ScaleTargetRef: autoscalingv2beta2.CrossVersionObjectReference{
    						Name:       scaledObject.Spec.ScaleTargetRef.Name,
    						Kind:       gvkr.Kind,
    						APIVersion: gvkr.GroupVersion().String(),
    					}},
    				ObjectMeta: metav1.ObjectMeta{
    					Name:      getHPAName(scaledObject),
    					Namespace: scaledObject.Namespace,
    					Labels:    labels,
    				},
    				TypeMeta: metav1.TypeMeta{
    					APIVersion: "v2beta2",
    				},
    			}
    		...
    		return hpa, nil
    }
    ```
    
4. call actual [scale handlers](https://github.com/kedacore/keda/blob/main/controllers/keda/scaledobject_controller.go#L394) to handle request.
    
    ```go
    func (r *ScaledObjectReconciler) requestScaleLoop(logger logr.Logger, scaledObject *kedav1alpha1.ScaledObject) error {
    	logger.V(1).Info("Notify scaleHandler of an update in scaledObject")
    
    	key, err := cache.MetaNamespaceKeyFunc(scaledObject)
    	if err != nil {
    		logger.Error(err, "Error getting key for scaledObject")
    		return err
    	}
    
    	if err = r.scaleHandler.HandleScalableObject(scaledObject); err != nil {
    		return err
    	}
    
    	// store ScaledObject's current Generation
    	r.scaledObjectsGenerations.Store(key, scaledObject.Generation)
    
    	return nil
    }
    ```
    
    corresponded [handlers](https://github.com/kedacore/keda/blob/main/pkg/scaling/scale_handler.go) will be invoked based on [scaler type](https://keda.sh/docs/2.4/scalers/), take [cron](https://keda.sh/docs/2.4/scalers/cron/) as an example.
    
    ```go
    func (h *scaleHandler) HandleScalableObject(scalableObject interface{}) error {
    	...
    
    	// passing deep copy of ScaledObject/ScaledJob to the scaleLoop go routines, it's a precaution to not have global objects shared between threads
    	switch obj := scalableObject.(type) {
    	case *kedav1alpha1.ScaledObject:
    		go h.startPushScalers(ctx, withTriggers, obj.DeepCopy(), scalingMutex)
    		go h.startScaleLoop(ctx, withTriggers, obj.DeepCopy(), scalingMutex)
    	case *kedav1alpha1.ScaledJob:
    		go h.startPushScalers(ctx, withTriggers, obj.DeepCopy(), scalingMutex)
    		go h.startScaleLoop(ctx, withTriggers, obj.DeepCopy(), scalingMutex)
    	}
    	...
    }
    ```
    
5. [scale targets](https://github.com/kedacore/keda/blob/main/pkg/scaling/executor/scale_scaledobjects.go)
    
    ```go
    func (e *scaleExecutor) RequestScale(ctx context.Context, scaledObject *kedav1alpha1.ScaledObject, isActive bool, isError bool) {
    	...
    	if isActive {
    		switch {
    		case scaledObject.Spec.IdleReplicaCount != nil && currentReplicas < minReplicas,
    			e.scaleFromZeroOrIdle(ctx, logger, scaledObject, currentScale)
    		...
    		}
    	} else {
    		// isActive == false
    		switch {
    		case isError && scaledObject.Spec.Fallback != nil && scaledObject.Spec.Fallback.Replicas != 0:
    			e.doFallbackScaling(ctx, scaledObject, currentScale, logger, currentReplicas)
    		case scaledObject.Spec.IdleReplicaCount != nil && currentReplicas > *scaledObject.Spec.IdleReplicaCount,
    			currentReplicas > 0 && minReplicas == 0:
    			
    			e.scaleToZeroOrIdle(ctx, logger, scaledObject, currentScale)
    		case currentReplicas < minReplicas && scaledObject.Spec.IdleReplicaCount == nil:
    			_, err := e.updateScaleOnScaleTarget(ctx, scaledObject, currentScale, *scaledObject.Spec.MinReplicaCount)
    			if err == nil {
    				logger.Info("Successfully set ScaleTarget replicas count to ScaledObject minReplicaCount",
    					"Original Replicas Count", currentReplicas,
    					"New Replicas Count", *scaledObject.Spec.MinReplicaCount)
    			}
    			...
    		}
    	...
    	}
    
    func (e *scaleExecutor) updateScaleOnScaleTarget(ctx context.Context, scaledObject *kedav1alpha1.ScaledObject, scale *autoscalingv1.Scale, replicas int32) (int32, error) {
    	if scale == nil {
    		// Wasn't retrieved earlier, grab it now.
    		var err error
    		scale, err = e.getScaleTargetScale(ctx, scaledObject)
    		if err != nil {
    			return -1, err
    		}
    	}
    
    	// Update with requested repliacs.
    	currentReplicas := scale.Spec.Replicas
    	scale.Spec.Replicas = replicas
    
    	_, err := e.scaleClient.Scales(scaledObject.Namespace).Update(ctx, scaledObject.Status.ScaleTargetGVKR.GroupResource(), scale, metav1.UpdateOptions{})
    	return currentReplicas, err
    }
    ```
    
    simply speaking,
    
    - check if it's active. (in case of cron, condition is time slot)
    - compare desired replica and actual replica
    - use [scaleClient](https://www.notion.so/KEDA-Infrastructure-789c5b58479b49ab98bb6fc2172db981?pvs=21) to change replica of target object.
    
    ### keda-operator-metrics-apiserver
    
    it's basically just a [custom-metrics-server](https://github.com/kubernetes-sigs/custom-metrics-apiserver).
    
    1. entrance is under [adapter/**main.go**](https://github.com/kedacore/keda/blob/main/adapter/main.go)
        
        ```go
        func main() {
        	...
        
        	cmd := &Adapter{}
        
        	...
        	kedaProvider, err := cmd.makeProvider(time.Duration(globalHTTPTimeoutMS) * time.Millisecond)
        	if err != nil {
        		logger.Error(err, "making provider")
        		return
        	}
        	cmd.WithExternalMetrics(kedaProvider)
        
        	logger.Info(cmd.Message)
        	if err = cmd.Run(wait.NeverStop); err != nil {
        		return
        	}
        }
        ```
        
    2. actual logic is in [keda provider](https://github.com/kedacore/keda/blob/main/pkg/provider/provider.go) which implements custom-metrics-server interfaces.
        
        ```go
        type KedaProvider struct {
        	client           client.Client
        	values           map[provider.CustomMetricInfo]int64
        	externalMetrics  []externalMetric
        	scaleHandler     scaling.ScaleHandler
        	watchedNamespace string
        }
        ```