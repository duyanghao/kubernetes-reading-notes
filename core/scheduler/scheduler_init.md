Kubernetes Scheduler Init
=========================

我们从[cmd/kube-scheduler/scheduler.go](https://github.com/kubernetes/kubernetes/blob/v1.17.4/cmd/kube-scheduler/scheduler.go)出发，阅读scheduler的初始化代码

```bash
$ tree cmd/kube-scheduler
cmd/kube-scheduler
├── app
│   ├── BUILD
│   ├── config
│   │   └── config.go
│   ├── options
│   │   ├── BUILD
│   │   ├── configfile.go
│   │   ├── options.go
│   │   └── options_test.go
│   ├── server.go
└── scheduler.go
```

```go
func main() {
	rand.Seed(time.Now().UnixNano())

	command := app.NewSchedulerCommand()

	// TODO: once we switch everything over to Cobra commands, we can go back to calling
	// utilflag.InitFlags() (by removing its pflag.Parse() call). For now, we have to set the
	// normalize func and add the go flag set by hand.
	pflag.CommandLine.SetNormalizeFunc(cliflag.WordSepNormalizeFunc)
	// utilflag.InitFlags()
	logs.InitLogs()
	defer logs.FlushLogs()

	if err := command.Execute(); err != nil {
		os.Exit(1)
	}
}
```

Kubernetes scheduler使用了[cobra](https://github.com/spf13/cobra)命令行库，首先构建`scheduler cobra command`，如下：

```go
// NewSchedulerCommand creates a *cobra.Command object with default parameters and registryOptions
func NewSchedulerCommand(registryOptions ...Option) *cobra.Command {
	opts, err := options.NewOptions()
	if err != nil {
		klog.Fatalf("unable to initialize command options: %v", err)
	}

	cmd := &cobra.Command{
		Use: "kube-scheduler",
		Long: `The Kubernetes scheduler is a policy-rich, topology-aware,
workload-specific function that significantly impacts availability, performance,
and capacity. The scheduler needs to take into account individual and collective
resource requirements, quality of service requirements, hardware/software/policy
constraints, affinity and anti-affinity specifications, data locality, inter-workload
interference, deadlines, and so on. Workload-specific requirements will be exposed
through the API as necessary.`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := runCommand(cmd, args, opts, registryOptions...); err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
		},
	}
    ...

	return cmd
}
```

初始化内容由`command.Execute()`执行，具体如下：

```go
// Run executes the scheduler based on the given configuration. It only returns on error or when context is done.
func Run(ctx context.Context, cc schedulerserverconfig.CompletedConfig, outOfTreeRegistryOptions ...Option) error {
	// To help debugging, immediately log version
	klog.V(1).Infof("Starting Kubernetes Scheduler version %+v", version.Get())

	// Create the scheduler.
	sched, err := scheduler.New(cc.Client,
		cc.InformerFactory,
		cc.PodInformer,
		cc.Recorder,
		ctx.Done(),
		scheduler.WithName(cc.ComponentConfig.SchedulerName),
		scheduler.WithAlgorithmSource(cc.ComponentConfig.AlgorithmSource),
		scheduler.WithHardPodAffinitySymmetricWeight(cc.ComponentConfig.HardPodAffinitySymmetricWeight),
		scheduler.WithPreemptionDisabled(cc.ComponentConfig.DisablePreemption),
		scheduler.WithPercentageOfNodesToScore(cc.ComponentConfig.PercentageOfNodesToScore),
		scheduler.WithBindTimeoutSeconds(cc.ComponentConfig.BindTimeoutSeconds),
		scheduler.WithFrameworkOutOfTreeRegistry(outOfTreeRegistry),
		scheduler.WithFrameworkPlugins(cc.ComponentConfig.Plugins),
		scheduler.WithFrameworkPluginConfig(cc.ComponentConfig.PluginConfig),
		scheduler.WithPodMaxBackoffSeconds(cc.ComponentConfig.PodMaxBackoffSeconds),
		scheduler.WithPodInitialBackoffSeconds(cc.ComponentConfig.PodInitialBackoffSeconds),
	)
	if err != nil {
		return err
	}

	// Start all informers.
	go cc.PodInformer.Informer().Run(ctx.Done())
	cc.InformerFactory.Start(ctx.Done())

	// Wait for all caches to sync before scheduling.
	cc.InformerFactory.WaitForCacheSync(ctx.Done())

	// If leader election is enabled, runCommand via LeaderElector until done and exit.
	if cc.LeaderElection != nil {
		cc.LeaderElection.Callbacks = leaderelection.LeaderCallbacks{
			OnStartedLeading: sched.Run,
			OnStoppedLeading: func() {
				klog.Fatalf("leaderelection lost")
			},
		}
		leaderElector, err := leaderelection.NewLeaderElector(*cc.LeaderElection)
		if err != nil {
			return fmt.Errorf("couldn't create leader elector: %v", err)
		}

		leaderElector.Run(ctx)

		return fmt.Errorf("lost lease")
	}

	// Leader election is disabled, so runCommand inline until done.
	sched.Run(ctx)
	return fmt.Errorf("finished without leader elect")
}
```

首先根据一系列配置构建`scheduler`，对应结构体如下：

```go
// Scheduler watches for new unscheduled pods. It attempts to find
// nodes that they fit on and writes bindings back to the api server.
type Scheduler struct {
	// It is expected that changes made via SchedulerCache will be observed
	// by NodeLister and Algorithm.
	SchedulerCache internalcache.Cache

	Algorithm core.ScheduleAlgorithm
	GetBinder func(pod *v1.Pod) Binder
	// PodConditionUpdater is used only in case of scheduling errors. If we succeed
	// with scheduling, PodScheduled condition will be updated in apiserver in /bind
	// handler so that binding and setting PodCondition it is atomic.
	podConditionUpdater podConditionUpdater
	// PodPreemptor is used to evict pods and update 'NominatedNode' field of
	// the preemptor pod.
	podPreemptor podPreemptor
	// Framework runs scheduler plugins at configured extension points.
	Framework framework.Framework

	// NextPod should be a function that blocks until the next pod
	// is available. We don't use a channel for this, because scheduling
	// a pod may take some amount of time and we don't want pods to get
	// stale while they sit in a channel.
	NextPod func() *framework.PodInfo

	// Error is called if there is an error. It is passed the pod in
	// question, and the error
	Error func(*framework.PodInfo, error)

	// Recorder is the EventRecorder to use
	Recorder events.EventRecorder

	// Close this to shut down the scheduler.
	StopEverything <-chan struct{}

	// VolumeBinder handles PVC/PV binding for the pod.
	VolumeBinder *volumebinder.VolumeBinder

	// Disable pod preemption or not.
	DisablePreemption bool

	// SchedulingQueue holds pods to be scheduled
	SchedulingQueue internalqueue.SchedulingQueue

	scheduledPodsHasSynced func() bool

	// The final configuration of the framework.
	Plugins      schedulerapi.Plugins
	PluginConfig []schedulerapi.PluginConfig
}
```

这个结构体在后续分析代码时还会用上，注意留意`SchedulingQueue`，`NextPod`，`SchedulerCache`以及`Algorithm`等字段

之后由选举leader执行`OnStartedLeading: sched.Run`，如下：

```go
// Run begins watching and scheduling. It waits for cache to be synced, then starts scheduling and blocked until the context is done.
func (sched *Scheduler) Run(ctx context.Context) {
	if !cache.WaitForCacheSync(ctx.Done(), sched.scheduledPodsHasSynced) {
		return
	}

	wait.UntilWithContext(ctx, sched.scheduleOne, 0)
}
```

而`sched.scheduleOne`则是调度算法整体框架，这个在后面会详细介绍，这里不展开

这里我们展开分析`New`逻辑，这是初始化scheduler的重点内容：

```go
// New returns a Scheduler
func New(client clientset.Interface,
	informerFactory informers.SharedInformerFactory,
	podInformer coreinformers.PodInformer,
	recorder events.EventRecorder,
	stopCh <-chan struct{},
	opts ...Option) (*Scheduler, error) {

	schedulerCache := internalcache.New(30*time.Second, stopEverything)
	volumeBinder := volumebinder.NewVolumeBinder(
		client,
		informerFactory.Core().V1().Nodes(),
		informerFactory.Storage().V1().CSINodes(),
		informerFactory.Core().V1().PersistentVolumeClaims(),
		informerFactory.Core().V1().PersistentVolumes(),
		informerFactory.Storage().V1().StorageClasses(),
		time.Duration(options.bindTimeoutSeconds)*time.Second,
	)

	configurator := &Configurator{
		client:                         client,
		informerFactory:                informerFactory,
		podInformer:                    podInformer,
		volumeBinder:                   volumeBinder,
		schedulerCache:                 schedulerCache,
		StopEverything:                 stopEverything,
		hardPodAffinitySymmetricWeight: options.hardPodAffinitySymmetricWeight,
		disablePreemption:              options.disablePreemption,
		percentageOfNodesToScore:       options.percentageOfNodesToScore,
		bindTimeoutSeconds:             options.bindTimeoutSeconds,
		podInitialBackoffSeconds:       options.podInitialBackoffSeconds,
		podMaxBackoffSeconds:           options.podMaxBackoffSeconds,
		enableNonPreempting:            utilfeature.DefaultFeatureGate.Enabled(kubefeatures.NonPreemptingPriority),
		registry:                       registry,
		plugins:                        options.frameworkPlugins,
		pluginConfig:                   options.frameworkPluginConfig,
		pluginConfigProducerRegistry:   options.frameworkConfigProducerRegistry,
		nodeInfoSnapshot:               snapshot,
		algorithmFactoryArgs: AlgorithmFactoryArgs{
			SharedLister:                   snapshot,
			InformerFactory:                informerFactory,
			VolumeBinder:                   volumeBinder,
			HardPodAffinitySymmetricWeight: options.hardPodAffinitySymmetricWeight,
		},
		configProducerArgs: &frameworkplugins.ConfigProducerArgs{},
	}

	metrics.Register()

	var sched *Scheduler
	source := options.schedulerAlgorithmSource
	switch {
	case source.Provider != nil:
		// Create the config from a named algorithm provider.
		sc, err := configurator.CreateFromProvider(*source.Provider)
		if err != nil {
			return nil, fmt.Errorf("couldn't create scheduler using provider %q: %v", *source.Provider, err)
		}
		sched = sc
	case source.Policy != nil:
		// Create the config from a user specified policy source.
		policy := &schedulerapi.Policy{}
		switch {
		case source.Policy.File != nil:
			if err := initPolicyFromFile(source.Policy.File.Path, policy); err != nil {
				return nil, err
			}
		case source.Policy.ConfigMap != nil:
			if err := initPolicyFromConfigMap(client, source.Policy.ConfigMap, policy); err != nil {
				return nil, err
			}
		}
		sc, err := configurator.CreateFromConfig(*policy)
		if err != nil {
			return nil, fmt.Errorf("couldn't create scheduler from policy: %v", err)
		}
		sched = sc
	default:
		return nil, fmt.Errorf("unsupported algorithm source: %v", source)
	}
	// Additional tweaks to the config produced by the configurator.
	sched.Recorder = recorder
	sched.DisablePreemption = options.disablePreemption
	sched.StopEverything = stopEverything
	sched.podConditionUpdater = &podConditionUpdaterImpl{client}
	sched.podPreemptor = &podPreemptorImpl{client}
	sched.scheduledPodsHasSynced = podInformer.Informer().HasSynced

	AddAllEventHandlers(sched, options.schedulerName, informerFactory, podInformer)
	return sched, nil
}
```

可以看到前面是初始化`Configurator`逻辑，都是为了后面构建scheduler，而无论是从`algorithm provider`还是`user specified policy source`算法源，都会调用如下函数构建schduler，具体如下：

```go
// CreateFromKeys creates a scheduler from a set of registered fit predicate keys and priority keys.
func (c *Configurator) CreateFromKeys(predicateKeys, priorityKeys sets.String, extenders []algorithm.SchedulerExtender) (*Scheduler, error) {
	klog.V(2).Infof("Creating scheduler with fit predicates '%v' and priority functions '%v'", predicateKeys, priorityKeys)

	predicateFuncs, pluginsForPredicates, pluginConfigForPredicates, err := c.getPredicateConfigs(predicateKeys)
	if err != nil {
		return nil, err
	}

	priorityConfigs, pluginsForPriorities, pluginConfigForPriorities, err := c.getPriorityConfigs(priorityKeys)
	if err != nil {
		return nil, err
	}

	podQueue := internalqueue.NewSchedulingQueue(
		c.StopEverything,
		framework,
		internalqueue.WithPodInitialBackoffDuration(time.Duration(c.podInitialBackoffSeconds)*time.Second),
		internalqueue.WithPodMaxBackoffDuration(time.Duration(c.podMaxBackoffSeconds)*time.Second),
	)

	go func() {
		<-c.StopEverything
		podQueue.Close()
	}()

	algo := core.NewGenericScheduler(
		c.schedulerCache,
		podQueue,
		predicateFuncs,
		predicateMetaProducer,
		priorityConfigs,
		priorityMetaProducer,
		c.nodeInfoSnapshot,
		framework,
		extenders,
		c.volumeBinder,
		c.informerFactory.Core().V1().PersistentVolumeClaims().Lister(),
		GetPodDisruptionBudgetLister(c.informerFactory),
		c.alwaysCheckAllPredicates,
		c.disablePreemption,
		c.percentageOfNodesToScore,
		c.enableNonPreempting,
	)

	return &Scheduler{
		SchedulerCache:  c.schedulerCache,
		Algorithm:       algo,
		GetBinder:       getBinderFunc(c.client, extenders),
		Framework:       framework,
		NextPod:         internalqueue.MakeNextPodFunc(podQueue),
		Error:           MakeDefaultErrorFunc(c.client, podQueue, c.schedulerCache),
		StopEverything:  c.StopEverything,
		VolumeBinder:    c.volumeBinder,
		SchedulingQueue: podQueue,
		Plugins:         plugins,
		PluginConfig:    pluginConfig,
	}, nil
}
```

这里我们主要看`getPredicateConfigs`和`getPriorityConfigs`。首先是`getPredicateConfigs`，该函数负责预选策略：

```go
// getPredicateConfigs returns predicates configuration: ones that will run as fitPredicates and ones that will run
// as framework plugins. Specifically, a predicate will run as a framework plugin if a plugin config producer was
// registered for that predicate.
// Note that the framework executes plugins according to their order in the Plugins list, and so predicates run as plugins
// are added to the Plugins list according to the order specified in predicates.Ordering().
func (c *Configurator) getPredicateConfigs(predicateKeys sets.String) (map[string]predicates.FitPredicate, *schedulerapi.Plugins, []schedulerapi.PluginConfig, error) {
	allFitPredicates, err := getFitPredicateFunctions(predicateKeys, c.algorithmFactoryArgs)
	if err != nil {
		return nil, nil, nil, err
	}

	if c.pluginConfigProducerRegistry == nil {
		return allFitPredicates, nil, nil, nil
	}

	asPlugins := sets.NewString()
	asFitPredicates := make(map[string]predicates.FitPredicate)
	frameworkConfigProducers := c.pluginConfigProducerRegistry.PredicateToConfigProducer

	// First, identify the predicates that will run as actual fit predicates, and ones
	// that will run as framework plugins.
	for predicateKey := range allFitPredicates {
		if _, exist := frameworkConfigProducers[predicateKey]; exist {
			asPlugins.Insert(predicateKey)
		} else {
			asFitPredicates[predicateKey] = allFitPredicates[predicateKey]
		}
	}

	// Second, create the framework plugin configurations, and place them in the order
	// that the corresponding predicates were supposed to run.
	var plugins schedulerapi.Plugins
	var pluginConfig []schedulerapi.PluginConfig

	for _, predicateKey := range predicates.Ordering() {
		if asPlugins.Has(predicateKey) {
			producer := frameworkConfigProducers[predicateKey]
			p, pc := producer(*c.configProducerArgs)
			plugins.Append(&p)
			pluginConfig = append(pluginConfig, pc...)
			asPlugins.Delete(predicateKey)
		}
	}

	// Third, add the rest in no specific order.
	for predicateKey := range asPlugins {
		producer := frameworkConfigProducers[predicateKey]
		p, pc := producer(*c.configProducerArgs)
		plugins.Append(&p)
		pluginConfig = append(pluginConfig, pc...)
	}

	return asFitPredicates, &plugins, pluginConfig, nil
}
```

返回预选策略`map[string]predicates.FitPredicate`，结构体如下：

```go
// FitPredicate is a function that indicates if a pod fits into an existing node.
// The failure information is given by the error.
type FitPredicate func(pod *v1.Pod, meta Metadata, nodeInfo *schedulernodeinfo.NodeInfo) (bool, []PredicateFailureReason, error)
```

预选map中，每个key代表一种预选算法名称，对应的FitPredicate(value)代表具体执行逻辑

其次是`getPriorityConfigs`，该函数负责优选策略：

```go
// getPriorityConfigs returns priorities configuration: ones that will run as priorities and ones that will run
// as framework plugins. Specifically, a priority will run as a framework plugin if a plugin config producer was
// registered for that priority.
func (c *Configurator) getPriorityConfigs(priorityKeys sets.String) ([]priorities.PriorityConfig, *schedulerapi.Plugins, []schedulerapi.PluginConfig, error) {
	allPriorityConfigs, err := getPriorityFunctionConfigs(priorityKeys, c.algorithmFactoryArgs)
	if err != nil {
		return nil, nil, nil, err
	}

	if c.pluginConfigProducerRegistry == nil {
		return allPriorityConfigs, nil, nil, nil
	}

	var priorityConfigs []priorities.PriorityConfig
	var plugins schedulerapi.Plugins
	var pluginConfig []schedulerapi.PluginConfig
	frameworkConfigProducers := c.pluginConfigProducerRegistry.PriorityToConfigProducer
	for _, p := range allPriorityConfigs {
		if producer, exist := frameworkConfigProducers[p.Name]; exist {
			args := *c.configProducerArgs
			args.Weight = int32(p.Weight)
			pl, pc := producer(args)
			plugins.Append(&pl)
			pluginConfig = append(pluginConfig, pc...)
		} else {
			priorityConfigs = append(priorityConfigs, p)
		}
	}
	return priorityConfigs, &plugins, pluginConfig, nil
}
```

返回优选策略`[]priorities.PriorityConfig`，结构体如下：

```go
// PriorityConfig is a config used for a priority function.
type PriorityConfig struct {
	Name   string
	Map    PriorityMapFunction
	Reduce PriorityReduceFunction
	Weight int64
}
```

该结构体中，name代表优选算法名称，map和reduce代表了该种优选算法对应的两种执行函数，这个我们在优选算法中会具体介绍。而weight则代表了该种优选算法权重(每种优选算法都有一个属于自己的权重)

这样以后，scheduler的预选和优选算法就确定了。接下来我们会分析scheduler框架……