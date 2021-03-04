SuperEdge application-grid-wrapper源码分析
=========================================

## 前言

SuperEdge service group利用application-grid-wrapper实现拓扑感知，完成了同一个nodeunit内服务的闭环访问

在深入分析application-grid-wrapper之前，这里先简单介绍一下社区Kubernetes原生支持的[拓扑感知特性](https://kubernetes.io/docs/concepts/services-networking/service-topology/)

Kubernetes service topology awareness特性于v1.17发布alpha版本，用于实现路由拓扑以及就近访问特性。用户需要在service中添加topologyKeys字段标示拓扑key类型，只有具有相同拓扑域的endpoint会被访问到，目前有三种topologyKeys可供选择：

* "kubernetes.io/hostname"：访问本节点内(`kubernetes.io/hostname` label value相同)的endpoint，如果没有则service访问失败
* "topology.kubernetes.io/zone"：访问相同zone域内(`topology.kubernetes.io/zone` label value相同)的endpoint，如果没有则service访问失败
* "topology.kubernetes.io/region"：访问相同region域内(`topology.kubernetes.io/region` label value相同)的endpoint，如果没有则service访问失败

除了单独填写如上某一个拓扑key之外，还可以将这些key构造成列表进行填写，例如：`["kubernetes.io/hostname", "topology.kubernetes.io/zone", "topology.kubernetes.io/region"]`，这表示：优先访问本节点内的endpoint；如果不存在，则访问同一个zone内的endpoint；如果再不存在，则访问同一个region内的endpoint，如果都不存在则访问失败

另外，还可以在列表最后(只能最后一项)添加"*"表示：如果前面拓扑域都失败，则访问任何有效的endpoint，也即没有限制拓扑了，示例如下：

```yaml
# A Service that prefers node local, zonal, then regional endpoints but falls back to cluster wide endpoints.
apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  selector:
    app: my-app
  ports:
    - protocol: TCP
      port: 80
      targetPort: 9376
  topologyKeys:
    - "kubernetes.io/hostname"
    - "topology.kubernetes.io/zone"
    - "topology.kubernetes.io/region"
    - "*"
```

而service group实现的拓扑感知和社区对比，有如下区别：

* service group拓扑key可以自定义，也即为gridUniqKey，使用起来更加灵活；而社区实现目前只有三种选择："kubernetes.io/hostname"，"topology.kubernetes.io/zone"以及"topology.kubernetes.io/region"
* service group只能填写一个拓扑key，也即只能访问本拓扑域内有效的endpoint，无法访问其它拓扑域的endpoint；而社区可以通过topologyKey列表以及"*"实现其它备选拓扑域endpoint的访问

service group实现的拓扑感知，service配置如下：

```yaml
# A Service that only prefers node zone1al endpoints.
apiVersion: v1
kind: Service
metadata:
  annotations:
    topologyKeys: '["zone1"]'
  labels:
    superedge.io/grid-selector: servicegrid-demo
  name: servicegrid-demo-svc
spec:
  ports:
  - port: 80
    protocol: TCP
    targetPort: 8080
  selector:
    appGrid: echo
```

在介绍完service group实现的拓扑感知后，我们深入到源码分析实现细节。同样的，这里以一个使用示例开始分析：

```yaml
# step1: labels edge nodes
$ kubectl  get nodes
NAME    STATUS   ROLES    AGE   VERSION
node0   Ready    <none>   16d   v1.16.7
node1   Ready    <none>   16d   v1.16.7
node2   Ready    <none>   16d   v1.16.7
# nodeunit1(nodegroup and servicegroup zone1)
$ kubectl --kubeconfig config label nodes node0 zone1=nodeunit1  
# nodeunit2(nodegroup and servicegroup zone1)
$ kubectl --kubeconfig config label nodes node1 zone1=nodeunit2
$ kubectl --kubeconfig config label nodes node2 zone1=nodeunit2

...

# step3: deploy echo ServiceGrid
$ cat <<EOF | kubectl --kubeconfig config apply -f -
apiVersion: superedge.io/v1
kind: ServiceGrid
metadata:
  name: servicegrid-demo
  namespace: default
spec:
  gridUniqKey: zone1
  template:
    selector:
      appGrid: echo
    ports:
    - protocol: TCP
      port: 80
      targetPort: 8080
EOF
servicegrid.superedge.io/servicegrid-demo created
# note that there is only one relevant service generated
$ kubectl  get svc
NAME                   TYPE        CLUSTER-IP        EXTERNAL-IP   PORT(S)   AGE
kubernetes             ClusterIP   192.168.0.1       <none>        443/TCP   16d
servicegrid-demo-svc   ClusterIP   192.168.6.139     <none>        80/TCP    10m

# step4: access servicegrid-demo-svc(service topology and closed-looped)
# execute on node0
$ curl 192.168.6.139|grep "node name"
        node name:      node0
# execute on node1 and node2
$ curl 192.168.6.139|grep "node name"
        node name:      node2
$ curl 192.168.6.139|grep "node name"
        node name:      node1        
```

在创建完ServiceGrid CR后，ServiceGrid Controller负责根据ServiceGrid产生对应的service；而application-grid-wrapper根据service实现拓扑感知，下面依次分析

## ServiceGrid Controller分析

ServiceGrid Controller逻辑和DeploymentGrid Controller整体一致，如下：

* 1、创建并维护service group需要的若干CRDs(包括：ServiceGrid)
* 2、监听ServiceGrid event，并填充ServiceGrid到工作队列中；循环从队列中取出ServiceGrid进行解析，创建并且维护对应的service
* 3、监听service event，并将相关的ServiceGrid塞到工作队列中进行上述处理，协助上述逻辑达到整体reconcile逻辑

注意这里区别于DeploymentGrid Controller：

* 一个ServiceGrid对象只产生一个service
* 只需额外监听service event，无需监听node事件。因为node的CRUD与ServiceGrid无关

```go
func (sgc *ServiceGridController) syncServiceGrid(key string) error {
	startTime := time.Now()
	klog.V(4).Infof("Started syncing service grid %q (%v)", key, startTime)
	defer func() {
		klog.V(4).Infof("Finished syncing service grid %q (%v)", key, time.Since(startTime))
	}()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}

	sg, err := sgc.svcGridLister.ServiceGrids(namespace).Get(name)
	if errors.IsNotFound(err) {
		klog.V(2).Infof("service grid %v has been deleted", key)
		return nil
	}
	if err != nil {
		return err
	}

	if sg.Spec.GridUniqKey == "" {
		sgc.eventRecorder.Eventf(sg, corev1.EventTypeWarning, "Empty", "This service grid has an empty grid key")
		return nil
	}

	// get service workload list of this grid
	svcList, err := sgc.getServiceForGrid(sg)
	if err != nil {
		return err
	}

	if sg.DeletionTimestamp != nil {
		return nil
	}

	// sync service grid relevant services workload
	return sgc.reconcile(sg, svcList)
}

func (sgc *ServiceGridController) getServiceForGrid(sg *crdv1.ServiceGrid) ([]*corev1.Service, error) {
	svcList, err := sgc.svcLister.Services(sg.Namespace).List(labels.Everything())
	if err != nil {
		return nil, err
	}

	labelSelector, err := common.GetDefaultSelector(sg.Name)
	if err != nil {
		return nil, err
	}
	canAdoptFunc := controller.RecheckDeletionTimestamp(func() (metav1.Object, error) {
		fresh, err := sgc.crdClient.SuperedgeV1().ServiceGrids(sg.Namespace).Get(context.TODO(), sg.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if fresh.UID != sg.UID {
			return nil, fmt.Errorf("orignal service grid %v/%v is gone: got uid %v, wanted %v", sg.Namespace,
				sg.Name, fresh.UID, sg.UID)
		}
		return fresh, nil
	})

	cm := controller.NewServiceControllerRefManager(sgc.svcClient, sg, labelSelector, util.ControllerKind, canAdoptFunc)
	return cm.ClaimService(svcList)
}

func (sgc *ServiceGridController) reconcile(g *crdv1.ServiceGrid, svcList []*corev1.Service) error {
	var (
		adds    []*corev1.Service
		updates []*corev1.Service
		deletes []*corev1.Service
	)

	sgTargetSvcName := util.GetServiceName(g)
	isExistingSvc := false
	for _, svc := range svcList {
		if svc.Name == sgTargetSvcName {
			isExistingSvc = true
			template := util.KeepConsistence(g, svc)
			if !apiequality.Semantic.DeepEqual(template, svc) {
				updates = append(updates, template)
			}
		} else {
			deletes = append(deletes, svc)
		}
	}

	if !isExistingSvc {
		adds = append(adds, util.CreateService(g))
	}

	return sgc.syncService(adds, updates, deletes)
}
```

由于逻辑与DeploymentGrid类似，这里不展开细节，重点关注application-grid-wrapper部分

## application-grid-wrapper分析

在ServiceGrid Controller创建完service之后，application-grid-wrapper的作用就开始启动了：

```yaml
apiVersion: v1
kind: Service
metadata:
  annotations:
    topologyKeys: '["zone1"]'
  creationTimestamp: "2021-03-03T07:33:30Z"
  labels:
    superedge.io/grid-selector: servicegrid-demo
  name: servicegrid-demo-svc
  namespace: default
  ownerReferences:
  - apiVersion: superedge.io/v1
    blockOwnerDeletion: true
    controller: true
    kind: ServiceGrid
    name: servicegrid-demo
    uid: 78c74d3c-72ac-4e68-8c79-f1396af5a581
  resourceVersion: "127987090"
  selfLink: /api/v1/namespaces/default/services/servicegrid-demo-svc
  uid: 8130ba7b-c27e-4c3a-8ceb-4f6dd0178dfc
spec:
  clusterIP: 192.168.161.1
  ports:
  - port: 80
    protocol: TCP
    targetPort: 8080
  selector:
    appGrid: echo
  sessionAffinity: None
  type: ClusterIP
status:
  loadBalancer: {}
```

为了实现Kubernetes零侵入，需要在kube-proxy与apiserver通信之间添加一层wrapper，架构如下：

![](images/superedge_arch.png)

调用链路如下：

```
kube-proxy -> application-grid-wrapper -> lite-apiserver -> kube-apiserver
```

因此application-grid-wrapper会起服务，接受来自kube-proxy的请求，如下：

```go
func (s *interceptorServer) Run(debug bool, bindAddress string, insecure bool, caFile, certFile, keyFile string) error {
    ...
	klog.Infof("Start to run interceptor server")
	/* filter
	 */
	server := &http.Server{Addr: bindAddress, Handler: s.buildFilterChains(debug)}

	if insecure {
		return server.ListenAndServe()
	}
    ...
	server.TLSConfig = tlsConfig
	return server.ListenAndServeTLS("", "")
}

func (s *interceptorServer) buildFilterChains(debug bool) http.Handler {
	handler := http.Handler(http.NewServeMux())

	handler = s.interceptEndpointsRequest(handler)
	handler = s.interceptServiceRequest(handler)
	handler = s.interceptEventRequest(handler)
	handler = s.interceptNodeRequest(handler)
	handler = s.logger(handler)

	if debug {
		handler = s.debugger(handler)
	}

	return handler
}
```

这里会首先创建interceptorServer，然后注册处理函数，由外到内依次如下：

* debug：接受debug请求，返回wrapper pprof运行信息
* logger：打印请求日志
* node：接受kube-proxy node GET(/api/v1/nodes/{node})请求，并返回node信息
* event：接受kube-proxy events POST(/events)请求，并将请求转发给lite-apiserver
```go
func (s *interceptorServer) interceptEventRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/events") {
			handler.ServeHTTP(w, r)
			return
		}

		targetURL, _ := url.Parse(s.restConfig.Host)
		reverseProxy := httputil.NewSingleHostReverseProxy(targetURL)
		reverseProxy.Transport, _ = rest.TransportFor(s.restConfig)
		reverseProxy.ServeHTTP(w, r)
	})
}
```
* service：接受kube-proxy service List&Watch(/api/v1/services)请求，并根据storageCache内容返回(GetServices)
* endpoint：接受kube-proxy endpoint List&Watch(/api/v1/endpoints)请求，并根据storageCache内容返回(GetEndpoints)

下面先重点分析cache部分的逻辑，然后再回过头来分析具体的http handler List&Watch处理逻辑

wrapper为了实现拓扑感知，自己维护了一个cache，包括：node，service，endpoint。可以看到在setupInformers中注册了这三类资源的处理函数：

```go
type storageCache struct {
	// hostName is the nodeName of node which application-grid-wrapper deploys on
	hostName         string
	wrapperInCluster bool

	// mu lock protect the following map structure
	mu           sync.RWMutex
	servicesMap  map[types.NamespacedName]*serviceContainer
	endpointsMap map[types.NamespacedName]*endpointsContainer
	nodesMap     map[types.NamespacedName]*nodeContainer

	// service watch channel
	serviceChan chan<- watch.Event
	// endpoints watch channel
	endpointsChan chan<- watch.Event
}
...
func NewStorageCache(hostName string, wrapperInCluster bool, serviceNotifier, endpointsNotifier chan watch.Event) *storageCache {
	msc := &storageCache{
		hostName:         hostName,
		wrapperInCluster: wrapperInCluster,
		servicesMap:      make(map[types.NamespacedName]*serviceContainer),
		endpointsMap:     make(map[types.NamespacedName]*endpointsContainer),
		nodesMap:         make(map[types.NamespacedName]*nodeContainer),
		serviceChan:      serviceNotifier,
		endpointsChan:    endpointsNotifier,
	}

	return msc
}
...
func (s *interceptorServer) Run(debug bool, bindAddress string, insecure bool, caFile, certFile, keyFile string) error {
    ...
	if err := s.setupInformers(ctx.Done()); err != nil {
		return err
	}

	klog.Infof("Start to run interceptor server")
	/* filter
	 */
	server := &http.Server{Addr: bindAddress, Handler: s.buildFilterChains(debug)}
    ...
	return server.ListenAndServeTLS("", "")
}

func (s *interceptorServer) setupInformers(stop <-chan struct{}) error {
	klog.Infof("Start to run service and endpoints informers")
	noProxyName, err := labels.NewRequirement(apis.LabelServiceProxyName, selection.DoesNotExist, nil)
	if err != nil {
		klog.Errorf("can't parse proxy label, %v", err)
		return err
	}

	noHeadlessEndpoints, err := labels.NewRequirement(v1.IsHeadlessService, selection.DoesNotExist, nil)
	if err != nil {
		klog.Errorf("can't parse headless label, %v", err)
		return err
	}

	labelSelector := labels.NewSelector()
	labelSelector = labelSelector.Add(*noProxyName, *noHeadlessEndpoints)

	resyncPeriod := time.Minute * 5
	client := kubernetes.NewForConfigOrDie(s.restConfig)
	nodeInformerFactory := informers.NewSharedInformerFactory(client, resyncPeriod)
	informerFactory := informers.NewSharedInformerFactoryWithOptions(client, resyncPeriod,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.LabelSelector = labelSelector.String()
		}))

	nodeInformer := nodeInformerFactory.Core().V1().Nodes().Informer()
	serviceInformer := informerFactory.Core().V1().Services().Informer()
	endpointsInformer := informerFactory.Core().V1().Endpoints().Informer()

	/*
	 */
	nodeInformer.AddEventHandlerWithResyncPeriod(s.cache.NodeEventHandler(), resyncPeriod)
	serviceInformer.AddEventHandlerWithResyncPeriod(s.cache.ServiceEventHandler(), resyncPeriod)
	endpointsInformer.AddEventHandlerWithResyncPeriod(s.cache.EndpointsEventHandler(), resyncPeriod)

	go nodeInformer.Run(stop)
	go serviceInformer.Run(stop)
	go endpointsInformer.Run(stop)

	if !cache.WaitForNamedCacheSync("node", stop,
		nodeInformer.HasSynced,
		serviceInformer.HasSynced,
		endpointsInformer.HasSynced) {
		return fmt.Errorf("can't sync informers")
	}

	return nil
}

func (sc *storageCache) NodeEventHandler() cache.ResourceEventHandler {
	return &nodeHandler{cache: sc}
}

func (sc *storageCache) ServiceEventHandler() cache.ResourceEventHandler {
	return &serviceHandler{cache: sc}
}

func (sc *storageCache) EndpointsEventHandler() cache.ResourceEventHandler {
	return &endpointsHandler{cache: sc}
}
```

这里依次分析NodeEventHandler，ServiceEventHandler以及EndpointsEventHandler，如下：

1. NodeEventHandler

NodeEventHandler负责监听node资源相关event，并将node以及node Labels添加到storageCache.nodesMap中(key为nodeName，value为node以及node labels)

```go
func (nh *nodeHandler) add(node *v1.Node) {
	sc := nh.cache

	sc.mu.Lock()

	nodeKey := types.NamespacedName{Namespace: node.Namespace, Name: node.Name}
	klog.Infof("Adding node %v", nodeKey)
	sc.nodesMap[nodeKey] = &nodeContainer{
		node:   node,
		labels: node.Labels,
	}
	// update endpoints
	changedEps := sc.rebuildEndpointsMap()

	sc.mu.Unlock()

	for _, eps := range changedEps {
		sc.endpointsChan <- eps
	}
}

func (nh *nodeHandler) update(node *v1.Node) {
	sc := nh.cache

	sc.mu.Lock()

	nodeKey := types.NamespacedName{Namespace: node.Namespace, Name: node.Name}
	klog.Infof("Updating node %v", nodeKey)
	nodeContainer, found := sc.nodesMap[nodeKey]
	if !found {
		sc.mu.Unlock()
		klog.Errorf("Updating non-existed node %v", nodeKey)
		return
	}

	nodeContainer.node = node
	// return directly when labels of node stay unchanged
	if reflect.DeepEqual(node.Labels, nodeContainer.labels) {
		sc.mu.Unlock()
		return
	}
	nodeContainer.labels = node.Labels

	// update endpoints
	changedEps := sc.rebuildEndpointsMap()

	sc.mu.Unlock()

	for _, eps := range changedEps {
		sc.endpointsChan <- eps
	}
}
...
```

同时由于node的改变会影响endpoint，因此会调用rebuildEndpointsMap刷新storageCache.endpointsMap

```go
// rebuildEndpointsMap updates all endpoints stored in storageCache.endpointsMap dynamically and constructs relevant modified events
func (sc *storageCache) rebuildEndpointsMap() []watch.Event {
	evts := make([]watch.Event, 0)
	for name, endpointsContainer := range sc.endpointsMap {
		newEps := pruneEndpoints(sc.hostName, sc.nodesMap, sc.servicesMap, endpointsContainer.endpoints, sc.wrapperInCluster)
		if apiequality.Semantic.DeepEqual(newEps, endpointsContainer.modified) {
			continue
		}
		sc.endpointsMap[name].modified = newEps
		evts = append(evts, watch.Event{
			Type:   watch.Modified,
			Object: newEps,
		})
	}
	return evts
}
```

rebuildEndpointsMap是cache的核心函数，同时也是拓扑感知的算法实现：

```go
// pruneEndpoints filters endpoints using serviceTopology rules combined by services topologyKeys and node labels
func pruneEndpoints(hostName string,
	nodes map[types.NamespacedName]*nodeContainer,
	services map[types.NamespacedName]*serviceContainer,
	eps *v1.Endpoints, wrapperInCluster bool) *v1.Endpoints {

	epsKey := types.NamespacedName{Namespace: eps.Namespace, Name: eps.Name}

	if wrapperInCluster {
		eps = genLocalEndpoints(eps)
	}

	// dangling endpoints
	svc, ok := services[epsKey]
	if !ok {
		klog.V(4).Infof("Dangling endpoints %s, %+#v", eps.Name, eps.Subsets)
		return eps
	}

	// normal service
	if len(svc.keys) == 0 {
		klog.V(4).Infof("Normal endpoints %s, %+#v", eps.Name, eps.Subsets)
		return eps
	}

	// topology endpoints
	newEps := eps.DeepCopy()
	for si := range newEps.Subsets {
		subnet := &newEps.Subsets[si]
		subnet.Addresses = filterConcernedAddresses(svc.keys, hostName, nodes, subnet.Addresses)
		subnet.NotReadyAddresses = filterConcernedAddresses(svc.keys, hostName, nodes, subnet.NotReadyAddresses)
	}
	klog.V(4).Infof("Topology endpoints %s: subnets from %+#v to %+#v", eps.Name, eps.Subsets, newEps.Subsets)

	return newEps
}

// filterConcernedAddresses aims to filter out endpoints addresses within the same node unit
func filterConcernedAddresses(topologyKeys []string, hostName string, nodes map[types.NamespacedName]*nodeContainer,
	addresses []v1.EndpointAddress) []v1.EndpointAddress {
	hostNode, found := nodes[types.NamespacedName{Name: hostName}]
	if !found {
		return nil
	}

	filteredEndpointAddresses := make([]v1.EndpointAddress, 0)
	for i := range addresses {
		addr := addresses[i]
		if nodeName := addr.NodeName; nodeName != nil {
			epsNode, found := nodes[types.NamespacedName{Name: *nodeName}]
			if !found {
				continue
			}
			if hasIntersectionLabel(topologyKeys, hostNode.labels, epsNode.labels) {
				filteredEndpointAddresses = append(filteredEndpointAddresses, addr)
			}
		}
	}

	return filteredEndpointAddresses
}

func hasIntersectionLabel(keys []string, n1, n2 map[string]string) bool {
	if n1 == nil || n2 == nil {
		return false
	}

	for _, key := range keys {
		val1, v1found := n1[key]
		val2, v2found := n2[key]

		if v1found && v2found && val1 == val2 {
			return true
		}
	}

	return false
}
```

算法逻辑如下：

* 判断endpoint是否为default kubernetes service，如果是，则将该endpoint转化为wrapper所在边缘节点的lite-apiserver地址(127.0.0.1)和端口(51003)

```yaml
apiVersion: v1
kind: Endpoints
metadata:
  annotations:
    superedge.io/local-endpoint: 127.0.0.1
    superedge.io/local-port: "51003"
  name: kubernetes
  namespace: default
subsets:
- addresses:
  - ip: 172.31.0.60
  ports:
  - name: https
    port: xxx
    protocol: TCP
```

```go
func genLocalEndpoints(eps *v1.Endpoints) *v1.Endpoints {
	if eps.Namespace != metav1.NamespaceDefault || eps.Name != MasterEndpointName {
		return eps
	}

	klog.V(4).Infof("begin to gen local ep %v", eps)
	ipAddress, e := eps.Annotations[EdgeLocalEndpoint]
	if !e {
		return eps
	}

	portStr, e := eps.Annotations[EdgeLocalPort]
	if !e {
		return eps
	}

	klog.V(4).Infof("get local endpoint %s:%s", ipAddress, portStr)
	port, err := strconv.ParseInt(portStr, 10, 32)
	if err != nil {
		klog.Errorf("parse int %s err %v", portStr, err)
		return eps
	}

	ip := net.ParseIP(ipAddress)
	if ip == nil {
		klog.Warningf("parse ip %s nil", ipAddress)
		return eps
	}

	nep := eps.DeepCopy()
	nep.Subsets = []v1.EndpointSubset{
		{
			Addresses: []v1.EndpointAddress{
				{
					IP: ipAddress,
				},
			},
			Ports: []v1.EndpointPort{
				{
					Protocol: v1.ProtocolTCP,
					Port:     int32(port),
					Name:     "https",
				},
			},
		},
	}

	klog.V(4).Infof("gen new endpoint complete %v", nep)
	return nep
}
```

**这样做的目的是使边缘节点上的服务采用集群内(InCluster)方式访问的apiserver为本地的lite-apiserver，而不是云端的apiserver**

* 从storageCache.servicesMap cache中根据endpoint名称(namespace/name)取出对应service，如果该service没有topologyKeys则无需做拓扑转化(非service group)

```go
func getTopologyKeys(objectMeta *metav1.ObjectMeta) []string {
	if !hasTopologyKey(objectMeta) {
		return nil
	}

	var keys []string
	keyData := objectMeta.Annotations[TopologyAnnotationsKey]
	if err := json.Unmarshal([]byte(keyData), &keys); err != nil {
		klog.Errorf("can't parse topology keys %s, %v", keyData, err)
		return nil
	}

	return keys
}
```

* 调用filterConcernedAddresses过滤endpoint.Subsets Addresses以及NotReadyAddresses，只保留同一个service topologyKeys中的endpoint

```go
// filterConcernedAddresses aims to filter out endpoints addresses within the same node unit
func filterConcernedAddresses(topologyKeys []string, hostName string, nodes map[types.NamespacedName]*nodeContainer,
	addresses []v1.EndpointAddress) []v1.EndpointAddress {
	hostNode, found := nodes[types.NamespacedName{Name: hostName}]
	if !found {
		return nil
	}

	filteredEndpointAddresses := make([]v1.EndpointAddress, 0)
	for i := range addresses {
		addr := addresses[i]
		if nodeName := addr.NodeName; nodeName != nil {
			epsNode, found := nodes[types.NamespacedName{Name: *nodeName}]
			if !found {
				continue
			}
			if hasIntersectionLabel(topologyKeys, hostNode.labels, epsNode.labels) {
				filteredEndpointAddresses = append(filteredEndpointAddresses, addr)
			}
		}
	}

	return filteredEndpointAddresses
}

func hasIntersectionLabel(keys []string, n1, n2 map[string]string) bool {
	if n1 == nil || n2 == nil {
		return false
	}

	for _, key := range keys {
		val1, v1found := n1[key]
		val2, v2found := n2[key]

		if v1found && v2found && val1 == val2 {
			return true
		}
	}

	return false
}
```

**注意：如果wrapper所在边缘节点没有service topologyKeys标签，则也无法访问该service**

回到rebuildEndpointsMap，在调用pruneEndpoints刷新了同一个拓扑域内的endpoint后，会将修改后的endpoints赋值给storageCache.endpointsMap[endpoint].modified(该字段记录了拓扑感知后修改的endpoints)

```go
func (nh *nodeHandler) add(node *v1.Node) {
	sc := nh.cache

	sc.mu.Lock()

	nodeKey := types.NamespacedName{Namespace: node.Namespace, Name: node.Name}
	klog.Infof("Adding node %v", nodeKey)
	sc.nodesMap[nodeKey] = &nodeContainer{
		node:   node,
		labels: node.Labels,
	}
	// update endpoints
	changedEps := sc.rebuildEndpointsMap()

	sc.mu.Unlock()

	for _, eps := range changedEps {
		sc.endpointsChan <- eps
	}
}

// rebuildEndpointsMap updates all endpoints stored in storageCache.endpointsMap dynamically and constructs relevant modified events
func (sc *storageCache) rebuildEndpointsMap() []watch.Event {
	evts := make([]watch.Event, 0)
	for name, endpointsContainer := range sc.endpointsMap {
		newEps := pruneEndpoints(sc.hostName, sc.nodesMap, sc.servicesMap, endpointsContainer.endpoints, sc.wrapperInCluster)
		if apiequality.Semantic.DeepEqual(newEps, endpointsContainer.modified) {
			continue
		}
		sc.endpointsMap[name].modified = newEps
		evts = append(evts, watch.Event{
			Type:   watch.Modified,
			Object: newEps,
		})
	}
	return evts
}
```

另外，如果endpoints(拓扑感知后修改的endpoints)发生改变，会构建watch event，传递给endpoints handler(interceptEndpointsRequest)处理

2. ServiceEventHandler

storageCache.servicesMap结构体key为service名称(namespace/name)，value为serviceContainer，包含如下数据：

* svc：service对象
* keys：service topologyKeys

对于service资源的改动，这里用Update event说明：

```go
func (sh *serviceHandler) update(service *v1.Service) {
	sc := sh.cache

	sc.mu.Lock()
	serviceKey := types.NamespacedName{Namespace: service.Namespace, Name: service.Name}
	klog.Infof("Updating service %v", serviceKey)
	newTopologyKeys := getTopologyKeys(&service.ObjectMeta)
	serviceContainer, found := sc.servicesMap[serviceKey]
	if !found {
		sc.mu.Unlock()
		klog.Errorf("update non-existed service, %v", serviceKey)
		return
	}

	sc.serviceChan <- watch.Event{
		Type:   watch.Modified,
		Object: service,
	}

	serviceContainer.svc = service
	// return directly when topologyKeys of service stay unchanged
	if reflect.DeepEqual(serviceContainer.keys, newTopologyKeys) {
		sc.mu.Unlock()
		return
	}

	serviceContainer.keys = newTopologyKeys

	// update endpoints
	changedEps := sc.rebuildEndpointsMap()
	sc.mu.Unlock()

	for _, eps := range changedEps {
		sc.endpointsChan <- eps
	}
}
```

逻辑如下：

* 获取service topologyKeys
* 构建service event.Modified event
* 比较service topologyKeys与已经存在的是否有差异
* 如果有差异则更新topologyKeys，且调用rebuildEndpointsMap刷新该service对应的endpoints，如果endpoints发生变化，则构建endpoints watch event，传递给endpoints handler(interceptEndpointsRequest)处理

3. EndpointsEventHandler

storageCache.endpointsMap结构体key为endpoints名称(namespace/name)，value为endpointsContainer，包含如下数据：

* endpoints：拓扑修改前的endpoints
* modified：拓扑修改后的endpoints

对于endpoints资源的改动，这里用Update event说明：

```go
func (eh *endpointsHandler) update(endpoints *v1.Endpoints) {
	sc := eh.cache

	sc.mu.Lock()
	endpointsKey := types.NamespacedName{Namespace: endpoints.Namespace, Name: endpoints.Name}
	klog.Infof("Updating endpoints %v", endpointsKey)

	endpointsContainer, found := sc.endpointsMap[endpointsKey]
	if !found {
		sc.mu.Unlock()
		klog.Errorf("Updating non-existed endpoints %v", endpointsKey)
		return
	}
	endpointsContainer.endpoints = endpoints
	newEps := pruneEndpoints(sc.hostName, sc.nodesMap, sc.servicesMap, endpoints, sc.wrapperInCluster)
	changed := !apiequality.Semantic.DeepEqual(endpointsContainer.modified, newEps)
	if changed {
		endpointsContainer.modified = newEps
	}
	sc.mu.Unlock()

	if changed {
		sc.endpointsChan <- watch.Event{
			Type:   watch.Modified,
			Object: newEps,
		}
	}
}
```

逻辑如下：

* 更新endpointsContainer.endpoint为新的endpoints对象
* 调用pruneEndpoints获取拓扑刷新后的endpoints
* 比较endpointsContainer.modified与新刷新后的endpoints
* 如果有差异则更新endpointsContainer.modified，则构建endpoints watch event，传递给endpoints handler(interceptEndpointsRequest)处理

在分析完NodeEventHandler，ServiceEventHandler以及EndpointsEventHandler之后，我们回到具体的http handler List&Watch处理逻辑上，这里以endpoints为例：

```go
func (s *interceptorServer) interceptEndpointsRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/api/v1/endpoints") {
			handler.ServeHTTP(w, r)
			return
		}

		queries := r.URL.Query()
		acceptType := r.Header.Get("Accept")
		info, found := s.parseAccept(acceptType, s.mediaSerializer)
		if !found {
			klog.Errorf("can't find %s serializer", acceptType)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		encoder := scheme.Codecs.EncoderForVersion(info.Serializer, v1.SchemeGroupVersion)
		// list request
		if queries.Get("watch") == "" {
			w.Header().Set("Content-Type", info.MediaType)
			allEndpoints := s.cache.GetEndpoints()
			epsItems := make([]v1.Endpoints, 0, len(allEndpoints))
			for _, eps := range allEndpoints {
				epsItems = append(epsItems, *eps)
			}

			epsList := &v1.EndpointsList{
				Items: epsItems,
			}

			err := encoder.Encode(epsList, w)
			if err != nil {
				klog.Errorf("can't marshal endpoints list, %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			return
		}

		// watch request
		timeoutSecondsStr := r.URL.Query().Get("timeoutSeconds")
		timeout := time.Minute
		if timeoutSecondsStr != "" {
			timeout, _ = time.ParseDuration(fmt.Sprintf("%ss", timeoutSecondsStr))
		}

		timer := time.NewTimer(timeout)
		defer timer.Stop()

		flusher, ok := w.(http.Flusher)
		if !ok {
			klog.Errorf("unable to start watch - can't get http.Flusher: %#v", w)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		e := restclientwatch.NewEncoder(
			streaming.NewEncoder(info.StreamSerializer.Framer.NewFrameWriter(w),
				scheme.Codecs.EncoderForVersion(info.StreamSerializer, v1.SchemeGroupVersion)),
			encoder)
		if info.MediaType == runtime.ContentTypeProtobuf {
			w.Header().Set("Content-Type", runtime.ContentTypeProtobuf+";stream=watch")
		} else {
			w.Header().Set("Content-Type", runtime.ContentTypeJSON)
		}
		w.Header().Set("Transfer-Encoding", "chunked")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-timer.C:
				return
			case evt := <-s.endpointsWatchCh:
				klog.V(4).Infof("Send endpoint watch event: %+#v", evt)
				err := e.Encode(&evt)
				if err != nil {
					klog.Errorf("can't encode watch event, %v", err)
					return
				}

				if len(s.endpointsWatchCh) == 0 {
					flusher.Flush()
				}
			}
		}
	})
}
```

逻辑如下：

* 如果为List请求，则调用GetEndpoints获取拓扑修改后的endpoints列表，并返回

```go
func (sc *storageCache) GetEndpoints() []*v1.Endpoints {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	epList := make([]*v1.Endpoints, 0, len(sc.endpointsMap))
	for _, v := range sc.endpointsMap {
		epList = append(epList, v.modified)
	}
	return epList
}
```

* 如果为Watch请求，则不断从storageCache.endpointsWatchCh管道中接受watch event，并返回

interceptServiceRequest逻辑与interceptEndpointsRequest一致，这里不再赘述

## 总结

