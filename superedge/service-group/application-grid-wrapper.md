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



## 总结