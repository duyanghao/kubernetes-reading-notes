SuperEdge DeploymentGrid源码分析
===============================

SuperEdge目前支持两种工作负载类型：

* deployment-grid：适用于无状态服务，对应Kubernetes deployment负载类型，会在每个nodeunit中产生相对应的deployment，并利用service topology awareness(拓扑感知)实现闭环访问
* statefulset-grid：适用于有状态服务，对应Kubernetes statefulset负载类型，会在每个nodeunit中产生相对应的statefulset，并利用拓扑感知实现闭环访问

本章主要对deployment-grid进行源码分析。这里从一个示例开始：

## 示例

```bash
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

# step2: deploy echo DeploymentGrid
$ cat <<EOF | kubectl --kubeconfig config apply -f -
apiVersion: superedge.io/v1
kind: DeploymentGrid
metadata:
  name: deploymentgrid-demo
  namespace: default
spec:
  gridUniqKey: zone1
  template:
    replicas: 2
    selector:
      matchLabels:
        appGrid: echo
    strategy: {}
    template:
      metadata:
        creationTimestamp: null
        labels:
          appGrid: echo
      spec:
        containers:
        - image: gcr.io/kubernetes-e2e-test-images/echoserver:2.2
          name: echo
          ports:
          - containerPort: 8080
            protocol: TCP
          env:
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            - name: POD_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
            - name: POD_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
            - name: POD_IP
              valueFrom:
                fieldRef:
                  fieldPath: status.podIP
          resources: {}
EOF
deploymentgrid.superedge.io/deploymentgrid-demo created

# note that there are two deployments generated and deployed into both nodeunit1 and nodeunit2
$ kubectl  get deploy
NAME                            READY   UP-TO-DATE   AVAILABLE   AGE
deploymentgrid-demo-nodeunit1   2/2     2            2           5m50s
deploymentgrid-demo-nodeunit2   2/2     2            2           5m50s
$ kubectl  get pods -o wide
NAME                                             READY   STATUS    RESTARTS   AGE     IP            NODE    NOMINATED NODE   READINESS GATES
deploymentgrid-demo-nodeunit1-65bbb7c6bb-6lcmt   1/1     Running   0          5m34s   172.16.0.16   node0   <none>           <none>
deploymentgrid-demo-nodeunit1-65bbb7c6bb-hvmlg   1/1     Running   0          6m10s   172.16.0.15   node0   <none>           <none>
deploymentgrid-demo-nodeunit2-56dd647d7-fh2bm    1/1     Running   0          5m34s   172.16.1.12   node1   <none>           <none>
deploymentgrid-demo-nodeunit2-56dd647d7-gb2j8    1/1     Running   0          6m10s   172.16.2.9    node2   <none>           <none>    
```

## 源码分析

deployment-grid-controller是典型的operator开发模式，CRD为DeploymentGrid，controller负责监听该CRD event并 创建&维护 对应nodeunit的deployment。总体逻辑很简单，如下：

* 1、创建并维护service group需要的若干CRDs(包括：DeploymentGrid)
* 2、监听DeploymentGrid event，并填充DeploymentGrid到工作队列中；循环从队列中取出DeploymentGrid并 创建&维护 各nodeunit对应的deployment
* 3、监听deployment以及node event，并将相关的DeploymentGrid塞到工作队列中进行上述处理

下面依次对上述环节进行介绍：

### crdPreparator - 创建并维护service group对应的若干CRDs

application-grid-controller启动后会构建crdPreparator：

```go
func runController(parent context.Context,
	apiextensionClient *apiextclientset.Clientset, kubeClient *clientset.Clientset, crdClient *crdClientset.Clientset,
	workerNum, syncPeriod int) {

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	// Create and wait for CRDs ready
	crdP := prepare.NewCRDPreparator(apiextensionClient)
	if err := crdP.Prepare(ctx.Done(), schema.GroupVersionKind{
		Group:   superedge.GroupName,
		Version: superedge.Version,
		Kind:    deploymentutil.ControllerKind.Kind,
	}, schema.GroupVersionKind{
		Group:   superedge.GroupName,
		Version: superedge.Version,
		Kind:    statefulsetutil.ControllerKind.Kind,
	}, schema.GroupVersionKind{
		Group:   superedge.GroupName,
		Version: superedge.Version,
		Kind:    serviceutil.ControllerKind.Kind,
	}); err != nil {
		klog.Fatalf("Create and wait for CRDs ready failed: %v", err)
	}

	controllerConfig := config.NewControllerConfig(crdClient, kubeClient, time.Second*time.Duration(syncPeriod))
	deploymentGridController := deployment.NewDeploymentGridController(
		controllerConfig.DeploymentGridInformer, controllerConfig.DeploymentInformer, controllerConfig.NodeInformer,
		kubeClient, crdClient)
    ...

	controllerConfig.Run(ctx.Done())
	go deploymentGridController.Run(workerNum, ctx.Done())
	<-ctx.Done()
}
```

crdPreparator.Prepare调用prepareCRDs执行CRDs初始的创建和检查工作：

```go
func (p *crdPreparator) Prepare(stopCh <-chan struct{}, gvks ...schema.GroupVersionKind) error {
	if len(gvks) == 0 {
		return nil
	}
	// First of all, create or update edge CRDs
	err := p.prepareCRDs(gvks...)
	if err != nil {
		return err
	}
	// Loop background
	go wait.Until(func() {
		p.prepareCRDs(gvks...)
	}, time.Minute, stopCh)
	return nil
}

func (p *crdPreparator) prepareCRDs(gvks ...schema.GroupVersionKind) error {
	// create or update specified edge CRDs
	for _, gvk := range gvks {
		curCRD, err := p.createOrUpdateCRD(gvk)
		if err != nil {
			return err
		}
		if err := p.waitCRD(curCRD.Name); err != nil {
			return err
		}
	}
	return nil
}
```

其中createOrUpdateCRD执行逻辑如下：

* 检查CRD是否存在，若不存在则按照CRDs yamls(common/deploymentgrid-crd.go)进行创建
* 检查已经存在的CRD是否和对应yaml字段保持一致(CRD.Spec.Validation以及CRD.Spec.Versions字段内容)，如果不一致，则更新CRD(reconcile) 

而waitCRD则负责等待CRD就绪(crd.Status.Conditions.Status == ConditionTrue)

在执行完一遍prepareCRDs后，CRDs已经创建完成并且就绪，接着每隔一分钟异步调用prepareCRDs对这些CRDs不断检查和调整，确保CRD都是service group所需要且正常的

### DeploymentGrid Controller主体逻辑

DeploymentGrid Controller主体逻辑如下：

1、监听DeploymentGrid CR event，并根据具体event填充workqueue

```go
func (dgc *DeploymentGridController) addDeploymentGrid(obj interface{}) {
	dg := obj.(*crdv1.DeploymentGrid)
	klog.V(4).Infof("Adding deployment grid %s", dg.Name)
	dgc.enqueueDeploymentGrid(dg)
}

func (dgc *DeploymentGridController) updateDeploymentGrid(oldObj, newObj interface{}) {
	oldDg := oldObj.(*crdv1.DeploymentGrid)
	curDg := newObj.(*crdv1.DeploymentGrid)
	klog.V(4).Infof("Updating deployment grid %s", oldDg.Name)
	if curDg.ResourceVersion == oldDg.ResourceVersion {
		// Periodic resync will send update events for all known DeploymentGrids.
		// Two different versions of the same DeploymentGrid will always have different RVs.
		return
	}
	dgc.enqueueDeploymentGrid(curDg)
}

func (dgc *DeploymentGridController) deleteDeploymentGrid(obj interface{}) {
	dg, ok := obj.(*crdv1.DeploymentGrid)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("Couldn't get object from tombstone %#v", obj))
			return
		}
		dg, ok = tombstone.Obj.(*crdv1.DeploymentGrid)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("Tombstone contained object that is not a deployment grid %#v", obj))
			return
		}
	}
	klog.V(4).Infof("Deleting deployment grid %s", dg.Name)
	dgc.enqueueDeploymentGrid(dg)
}

func (dgc *DeploymentGridController) enqueue(deploymentGrid *crdv1.DeploymentGrid) {
	key, err := controller.KeyFunc(deploymentGrid)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't get key for object %#v: %v", deploymentGrid, err))
		return
	}

	dgc.queue.Add(key)
}
```

2、不断消费workqueue，并对每个deploymentGrid执行syncDeploymentGrid同步函数

```go
func (dgc *DeploymentGridController) Run(workers int, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer dgc.queue.ShutDown()

	klog.Infof("Starting deployment grid controller")
	defer klog.Infof("Shutting down deployment grid controller")

	if !cache.WaitForNamedCacheSync("deployment-grid", stopCh,
		dgc.dpGridListerSynced, dgc.dpListerSynced, dgc.nodeListerSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.Until(dgc.worker, time.Second, stopCh)
	}
	<-stopCh
}

func (dgc *DeploymentGridController) worker() {
	for dgc.processNextWorkItem() {
	}
}

func (dgc *DeploymentGridController) processNextWorkItem() bool {
	key, quit := dgc.queue.Get()
	if quit {
		return false
	}
	defer dgc.queue.Done(key)

	err := dgc.syncHandler(key.(string))
	dgc.handleErr(err, key)

	return true
}

func (dgc *DeploymentGridController) handleErr(err error, key interface{}) {
	if err == nil {
		dgc.queue.Forget(key)
		return
	}

	if dgc.queue.NumRequeues(key) < common.MaxRetries {
		klog.V(2).Infof("Error syncing deployment grid %v: %v", key, err)
		dgc.queue.AddRateLimited(key)
		return
	}

	utilruntime.HandleError(err)
	klog.V(2).Infof("Dropping deployment grid %q out of the queue: %v", key, err)
	dgc.queue.Forget(key)
}
```

3、根据deploymentGrid定义创建对应各nodeunit的deployment

```go
func (dgc *DeploymentGridController) syncDeploymentGrid(key string) error {
	startTime := time.Now()
	klog.V(4).Infof("Started syncing deployment grid %q (%v)", key, startTime)
	defer func() {
		klog.V(4).Infof("Finished syncing deployment grid %q (%v)", key, time.Since(startTime))
	}()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}

	dg, err := dgc.dpGridLister.DeploymentGrids(namespace).Get(name)
	if errors.IsNotFound(err) {
		klog.V(2).Infof("deployment grid %v has been deleted", key)
		return nil
	}
	if err != nil {
		return err
	}

	if dg.Spec.GridUniqKey == "" {
		dgc.eventRecorder.Eventf(dg, corev1.EventTypeWarning, "Empty", "This deployment-grid has an empty grid key")
		return nil
	}

	// get deployment workload list of this grid
	dpList, err := dgc.getDeploymentForGrid(dg)
	if err != nil {
		return err
	}

	// get all grid labels in all nodes
	gridValues, err := common.GetGridValuesFromNode(dgc.nodeLister, dg.Spec.GridUniqKey)
	if err != nil {
		return err
	}

	// sync deployment grid workload status
	if dg.DeletionTimestamp != nil {
		return dgc.syncStatus(dg, dpList, gridValues)
	}

	// sync deployment grid status and its relevant deployments workload
	return dgc.reconcile(dg, dpList, gridValues)
}
```

具体来说细节处理如下：

* 调用getDeploymentForGrid获取deployment列表，满足：`superedge.io/grid-selector`label为deploymentGrid名称；同时ownerReferences为该deploymentGrid对象

```go
func (dgc *DeploymentGridController) getDeploymentForGrid(dg *crdv1.DeploymentGrid) ([]*appsv1.Deployment, error) {
	dpList, err := dgc.dpLister.Deployments(dg.Namespace).List(labels.Everything())
	if err != nil {
		return nil, err
	}

	labelSelector, err := common.GetDefaultSelector(dg.Name)
	if err != nil {
		return nil, err
	}
	canAdoptFunc := controller.RecheckDeletionTimestamp(func() (metav1.Object, error) {
		fresh, err := dgc.crdClient.SuperedgeV1().DeploymentGrids(dg.Namespace).Get(context.TODO(), dg.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if fresh.UID != dg.UID {
			return nil, fmt.Errorf("orignal Deployment-grid %v/%v is gone: got uid %v, wanted %v", dg.Namespace,
				dg.Name, fresh.UID, dg.UID)
		}
		return fresh, nil
	})

	cm := controller.NewDeploymentControllerRefManager(dgc.dpClient, dg, labelSelector, util.ControllerKind, canAdoptFunc)
	return cm.ClaimDeployment(dpList)
}
```

* 根据边缘节点列表以及deploymentGrid对象的GridUniqKey字段，构建nodeunit列表

```go
...
	// get all grid labels in all nodes
	gridValues, err := common.GetGridValuesFromNode(dgc.nodeLister, dg.Spec.GridUniqKey)
	if err != nil {
		return err
	}
...

func GetGridValuesFromNode(nodeLister corelisters.NodeLister, gridUniqKey string) ([]string, error) {
	labelSelector := labels.NewSelector()
	gridRequirement, err := labels.NewRequirement(gridUniqKey, selection.Exists, nil)
	if err != nil {
		return nil, err
	}
	labelSelector = labelSelector.Add(*gridRequirement)

	nodes, err := nodeLister.List(labelSelector)
	if err != nil {
		return nil, err
	}

	var values []string
	for _, n := range nodes {
		if gridVal := n.Labels[gridUniqKey]; gridVal != "" {
			values = append(values, gridVal)
		}
	}
	return values, nil
}
```

其中每个边缘节点的不同GridUniqKey label value对应了一个nodeunit

* 调用reconcile，对比第一步获取的deployment列表和第二步获取的nodeunit列表，对deployment进行创建，更新以及删除操作

```go
func (dgc *DeploymentGridController) reconcile(dg *crdv1.DeploymentGrid, dpList []*appsv1.Deployment, gridValues []string) error {
	existedDPMap := make(map[string]*appsv1.Deployment)

	for _, dp := range dpList {
		existedDPMap[dp.Name] = dp
	}

	wanted := sets.NewString()
	for _, v := range gridValues {
		wanted.Insert(util.GetDeploymentName(dg, v))
	}

	var (
		adds    []*appsv1.Deployment
		updates []*appsv1.Deployment
		deletes []*appsv1.Deployment
	)

	for _, v := range gridValues {
		name := util.GetDeploymentName(dg, v)

		dp, found := existedDPMap[name]
		if !found {
			adds = append(adds, util.CreateDeployment(dg, v))
			continue
		}

		template := util.KeepConsistence(dg, dp, v)
		if !apiequality.Semantic.DeepEqual(template, dp) {
			updates = append(updates, template)
		}
	}

	// If deployment's name is not matched with grid value but has the same selector, we remove it.
	for _, dp := range dpList {
		if !wanted.Has(dp.Name) {
			deletes = append(deletes, dp)
		}
	}

	if err := dgc.syncDeployment(adds, updates, deletes); err != nil {
		return err
	}

	return dgc.syncStatus(dg, dpList, gridValues)
}

func KeepConsistence(dg *crdv1.DeploymentGrid, dp *appsv1.Deployment, gridValue string) *appsv1.Deployment {
	// NEVER modify objects from the store. It's a read-only, local cache.
	// You can use DeepCopy() to make a deep copy of original object and modify this copy
	// Or create a copy manually for better performance
	copyObj := dp.DeepCopy()
	// Append existed DeploymentGrid labels to deployment to be checked
	if dg.Labels != nil {
		copyObj.Labels = dg.Labels
		copyObj.Labels[common.GridSelectorName] = dg.Name
		copyObj.Labels[common.GridSelectorUniqKeyName] = dg.Spec.GridUniqKey
	} else {
		copyObj.Labels = map[string]string{
			common.GridSelectorName:        dg.Name,
			common.GridSelectorUniqKeyName: dg.Spec.GridUniqKey,
		}
	}
	copyObj.Spec.Replicas = dg.Spec.Template.Replicas
	// Spec.selector field is immutable
	// copyObj.Spec.Selector = dg.Spec.Template.Selector
	// TODO: this line will cause DeepEqual fails always since actual generated deployment.Spec.Template is definitely different with ones of relevant deploymentGrid
	copyObj.Spec.Template = dg.Spec.Template.Template
	// Append existed DeploymentGrid NodeSelector to deployment to be checked
	if dg.Spec.Template.Template.Spec.NodeSelector != nil {
		copyObj.Spec.Template.Spec.NodeSelector[dg.Spec.GridUniqKey] = gridValue
	} else {
		copyObj.Spec.Template.Spec.NodeSelector = map[string]string{
			dg.Spec.GridUniqKey: gridValue,
		}
	}

	return copyObj
}
```

展开reconcile具体细节如下：

1）遍历nodeunit列表，根据deploymentGrid定义构建出每个nodeunit对应的deployment
2）将预构建的deployment对象与实际deployment进行对比，若部分字段有变化则添加到updates列表中
3）如果实际deployment列表中不存在预构建的deployment，则将该对象添加到adds列表中
4）如果实际deployment列表中存在不需要创建的对象，则将该对象添加到deletes列表中
5）执行syncDeployment，对adds，updates，deletes列表对象分别执行Create，Update以及Delete操作
6）执行syncStatus，将deploymentGrid对应各deployment.Status添加到deploymentGrid.Status.States map中

### 补充Controller逻辑

deploymentGrid除了主体的controller之外，还需要补充其它两种相关资源的controller逻辑以便达到整体的reconcile逻辑：

* deployment：需要监听诸如deployment删除或者更新的操作，将deployment对应的deploymentGrid填充到workqueue中，对其进行上述reconcile逻辑

```go
func (dgc *DeploymentGridController) updateDeployment(oldObj, newObj interface{}) {
	oldD := oldObj.(*appsv1.Deployment)
	curD := newObj.(*appsv1.Deployment)
	if curD.ResourceVersion == oldD.ResourceVersion {
		// Periodic resync will send update events for all known Deployments.
		// Two different versions of the same Deployment will always have different RVs.
		return
	}

	curControllerRef := metav1.GetControllerOf(curD)
	oldControllerRef := metav1.GetControllerOf(oldD)
	controllerRefChanged := !reflect.DeepEqual(curControllerRef, oldControllerRef)
	if controllerRefChanged && oldControllerRef != nil {
		// The ControllerRef was changed. Sync the old controller, if any.
		if dg := dgc.resolveControllerRef(oldD.Namespace, oldControllerRef); dg != nil {
			klog.V(4).Infof("Deployment %s(its old owner DeploymentGrid %s) updated.", oldD.Name, dg.Name)
			dgc.enqueueDeploymentGrid(dg)
		}
	}

	// If it has a ControllerRef, that's all that matters.
	if curControllerRef != nil {
		dg := dgc.resolveControllerRef(curD.Namespace, curControllerRef)
		if dg == nil {
			return
		}
		klog.V(4).Infof("Deployment %s(its owner DeploymentGrid %s) updated.", curD.Name, dg.Name)
		dgc.enqueueDeploymentGrid(dg)
		return
	}

	if !common.IsConcernedObject(curD.ObjectMeta) {
		return
	}

	// Otherwise, it's an orphan. If anything changed, sync matching controllers
	// to see if anyone wants to adopt it now.
	labelChanged := !reflect.DeepEqual(curD.Labels, oldD.Labels)
	if labelChanged || controllerRefChanged {
		dgs := dgc.getGridForDeployment(curD)
		for _, dg := range dgs {
			klog.V(4).Infof("Orphan Deployment %s(its possible owner DeploymentGrid %s) updated.", curD.Name, dg.Name)
			dgc.enqueueDeploymentGrid(dg)
		}
	}
}
```

* node：需要监听node添加，更新以及删除的操作，将node对应的deploymentGrid(通过GridUniqKey标签)填充到workqueue中，对其进行上述reconcile逻辑

```go
func (dgc *DeploymentGridController) updateNode(oldObj, newObj interface{}) {
	oldNode := oldObj.(*corev1.Node)
	curNode := newObj.(*corev1.Node)
	if curNode.ResourceVersion == oldNode.ResourceVersion {
		// Periodic resync will send update events for all known Nodes.
		// Two different versions of the same Node will always have different RVs.
		return
	}
	labelChanged := !reflect.DeepEqual(curNode.Labels, oldNode.Labels)
	// Only handles nodes whose label has changed.
	if labelChanged {
		dgs := dgc.getGridForNode(oldNode, curNode)
		for _, dg := range dgs {
			klog.V(4).Infof("Node %s(its relevant StatefulSetGrid %s) updated.", curNode.Name, dg.Name)
			dgc.enqueueDeploymentGrid(dg)
		}
	}
}

// getGridForNode filters deploymentGrids those gridUniqKey exists in node labels.
func (dgc *DeploymentGridController) getGridForNode(nodes ...*corev1.Node) []*crdv1.DeploymentGrid {
	// Return directly when there is no labels at all
	needCheck := false
	for _, node := range nodes {
		if len(node.Labels) == 0 {
			continue
		} else {
			needCheck = true
			break
		}
	}
	if !needCheck {
		return nil
	}
	// Filter relevant grids of nodes by labels
	dgs, err := dgc.dpGridLister.List(labels.Everything())
	if err != nil {
		return nil
	}
	var targetDgs []*crdv1.DeploymentGrid
	for _, dg := range dgs {
		for _, node := range nodes {
			if _, exist := node.Labels[dg.Spec.GridUniqKey]; exist {
				targetDgs = append(targetDgs, dg)
			}
		}
	}
	return targetDgs
}
```

## 总结

* deploymentGrid适用于无状态服务，对应Kubernetes deployment负载类型，会在每个nodeunit中产生相对应的deployment，并利用service topology awareness(拓扑感知)实现闭环访问
* deployment-grid-controller是典型的operator开发模式，CRD为DeploymentGrid，controller负责监听该CRD event并 创建&维护 对应nodeunit的deployment。总体逻辑很简单，如下：
  * 1、创建并维护service group需要的若干CRDs(包括：DeploymentGrid)
  * 2、监听DeploymentGrid event，并填充DeploymentGrid到工作队列中；循环从队列中取出DeploymentGrid进行解析，创建并且维护各nodeunit(每个边缘节点的不同GridUniqKey label value对应了一个nodeunit)对应的deployment
  * 3、监听deployment以及node event，并将相关的DeploymentGrid塞到工作队列中进行上述处理，协助上述逻辑达到整体reconcile逻辑


