SuperEdge ServiceGroup功能简介
=============================

## 功能

superedge可以支持原生Kubernetes的所有工作负载的应用部署，包括：

- deployment
- statefulset
- daemonset
- job
- cronjob

而对于边缘计算应用来说，具备如下独特点：

- 边缘计算场景中，往往会在同一个集群中管理多个边缘站点，每个边缘站点内有一个或多个计算节点
- 同时希望在每个站点中都运行一组有业务逻辑联系的服务，每个站点内的服务是一套完整的功能，可以为用户提供服务
- 由于受到网络限制，有业务联系的服务之间不希望或者不能跨站点访问

为了解决上述问题，superedge创新性地构建了ServiceGroup概念，方便用户便捷地在共属同一个集群的不同机房或区域中各自部署一组服务，并且使得各个服务间的请求在本机房或本地域内部即可完成(闭环)，避免了服务跨地域访问

ServiceGroup中涉及几个关键概念：

![img](https://github.com/superedge/superedge/raw/main/docs/img/serviceGroup-UseCase.png)

#### NodeUnit

- NodeUnit通常是位于同一边缘站点内的一个或多个计算资源实例，需要保证同一NodeUnit中的节点内网是通的
- ServiceGroup组中的服务运行在一个NodeUnit之内
- ServiceGroup允许用户设置服务在一个NodeUnit中运行的pod(belongs to deployment)数量
- ServiceGroup能够把服务之间的调用限制在本NodeUnit内

#### NodeGroup

- NodeGroup包含一个或者多个 NodeUnit
- 保证在集合中每个NodeUnit上均部署ServiceGroup中的服务
- 当集群中增加NodeUnit时会自动将ServiceGroup中的服务部署到新增NodeUnit

#### ServiceGroup

- ServiceGroup包含一个或者多个业务服务
- 适用场景：
  - 业务需要打包部署；
  - 需要在每一个NodeUnit中均运行起来并且保证pod数量
  - 需要将服务之间的调用控制在同一个 NodeUnit 中，不能将流量转发到其他NodeUnit上
- 注意：ServiceGroup是一种抽象资源概念，一个集群中可以创建多个ServiceGroup

下面以一个具体例子说明ServiceGroup功能：

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
# execute on onde0
$ curl 192.168.6.139|grep "node name"
        node name:      node0
# execute on node1 and node2
$ curl 192.168.6.139|grep "node name"
        node name:      node2
$ curl 192.168.6.139|grep "node name"
        node name:      node1        
```

通过上面的例子总结ServiceGroup如下：

- NodeUnit和NodeGroup以及ServiceGroup都是一种概念，具体来说实际使用中对应关系如下：
  - NodeUnit是具有相同label key以及value的一组边缘节点
  - NodeGroup是具有相同label key的一组NodeUnit(不同value)
  - ServiceGroup具体由两种CRD构成：DepolymentGrid以及ServiceGrid，具备相同的gridUniqKey
  - gridUniqKey值与NodeGroup的label key对应，也即ServiceGroup是与NodeGroup一一对应，而NodeGroup对应多个NodeUnit，同时NodeGroup中的每一个NodeUnit都会部署ServiceGroup对应deployment，这些deployment(deploymentgridName-NodeUnit命名)通过nodeSelector亲和性固定某个NodeUnit上，并通过服务拓扑感知限制在该NodeUnit内访问

