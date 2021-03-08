SuperEdge 分布式健康检查edge-health-admission源码分析
=================================================

## 前言

SuperEdge分布式健康检查功能由边端的edge-health-daemon以及云端的edge-health-admission组成：

* edge-health-daemon：对同区域边缘节点执行分布式健康检查，并向apiserver发送健康状态投票结果(给node打annotation)
* edge-health-admission：不断根据node edge-health annotation调整kube-controller-manager设置的node taint(去掉NoExecute taint)以及endpoints(将失联节点上的pods从endpoint subsets notReadyAddresses移到addresses中)，从而实现云端和边端共同决定节点状态

整体架构如下所示：

![](images/edge-health-arch.png)

之所以创建edge-health-admission云端组件，是因为当云边断连时，kube-controller-manager会执行如下操作：

* 失联的节点被置为ConditionUnknown状态，并被添加NoSchedule和NoExecute的taints
* 失联的节点上的pod从Service的Endpoint列表中移除

当edge-health-daemon在边端根据健康检查判断节点状态正常时，会更新node：去掉NoExecute taint。但是在node成功更新之后又会被kube-controller-manager给刷回去(再次添加NoExecute taint)，因此必须添加Kubernetes mutating admission webhook也即edge-health-admission，将kube-controller-manager对node api resource的更改做调整，最终实现分布式健康检查效果

本文将基于我对edge-health的重构PR [Refactor edge-health and admission webhook for a better maintainability and extendibility](https://github.com/superedge/superedge/pull/46) 分析edge-health-admission组件，在深入源码之前先介绍一下[Kubernetes Admission Controllers](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)

>> An admission controller is a piece of code that intercepts requests to the Kubernetes API server prior to persistence of the object, but after the request is authenticated and authorized. The controllers consist of the list below, are compiled into the kube-apiserver binary, and may only be configured by the cluster administrator. In that list, there are two special controllers: MutatingAdmissionWebhook and ValidatingAdmissionWebhook. These execute the mutating and validating (respectively) admission control webhooks which are configured in the API.

Kubernetes Admission Controllers是kube-apiserver处理api请求的某个环节，用于在api请求认证&鉴权之后，对象持久化之前进行调用，对请求进行校验或者修改(or both)

Kubernetes Admission Controllers包括多种admission，大多数都内嵌在kube-apiserver代码中了。其中MutatingAdmissionWebhook以及ValidatingAdmissionWebhook controller比较特殊，它们分别会调用外部构造的mutating admission control webhooks以及validating admission control webhooks  

>> Admission webhooks are HTTP callbacks that receive admission requests and do something with them. You can define two types of admission webhooks, validating admission webhook and mutating admission webhook. Mutating admission webhooks are invoked first, and can modify objects sent to the API server to enforce custom defaults. After all object modifications are complete, and after the incoming object is validated by the API server, validating admission webhooks are invoked and can reject requests to enforce custom policies.

Admission Webhooks是一个HTTP回调服务，接受AdmissionReview请求并进行处理，按照处理方式的不同，可以将Admission Webhooks分类如下：

* [validating admission webhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#validatingadmissionwebhook)：通过ValidatingWebhookConfiguration配置，会对api请求进行准入校验，但是不能修改请求对象
* [mutating admission webhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#mutatingadmissionwebhook)：通过MutatingWebhookConfiguration配置，会对api请求进行准入校验以及修改请求对象

两种类型的webhooks都需要定义如下Matching requests字段：

* admissionReviewVersions：定义了apiserver所支持的AdmissionReview api resource的版本列表(API servers send the first AdmissionReview version in the admissionReviewVersions list they support)
* name：webhook名称(如果一个WebhookConfiguration中定义了多个webhooks，需要保证名称的唯一性)
* clientConfig：定义了webhook server的访问地址(url or service)以及CA bundle(optionally include a custom CA bundle to use to verify the TLS connection)
* namespaceSelector：限定了匹配请求资源的命名空间labelSelector
* objectSelector：限定了匹配请求资源本身的labelSelector
* rules：限定了匹配请求的operations，apiGroups，apiVersions，resources以及resource scope，如下：
  * operations：规定了请求操作列表(Can be "CREATE", "UPDATE", "DELETE", "CONNECT", or "*" to match all.)
  * apiGroups：规定了请求资源的API groups列表("" is the core API group. "*" matches all API groups.)
  * apiVersions：规定了请求资源的API versions列表("*" matches all API versions.)
  * resources：规定了请求资源类型(node, deployment and etc)
  * scope：规定了请求资源的范围(Cluster，Namespaced or *)
* timeoutSeconds：规定了webhook回应的超时时间，如果超时了，根据failurePolicy进行处理
* failurePolicy：规定了apiserver对admission webhook请求失败的处理策略：
  * Ignore：means that an error calling the webhook is ignored and the API request is allowed to continue.
  * Fail：means that an error calling the webhook causes the admission to fail and the API request to be rejected.
* matchPolicy：规定了rules如何匹配到来的api请求，如下：
  * Exact：完全匹配rules列表限制
  * Equivalent：如果修改请求资源(apiserver可以实现对象在不同版本的转化)可以转化为能够配置rules列表限制，则认为该请求匹配，可以发送给admission webhook
* reinvocationPolicy：In v1.15+, to allow mutating admission plugins to observe changes made by other plugins, built-in mutating admission plugins are re-run if a mutating webhook modifies an object, and mutating webhooks can specify a reinvocationPolicy to control whether they are reinvoked as well.
  * Never: the webhook must not be called more than once in a single admission evaluation
  * IfNeeded: the webhook may be called again as part of the admission evaluation if the object being admitted is modified by other admission plugins after the initial webhook call.
* Side effects：某些webhooks除了修改AdmissionReview的内容外，还会连带修改其它的资源("side effects")。而sideEffects指示了Webhooks是否具有"side effects"，取值如下：
  * None: calling the webhook will have no side effects.
  * NoneOnDryRun: calling the webhook will possibly have side effects, but if a request with dryRun: true is sent to the webhook, the webhook will suppress the side effects (the webhook is dryRun-aware).
  
这里给出edge-health-admission对应的MutatingWebhookConfiguration作为参考示例：

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: edge-health-admission
webhooks:
  - admissionReviewVersions:
      - v1
    clientConfig:
      caBundle: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNwRENDQVl3Q0NRQ2RaL0w2akZSSkdqQU5CZ2txaGtpRzl3MEJBUXNGQURBVU1SSXdFQVlEVlFRRERBbFgKYVhObE1tTWdRMEV3SGhjTk1qQXdOekU0TURRek9ERTNXaGNOTkRjeE1qQTBNRFF6T0RFM1dqQVVNUkl3RUFZRApWUVFEREFsWGFYTmxNbU1nUTBFd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUNSCnhHT2hrODlvVkRHZklyVDBrYVkwajdJQVJGZ2NlVVFmVldSZVhVcjh5eEVOQkF6ZnJNVVZyOWlCNmEwR2VFL3cKZzdVdW8vQWtwUEgrbzNQNjFxdWYrTkg1UDBEWHBUd1pmWU56VWtyaUVja3FOSkYzL2liV0o1WGpFZUZSZWpidgpST1V1VEZabmNWOVRaeTJISVF2UzhTRzRBTWJHVmptQXlDMStLODBKdDI3QUl4YmdndmVVTW8xWFNHYnRxOXlJCmM3Zk1QTXJMSHhaOUl5aTZla3BwMnJrNVdpeU5YbXZhSVA4SmZMaEdnTU56YlJaS1RtL0ZKdDdyV0dhQ1orNXgKV0kxRGJYQ2MyWWhmbThqU1BqZ3NNQTlaNURONDU5ellJSkVhSTFHeFI3MlhaUVFMTm8zdE5jd3IzVlQxVlpiTgo1cmhHQlVaTFlrMERtd25vWTBCekFnTUJBQUV3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUhuUDJibnJBcWlWCjYzWkpMVzM0UWFDMnRreVFScTNVSUtWR3RVZHFobWRVQ0I1SXRoSUlleUdVRVdqVExpc3BDQzVZRHh4YVdrQjUKTUxTYTlUY0s3SkNOdkdJQUdQSDlILzRaeXRIRW10aFhiR1hJQ3FEVUVmSUVwVy9ObUgvcnBPQUxhYlRvSUVzeQpVNWZPUy9PVVZUM3ZoSldlRjdPblpIOWpnYk1SZG9zVElhaHdQdTEzZEtZMi8zcEtxRW1Cd1JkbXBvTExGbW9MCmVTUFQ4SjREZExGRkh2QWJKalFVbjhKQTZjOHUrMzZJZDIrWE1sTGRZYTdnTnhvZTExQTl6eFJQczRXdlpiMnQKUXZpbHZTbkFWb0ZUSVozSlpjRXVWQXllNFNRY1dKc3FLMlM0UER1VkNFdlg0SmRCRlA2NFhvU08zM3pXaWhtLworMXg3OXZHMUpFcz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
      service:
        namespace: kube-system
        name: edge-health-admission
        path: /node-taint
    failurePolicy: Ignore
    matchPolicy: Exact
    name: node-taint.k8s.io
    namespaceSelector: {}
    objectSelector: {}
    reinvocationPolicy: Never
    rules:
      - apiGroups:
          - '*'
        apiVersions:
          - '*'
        operations:
          - UPDATE
        resources:
          - nodes
        scope: '*'
    sideEffects: None
    timeoutSeconds: 5
  - admissionReviewVersions:
      - v1
    clientConfig:
      caBundle: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNwRENDQVl3Q0NRQ2RaL0w2akZSSkdqQU5CZ2txaGtpRzl3MEJBUXNGQURBVU1SSXdFQVlEVlFRRERBbFgKYVhObE1tTWdRMEV3SGhjTk1qQXdOekU0TURRek9ERTNXaGNOTkRjeE1qQTBNRFF6T0RFM1dqQVVNUkl3RUFZRApWUVFEREFsWGFYTmxNbU1nUTBFd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUNSCnhHT2hrODlvVkRHZklyVDBrYVkwajdJQVJGZ2NlVVFmVldSZVhVcjh5eEVOQkF6ZnJNVVZyOWlCNmEwR2VFL3cKZzdVdW8vQWtwUEgrbzNQNjFxdWYrTkg1UDBEWHBUd1pmWU56VWtyaUVja3FOSkYzL2liV0o1WGpFZUZSZWpidgpST1V1VEZabmNWOVRaeTJISVF2UzhTRzRBTWJHVmptQXlDMStLODBKdDI3QUl4YmdndmVVTW8xWFNHYnRxOXlJCmM3Zk1QTXJMSHhaOUl5aTZla3BwMnJrNVdpeU5YbXZhSVA4SmZMaEdnTU56YlJaS1RtL0ZKdDdyV0dhQ1orNXgKV0kxRGJYQ2MyWWhmbThqU1BqZ3NNQTlaNURONDU5ellJSkVhSTFHeFI3MlhaUVFMTm8zdE5jd3IzVlQxVlpiTgo1cmhHQlVaTFlrMERtd25vWTBCekFnTUJBQUV3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUhuUDJibnJBcWlWCjYzWkpMVzM0UWFDMnRreVFScTNVSUtWR3RVZHFobWRVQ0I1SXRoSUlleUdVRVdqVExpc3BDQzVZRHh4YVdrQjUKTUxTYTlUY0s3SkNOdkdJQUdQSDlILzRaeXRIRW10aFhiR1hJQ3FEVUVmSUVwVy9ObUgvcnBPQUxhYlRvSUVzeQpVNWZPUy9PVVZUM3ZoSldlRjdPblpIOWpnYk1SZG9zVElhaHdQdTEzZEtZMi8zcEtxRW1Cd1JkbXBvTExGbW9MCmVTUFQ4SjREZExGRkh2QWJKalFVbjhKQTZjOHUrMzZJZDIrWE1sTGRZYTdnTnhvZTExQTl6eFJQczRXdlpiMnQKUXZpbHZTbkFWb0ZUSVozSlpjRXVWQXllNFNRY1dKc3FLMlM0UER1VkNFdlg0SmRCRlA2NFhvU08zM3pXaWhtLworMXg3OXZHMUpFcz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
      service:
        namespace: kube-system
        name: edge-health-admission
        path: /endpoint
    failurePolicy: Ignore
    matchPolicy: Exact
    name: endpoint.k8s.io
    namespaceSelector: {}
    objectSelector: {}
    reinvocationPolicy: Never
    rules:
      - apiGroups:
          - '*'
        apiVersions:
          - '*'
        operations:
          - UPDATE
        resources:
          - endpoints
        scope: '*'
    sideEffects: None
    timeoutSeconds: 5
```
    
kube-apiserver会发送AdmissionReview(apiGroup: `admission.k8s.io`，apiVersion：`v1 or v1beta1`)给Webhooks，并封装成JSON格式，示例如下：

```yaml
# This example shows the data contained in an AdmissionReview object for a request to update the scale subresource of an apps/v1 Deployment
{
  "apiVersion": "admission.k8s.io/v1",
  "kind": "AdmissionReview",
  "request": {
    # Random uid uniquely identifying this admission call
    "uid": "705ab4f5-6393-11e8-b7cc-42010a800002",

    # Fully-qualified group/version/kind of the incoming object
    "kind": {"group":"autoscaling","version":"v1","kind":"Scale"},
    # Fully-qualified group/version/kind of the resource being modified
    "resource": {"group":"apps","version":"v1","resource":"deployments"},
    # subresource, if the request is to a subresource
    "subResource": "scale",

    # Fully-qualified group/version/kind of the incoming object in the original request to the API server.
    # This only differs from `kind` if the webhook specified `matchPolicy: Equivalent` and the
    # original request to the API server was converted to a version the webhook registered for.
    "requestKind": {"group":"autoscaling","version":"v1","kind":"Scale"},
    # Fully-qualified group/version/kind of the resource being modified in the original request to the API server.
    # This only differs from `resource` if the webhook specified `matchPolicy: Equivalent` and the
    # original request to the API server was converted to a version the webhook registered for.
    "requestResource": {"group":"apps","version":"v1","resource":"deployments"},
    # subresource, if the request is to a subresource
    # This only differs from `subResource` if the webhook specified `matchPolicy: Equivalent` and the
    # original request to the API server was converted to a version the webhook registered for.
    "requestSubResource": "scale",

    # Name of the resource being modified
    "name": "my-deployment",
    # Namespace of the resource being modified, if the resource is namespaced (or is a Namespace object)
    "namespace": "my-namespace",

    # operation can be CREATE, UPDATE, DELETE, or CONNECT
    "operation": "UPDATE",

    "userInfo": {
      # Username of the authenticated user making the request to the API server
      "username": "admin",
      # UID of the authenticated user making the request to the API server
      "uid": "014fbff9a07c",
      # Group memberships of the authenticated user making the request to the API server
      "groups": ["system:authenticated","my-admin-group"],
      # Arbitrary extra info associated with the user making the request to the API server.
      # This is populated by the API server authentication layer and should be included
      # if any SubjectAccessReview checks are performed by the webhook.
      "extra": {
        "some-key":["some-value1", "some-value2"]
      }
    },

    # object is the new object being admitted.
    # It is null for DELETE operations.
    "object": {"apiVersion":"autoscaling/v1","kind":"Scale",...},
    # oldObject is the existing object.
    # It is null for CREATE and CONNECT operations.
    "oldObject": {"apiVersion":"autoscaling/v1","kind":"Scale",...},
    # options contains the options for the operation being admitted, like meta.k8s.io/v1 CreateOptions, UpdateOptions, or DeleteOptions.
    # It is null for CONNECT operations.
    "options": {"apiVersion":"meta.k8s.io/v1","kind":"UpdateOptions",...},

    # dryRun indicates the API request is running in dry run mode and will not be persisted.
    # Webhooks with side effects should avoid actuating those side effects when dryRun is true.
    # See http://k8s.io/docs/reference/using-api/api-concepts/#make-a-dry-run-request for more details.
    "dryRun": false
  }
}
```

而Webhooks需要向kube-apiserver回应具有相同版本的AdmissionReview，并封装成JSON格式，包含如下关键字段：

* uid：拷贝发送给webhooks的AdmissionReview request.uid字段
* allowed：true表示准许；false表示不准许
* status：当不准许请求时，可以通过status给出相关原因(http code and message)
* patch：base64编码，包含mutating admission webhook对请求对象的一系列[JSON patch操作](https://jsonpatch.com/)
* patchType：目前只支持JSONPatch类型

示例如下：

```yaml
# a webhook response to add that label would be：
{
  "apiVersion": "admission.k8s.io/v1",
  "kind": "AdmissionReview",
  "response": {
    "uid": "<value from request.uid>",
    "allowed": true,
    "patchType": "JSONPatch",
    "patch": "W3sib3AiOiAiYWRkIiwgInBhdGgiOiAiL3NwZWMvcmVwbGljYXMiLCAidmFsdWUiOiAzfV0="
  }
}
```

edge-health-admission实际上就是一个mutating admission webhook，选择性地对endpoints以及node UPDATE请求进行修改，下面将详细分析其原理

## edge-health-admission源码分析

edge-health-admission完全参考[官方示例](https://github.com/kubernetes/kubernetes/blob/v1.13.0/test/images/webhook/main.go)编写，如下是监听入口：

```go
func (eha *EdgeHealthAdmission) Run(stopCh <-chan struct{}) {
	if !cache.WaitForNamedCacheSync("edge-health-admission", stopCh, eha.cfg.NodeInformer.Informer().HasSynced) {
		return
	}

	http.HandleFunc("/node-taint", eha.serveNodeTaint)
	http.HandleFunc("/endpoint", eha.serveEndpoint)
	server := &http.Server{
		Addr: eha.cfg.Addr,
	}

	go func() {
		if err := server.ListenAndServeTLS(eha.cfg.CertFile, eha.cfg.KeyFile); err != http.ErrServerClosed {
			klog.Fatalf("ListenAndServeTLS err %+v", err)
		}
	}()

	for {
		select {
		case <-stopCh:
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := server.Shutdown(ctx); err != nil {
				klog.Errorf("Server: program exit, server exit error %+v", err)
			}
			return
		default:
		}
	}
}
```

这里会注册两种路由处理函数：

* node-taint：对应处理函数serveNodeTaint，负责对node UPDATE请求进行更改
* endpoint：对应处理函数serveEndpoint，负责对endpoints UPDATE请求进行更改

而这两个函数都会调用serve函数，如下：

```go
// serve handles the http portion of a request prior to handing to an admit function
func serve(w http.ResponseWriter, r *http.Request, admit admitFunc) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		klog.Errorf("contentType=%s, expect application/json", contentType)
		return
	}

	klog.V(4).Info(fmt.Sprintf("handling request: %s", body))

	// The AdmissionReview that was sent to the webhook
	requestedAdmissionReview := admissionv1.AdmissionReview{}

	// The AdmissionReview that will be returned
	responseAdmissionReview := admissionv1.AdmissionReview{}

	deserializer := codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(body, nil, &requestedAdmissionReview); err != nil {
		klog.Error(err)
		responseAdmissionReview.Response = toAdmissionResponse(err)
	} else {
		// pass to admitFunc
		responseAdmissionReview.Response = admit(requestedAdmissionReview)
	}

	// Return the same UID
	responseAdmissionReview.Response.UID = requestedAdmissionReview.Request.UID

	klog.V(4).Info(fmt.Sprintf("sending response: %+v", responseAdmissionReview.Response))

	respBytes, err := json.Marshal(responseAdmissionReview)
	if err != nil {
		klog.Error(err)
	}
	if _, err := w.Write(respBytes); err != nil {
		klog.Error(err)
	}
}
```

serve逻辑如下所示：

* 解析request.Body为AdmissionReview对象，并赋值给requestedAdmissionReview
* 对AdmissionReview对象执行admit函数，并赋值给回responseAdmissionReview
* 设置responseAdmissionReview.Response.UID为请求的AdmissionReview.Request.UID

其中serveNodeTaint以及serveEndpoint对应的admit函数分别为：mutateNodeTaint以及mutateEndpoint，下面依次分析：

1、mutateNodeTaint

mutateNodeTaint会对node UPDATE请求按照分布式健康检查结果进行修改：

```go
func (eha *EdgeHealthAdmission) mutateNodeTaint(ar admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	klog.V(4).Info("mutating node taint")
	nodeResource := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "nodes"}
	if ar.Request.Resource != nodeResource {
		klog.Errorf("expect resource to be %s", nodeResource)
		return nil
	}

	var node corev1.Node
	deserializer := codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(ar.Request.Object.Raw, nil, &node); err != nil {
		klog.Error(err)
		return toAdmissionResponse(err)
	}

	reviewResponse := admissionv1.AdmissionResponse{}
	reviewResponse.Allowed = true

	if index, condition := util.GetNodeCondition(&node.Status, v1.NodeReady); index != -1 && condition.Status == v1.ConditionUnknown {
		if node.Annotations != nil {
			var patches []*patch
			if healthy, existed := node.Annotations[common.NodeHealthAnnotation]; existed && healthy == common.NodeHealthAnnotationPros {
				if index, existed := util.TaintExistsPosition(node.Spec.Taints, common.UnreachableNoExecuteTaint); existed {
					patches = append(patches, &patch{
						OP:   "remove",
						Path: fmt.Sprintf("/spec/taints/%d", index),
					})
					klog.V(4).Infof("UnreachableNoExecuteTaint: remove %d taints %s", index, node.Spec.Taints[index])
				}
			}
			if len(patches) > 0 {
				patchBytes, _ := json.Marshal(patches)
				reviewResponse.Patch = patchBytes
				pt := admissionv1.PatchTypeJSONPatch
				reviewResponse.PatchType = &pt
			}
		}
	}

	return &reviewResponse
}
```

主体逻辑如下：

* 检查AdmissionReview.Request.Resource是否为node资源的group/version/kind
* 将AdmissionReview.Request.Object.Raw转化为node对象
* 设置AdmissionReview.Response.Allowed为true，表示无论如何都准许该请求
* 执行协助边端健康检查核心逻辑：在节点处于ConditionUnknown状态且分布式健康检查结果为正常的情况下，若节点存在NoExecute(node.kubernetes.io/unreachable) taint，则将其移除

总的来说，mutateNodeTaint的作用就是：不断修正被kube-controller-manager更新的节点状态，去掉NoExecute(node.kubernetes.io/unreachable) taint，让节点不会被驱逐

2、mutateEndpoint

mutateEndpoint会对endpoints UPDATE请求按照分布式健康检查结果进行修改：

```go
func (eha *EdgeHealthAdmission) mutateEndpoint(ar admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	klog.V(4).Info("mutating endpoint")
	endpointResource := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "endpoints"}
	if ar.Request.Resource != endpointResource {
		klog.Errorf("expect resource to be %s", endpointResource)
		return nil
	}

	var endpoint corev1.Endpoints
	deserializer := codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(ar.Request.Object.Raw, nil, &endpoint); err != nil {
		klog.Error(err)
		return toAdmissionResponse(err)
	}

	reviewResponse := admissionv1.AdmissionResponse{}
	reviewResponse.Allowed = true

	for epSubsetIndex, epSubset := range endpoint.Subsets {
		for notReadyAddrIndex, EndpointAddress := range epSubset.NotReadyAddresses {
			if node, err := eha.nodeLister.Get(*EndpointAddress.NodeName); err == nil {
				if index, condition := util.GetNodeCondition(&node.Status, v1.NodeReady); index != -1 && condition.Status == v1.ConditionUnknown {
					if node.Annotations != nil {
						var patches []*patch
						if healthy, existed := node.Annotations[common.NodeHealthAnnotation]; existed && healthy == common.NodeHealthAnnotationPros {
							// TODO: handle readiness probes failure
							// Remove address on node from endpoint notReadyAddresses
							patches = append(patches, &patch{
								OP:   "remove",
								Path: fmt.Sprintf("/subsets/%d/notReadyAddresses/%d", epSubsetIndex, notReadyAddrIndex),
							})

							// Add address on node to endpoint readyAddresses
							TargetRef := map[string]interface{}{}
							TargetRef["kind"] = EndpointAddress.TargetRef.Kind
							TargetRef["namespace"] = EndpointAddress.TargetRef.Namespace
							TargetRef["name"] = EndpointAddress.TargetRef.Name
							TargetRef["uid"] = EndpointAddress.TargetRef.UID
							TargetRef["apiVersion"] = EndpointAddress.TargetRef.APIVersion
							TargetRef["resourceVersion"] = EndpointAddress.TargetRef.ResourceVersion
							TargetRef["fieldPath"] = EndpointAddress.TargetRef.FieldPath

							patches = append(patches, &patch{
								OP:   "add",
								Path: fmt.Sprintf("/subsets/%d/addresses/0", epSubsetIndex),
								Value: map[string]interface{}{
									"ip":        EndpointAddress.IP,
									"hostname":  EndpointAddress.Hostname,
									"nodeName":  EndpointAddress.NodeName,
									"targetRef": TargetRef,
								},
							})

							if len(patches) != 0 {
								patchBytes, _ := json.Marshal(patches)
								reviewResponse.Patch = patchBytes
								pt := admissionv1.PatchTypeJSONPatch
								reviewResponse.PatchType = &pt
							}
						}
					}
				}
			} else {
				klog.Errorf("Get pod's node err %+v", err)
			}
		}

	}

	return &reviewResponse
}
```

主体逻辑如下：

* 检查AdmissionReview.Request.Resource是否为endpoints资源的group/version/kind
* 将AdmissionReview.Request.Object.Raw转化为endpoints对象
* 设置AdmissionReview.Response.Allowed为true，表示无论如何都准许该请求
* 遍历endpoints.Subset.NotReadyAddresses，如果EndpointAddress所在节点处于ConditionUnknown状态且分布式健康检查结果为正常，则将该EndpointAddress从endpoints.Subset.NotReadyAddresses移到endpoints.Subset.Addresses

总的来说，mutateEndpoint的作用就是：不断修正被kube-controller-manager更新的endpoints状态，将分布式健康检查正常节点上的负载从endpoints.Subset.NotReadyAddresses移到endpoints.Subset.Addresses中，让服务依旧可用

## 总结

* SuperEdge分布式健康检查功能由边端的edge-health-daemon以及云端的edge-health-admission组成：
  * edge-health-daemon：对同区域边缘节点执行分布式健康检查，并向apiserver发送健康状态投票结果(给node打annotation)
  * edge-health-admission：不断根据node edge-health annotation调整kube-controller-manager设置的node taint(去掉NoExecute taint)以及endpoints(将失联节点上的pods从endpoint subsets notReadyAddresses移到addresses中)，从而实现云端和边端共同决定节点状态
* 之所以创建edge-health-admission云端组件，是因为当云边断连时，kube-controller-manager会将失联的节点置为ConditionUnknown状态，并添加NoSchedule和NoExecute的taints；同时失联的节点上的pod从Service的Endpoint列表中移除。当edge-health-daemon在边端根据健康检查判断节点状态正常时，会更新node：去掉NoExecute taint。但是在node成功更新之后又会被kube-controller-manager给刷回去(再次添加NoExecute taint)，因此必须添加Kubernetes mutating admission webhook，也即edge-health-admission将kube-controller-manager对node api resource的更改做调整，最终实现分布式健康检查效果  
* Kubernetes Admission Controllers是kube-apiserver处理api请求的某个环节，用于在api请求认证&鉴权之后，对象持久化之前进行调用，对请求进行校验或者修改(or both)；包括多种admission，大多数都内嵌在kube-apiserver代码中了。其中MutatingAdmissionWebhook以及ValidatingAdmissionWebhook controller比较特殊，它们分别会调用外部构造的mutating admission control webhooks以及validating admission control webhooks
* Admission Webhooks是一个HTTP回调服务，接受AdmissionReview请求并进行处理，按照处理方式的不同，可以将Admission Webhooks分类如下：
  * [validating admission webhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#validatingadmissionwebhook)：通过ValidatingWebhookConfiguration配置，会对api请求进行准入校验，但是不能修改请求对象
  * [mutating admission webhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#mutatingadmissionwebhook)：通过MutatingWebhookConfiguration配置，会对api请求进行准入校验以及修改请求对象
* kube-apiserver会发送AdmissionReview(apiGroup: `admission.k8s.io`，apiVersion：`v1 or v1beta1`)给Webhooks，并封装成JSON格式；而Webhooks需要向kube-apiserver回应具有相同版本的AdmissionReview，并封装成JSON格式，并且包含如下关键字段：
  * uid：拷贝发送给webhooks的AdmissionReview request.uid字段
  * allowed：true表示准许；false表示不准许
  * status：当不准许请求时，可以通过status给出相关原因(http code and message)
  * patch：base64编码，包含mutating admission webhook对请求对象的一系列JSON patch操作
  * patchType：目前只支持JSONPatch类型
* edge-health-admission实际上就是一个mutating admission webhook，选择性地对endpoints以及node UPDATE请求进行修改，包含如下处理逻辑：
  * mutateNodeTaint：不断修正被kube-controller-manager更新的节点状态，去掉NoExecute(node.kubernetes.io/unreachable) taint，让节点不会被驱逐
  * mutateEndpoint：不断修正被kube-controller-manager更新的endpoints状态，将分布式健康检查正常节点上的负载从endpoints.Subset.NotReadyAddresses移到endpoints.Subset.Addresses中，让服务依旧可用  

## 展望

SuperEdge为了实现对Kubernetes完全无侵入，设计了edge-health-admission调整kube-controller-manager对node以及endpoints的更改，但是目前也存在如下问题：

* 在edge-health-admission将kube-controller-manager对node api resource的更新请求调整之后，kube-controller-manager又会重新发出同样的更新请求，这样会造成对apiserver以及etcd一定的压力
* 对于endpoints的调整工作，目前是粗暴地将分布式健康检查正常节点上的所有负载从endpoints.Subset.NotReadyAddresses移到endpoints.Subset.Addresses中，但是没有考虑到服务本身不可用的情况(readiness probes failure)

后续会考虑优化这两点