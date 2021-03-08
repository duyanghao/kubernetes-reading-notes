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

当edge-health-daemon在边端根据健康检查判断节点状态正常时，会更新node：去掉NoExecute taint。但是在node成功更新之后又会被kube-controller-manager给刷回去(再次添加NoExecute taint)，因此必须添加Kubernetes mutating admission webhook也即edge-health-admission将kube-controller-manager对node api resource的更改做调整，最终实现分布式健康检查效果

本文将基于我对edge-health的重构PR [Refactor edge-health and admission webhook for a better maintainability and extendibility](https://github.com/superedge/superedge/pull/46) 分析edge-health-admission组件，在深入源码之前先介绍一下[Kubernetes Admission Controllers](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)

>> An admission controller is a piece of code that intercepts requests to the Kubernetes API server prior to persistence of the object, but after the request is authenticated and authorized. The controllers consist of the list below, are compiled into the kube-apiserver binary, and may only be configured by the cluster administrator. In that list, there are two special controllers: MutatingAdmissionWebhook and ValidatingAdmissionWebhook. These execute the mutating and validating (respectively) admission control webhooks which are configured in the API.

>> Admission webhooks are HTTP callbacks that receive admission requests and do something with them. You can define two types of admission webhooks, validating admission webhook and mutating admission webhook. Mutating admission webhooks are invoked first, and can modify objects sent to the API server to enforce custom defaults. After all object modifications are complete, and after the incoming object is validated by the API server, validating admission webhooks are invoked and can reject requests to enforce custom policies.

Kubernetes Admission Controllers是kube-apiserver处理api请求的某个环节，用于在api请求认证&鉴权之后，对象持久化之前进行调用，对请求进行校验或者修改(or both)

Kubernetes Admission Controllers包括多种admission，大多数都内嵌在kube-apiserver代码中了。其中MutatingAdmissionWebhook以及ValidatingAdmissionWebhook controller比较特殊，它们分别会调用外部构造的mutating admission control webhooks以及validating admission control webhooks  

Admission Webhooks是一个HTTP回调服务，接受AdmissionReview请求并进行处理，按照处理方式的不同，可以将Admission Webhooks分类如下：

* [validating admission webhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#validatingadmissionwebhook)：通过ValidatingWebhookConfiguration配置，会对api请求进行准入校验，但是不能修改请求对象
* [mutating admission webhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#mutatingadmissionwebhook)：通过MutatingWebhookConfiguration配置，会对api请求进行准入校验以及修改请求对象

两种类型的webhooks都需要定义如下Matching requests字段：

* admissionReviewVersions：定义了apiserver所支持的AdmissionReview的版本列表(API servers send the first AdmissionReview version in the admissionReviewVersions list they support)
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
    
kube-apiserver会发送AdmissionReview(API group: `admission.k8s.io`，version：`v1 or v1beta1`)给Webhooks，并封装成JSON格式，示例如下：

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

而Webhooks需要向kube-apiserver回应具有相同版本的AdmissionReview，并封装成JSON格式，并且包含如下关键字段：

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



## 总结

## 展望