Kubernetes v1.24.2 环境准备
==========================

本文基于最新的[Kubernetes 1.24.2](https://github.com/kubernetes/kubernetes/tree/v1.24.2)环境进行源码分析以及实践，如下是基于CentOS7系统部署该版本单节点环境所需要的详细步骤(参考[Bootstrapping clusters with kubeadm](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/))，其它系统请参考修改：

Step1：配置系统参数

```bash
# 配置二层转发时也去调用 iptables 配置的三层规则
$ cat <<EOF > /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF
$ sysctl --system
# 加载br_netfilter模块
$ modprobe br_netfilter
$ lsmod | grep br_netfilter
```

Step2：安装容器运行态

由于从v1.24大版本开始，Kubernetes便不再支持Docker。因此这里我们以containerd为容器运行时来安装演示环境(参考[Getting started with containerd](https://github.com/containerd/containerd/blob/main/docs/getting-started.md))：

```bash
# 安装containerd
$ wget https://github.com/containerd/containerd/releases/download/v1.6.6/containerd-1.6.6-linux-amd64.tar.gz
$ tar Cxzvf /usr/local containerd-1.6.2-linux-amd64.tar.gz
# 通过systemd管理containerd
$ wget https://github.com/containerd/containerd/blob/main/containerd.service
$ cp containerd.service /usr/local/lib/systemd/system/containerd.service
$ systemctl daemon-reload
$ systemctl enable --now containerd
# 安装runc
$ wget https://github.com/opencontainers/runc/releases/download/v1.1.3/runc.amd64
$ install -m 755 runc.amd64 /usr/local/sbin/runc
# 安装CNI插件
$ wget https://github.com/containernetworking/plugins/releases/download/v1.1.1/cni-plugins-linux-amd64-v1.1.1.tgz
$ tar Cxzvf /opt/cni/bin cni-plugins-linux-amd64-v1.1.1.tgz
# 检查安装是否正常
$ crictl version

# 导出默认配置
$ containerd config default > /etc/containerd/config.toml    
# 配置systemd cgroup
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
  ...
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
    SystemdCgroup = true
# 重启containerd
$ systemctl restart containerd
# 检查运行是否正常
$ crictl version
```

Step3：安装kubeadm、kubelet以及kubectl

```bash
# 安装yum源
$ cat <<EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=http://mirrors.aliyun.com/kubernetes/yum/repos/kubernetes-el7-x86_64
enabled=1
gpgcheck=0
repo_gpgcheck=0
gpgkey=http://mirrors.aliyun.com/kubernetes/yum/doc/yum-key.gpg
        http://mirrors.aliyun.com/kubernetes/yum/doc/rpm-package-key.gpg
EOF

$ yum clean all  
$ yum makecache  
$ yum repolist

# 安装kubeadm、kubelet以及kubectl
$ yum install -y kubelet kubeadm kubectl --disableexcludes=kubernetes
$ systemctl enable --now kubelet
# attention: should be stopped status
$ systemctl status kubelet

# 利用kubeadm安装Kubernetes集群(其中x.x.x.x替换为母机IP)
# 另外注意国内无法访问google镜像仓库，因此需要通过参数image-repository替换镜像源
$ kubeadm init --image-repository=registry.cn-hangzhou.aliyuncs.com/google_containers --pod-network-cidr=194.71.0.0/16 --service-cidr=194.70.255.0/24 --kubernetes-version=v1.24.2 --apiserver-advertise-address x.x.x.x --v=5

# 安装成功后执行
$ mkdir -p $HOME/.kube
$ cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
$ chown $(id -u):$(id -g) $HOME/.kube/config
```

Step4：安装网络插件

```bash
# 下载yaml文件
$ wget https://raw.githubusercontent.com/flannel-io/flannel/master/Documentation/kube-flannel.yml
# 修改Network参数为'--pod-network-cidr'内容: 194.71.0.0/16
# 安装flannel CNI插件
$ kubectl apply -f kube-flannel.yml
```

Step5：部署应用，简单测试

```bash
# 去污点
$ kubectl taint nodes --all node-role.kubernetes.io/master-
$ kubectl taint nodes --all node-role.kubernetes.io/control-plane-
# 部署nginx deployment
$ echo "
---
apiVersion: v1
kind: Service
metadata:
  labels:
    app: echo
  name: echo
spec:
  ports:
  - port: 8080
    name: high
    protocol: TCP
    targetPort: 8080
  - port: 80
    name: low
    protocol: TCP
    targetPort: 8080
  selector:
    app: echo
---
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: echo
  name: echo
spec:
  replicas: 2
  selector:
    matchLabels:
      app: echo
  strategy: {}
  template:
    metadata:
      creationTimestamp: null
      labels:
        app: echo
    spec:
      containers:
      - image: superedge/echoserver:2.2
        name: echo
        ports:
        - containerPort: 8080
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
" | kubectl apply -f -

$ kubectl get svc
NAME         TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)           AGE
echo         ClusterIP   194.70.255.237   <none>        8080/TCP,80/TCP   66s
$ kubectl get pods -o wide
NAME                     READY   STATUS    RESTARTS   AGE     IP           NODE               NOMINATED NODE   READINESS GATES
echo-67b57bb686-lp4ft    1/1     Running   0          2m37s   194.71.0.7   devlop.novalocal   <none>           <none>
echo-67b57bb686-mch4q    1/1     Running   0          3m23s   194.71.0.6   devlop.novalocal   <none>           <none>

$ curl 194.70.255.237|grep "pod IP"    
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   501    0   501    0     0   279k      0 --:--:-- --:--:-- --:--:--  489k
        pod IP: 194.71.0.6
$ curl 194.70.255.237|grep "pod IP"
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   501    0   501    0     0   374k      0 --:--:-- --:--:-- --:--:--  489k
        pod IP: 194.71.0.7
```

综上，基于v1.24.2版本的单节点Kubernetes环境就部署好了