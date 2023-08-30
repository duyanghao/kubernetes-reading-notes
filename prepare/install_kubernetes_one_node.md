Install_kubernetes_one_node
===========================

Here is the process for creating a single control-plane cluster with kubeadm:

## Install

```bash
# step1: Configurate centos 7
$ cat <<EOF > /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF
$ sysctl --system
$ modprobe br_netfilter
$ lsmod | grep br_netfilter

# Step2: Install docker
# base repo
$ cd /etc/yum.repos.d
$ curl -o CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo
$ sed -i 's/gpgcheck=1/gpgcheck=0/g' /etc/yum.repos.d/CentOS-Base.repo
$ sed -i 's/$releasever/7/g' /etc/yum.repos.d/CentOS-Base.repo

# docker repo
$ curl -o docker-ce.repo http://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo

# k8s repo
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

# update cache
$ yum clean all  
$ yum makecache  
$ yum repolist

# install docker-ce
$ yum list docker-ce --showduplicates | sort -r
$ yum install docker-ce-18.06.3.ce
$ systemctl enable docker --now
$ systemctl status docker

# Error starting daemon: Error initializing network controller: list bridge addresses failed: no available network
$ ip link add name docker0 type bridge
$ ip addr add dev docker0 172.17.0.1/16

# Step3: Install kubeadm, kubelet and kubectl
$ yum install -y kubelet kubeadm kubectl --disableexcludes=kubernetes
$ systemctl enable --now kubelet
# attention: should be stopped status
$ systemctl status kubelet

# Step4: Install kubernetes with kubeadm
$ kubeadm init --pod-network-cidr=194.70.0.0/16 --service-cidr=194.70.255.0/24 --kubernetes-version=v1.17.4 --apiserver-advertise-address {hostIP}
$ mkdir -p $HOME/.kube
$ cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
$ chown $(id -u):$(id -g) $HOME/.kube/config
# flannel (edit flannel configmap 'Network' field if '--pod-network-cidr' defined)
$ kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/2140ac876ef134e0ed5af15c65e414cf26827915/Documentation/kube-flannel.yml
# taint nodes
$ kubectl taint nodes --all node-role.kubernetes.io/master-

# Step5: Check cluster state
$ kubectl get cs
NAME                 STATUS    MESSAGE             ERROR
scheduler            Healthy   ok                  
controller-manager   Healthy   ok                  
etcd-0               Healthy   {"health":"true"}
$ cat << EOF > base.yaml
---
apiVersion: v1
kind: Namespace
metadata:
  name: nginx-example
  labels:
    app: nginx

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  namespace: nginx-example
spec:
  replicas: 2
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - image: nginx:1.17.6
        name: nginx
        ports:
        - containerPort: 80

---
apiVersion: v1
kind: Service
metadata:
  labels:
    app: nginx
  name: my-nginx
  namespace: nginx-example
spec:
  ports:
  - port: 80
    targetPort: 80
  selector:
    app: nginx
  type: ClusterIP
EOF

$ kubectl apply -f base.yaml
$ kubectl get pods -nnginx-example      
NAME                                READY   STATUS    RESTARTS   AGE
nginx-deployment-7cd5ddccc7-64t72   1/1     Running   0          42m
nginx-deployment-7cd5ddccc7-svdgg   1/1     Running   0          42m

# curl 194.70.0.99
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
```

## Refs

* [debug-environment](https://github.com/daniel-hutao/k8s-source-code-analysis/blob/master/prepare/debug-environment.md)
* [create-cluster-kubeadm](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/)