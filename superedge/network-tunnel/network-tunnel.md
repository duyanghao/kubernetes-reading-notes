SuperEdge 云边隧道network-tunnel源码分析
=====================================

## 前言

云边隧道主要用于代理云端访问边缘节点组件的请求，解决云端无法直接访问边缘节点的问题（边缘节点没有暴露在公网中）

架构图如下所示：

![](images/tunnel.png)

实现原理为：

* 边缘节点上tunnel-edge主动连接云端tunnel-cloud service，tunnel-cloud service根据负载均衡策略将请求转到tunnel-cloud的具体pod上
* tunnel-edge与tunnel-cloud建立grpc连接后，tunnel-cloud会把自身的podIp和tunnel-edge所在节点的nodeName的映射写入DNS(tunnel dns)。grpc连接断开之后，tunnel-cloud会删除相关podIp和节点名的映射

而整个请求的代理转发流程如下：

* apiserver或者其它云端的应用访问边缘节点上的kubelet或者其它应用时，tunnel-dns通过DNS劫持(将host中的节点名解析为tunnel-cloud的podIp)把请求转发到tunnel-cloud的pod上
* tunnel-cloud根据节点名把请求信息转发到节点名对应的与tunnel-edge建立的grpc连接上
* tunnel-edge根据接收的请求信息请求边缘节点上的应用

## tunnel配置&数据结构

```go
type Tunnel struct {
	TunnlMode *TunnelMode `toml:"mode"`
}

type TunnelMode struct {
	Cloud *TunnelCloud `toml:"cloud"`
	EDGE  *TunnelEdge  `toml:"edge"`
}
```

TunnelCloud代表云端配置而TunnelEdge代表边端配置，下面依次介绍：

```go
type TunnelCloud struct {
	Https  *HttpsServer      `toml:"https"`
	Stream *StreamCloud      `toml:"stream"`
	Tcp    map[string]string `toml:"tcp"`
}

type HttpsServer struct {
	Cert string            `toml:"cert"`
	Key  string            `toml:"key"`
	Addr map[string]string `toml:"addr"`
}

type StreamCloud struct {
	Server *StreamServer `toml:"server"`
	Dns    *Dns          `toml:"dns"`
}

type StreamServer struct {
	TokenFile    string `toml:"tokenfile"`
	Key          string `toml:"key"`
	Cert         string `toml:"cert"`
	GrpcPort     int    `toml:"grpcport"`
	LogPort      int    `toml:"logport"`
	ChannelzAddr string `toml:"channelzaddr"`
}

type Dns struct {
	Configmap string `toml:"configmap"`
	Hosts     string `toml:"hosts"`
	Service   string `toml:"service"`
	Debug     bool   `toml:"debug"`
}

type TunnelEdge struct {
	Https      *HttpsClient `toml:"https"`
	StreamEdge StreamEdge   `toml:"stream"`
}

type HttpsClient struct {
	Cert string `toml:"cert"`
	Key  string `toml:"key"`
}

type StreamEdge struct {
	Client *StreamClient `toml:"client"`
}

type StreamClient struct {
	Token        string `toml:"token"`
	Cert         string `toml:"cert"`
	Dns          string `toml:"dns"`
	ServerName   string `toml:"servername"`
	LogPort      int    `toml:"logport"`
	ChannelzAddr string `toml:"channelzaddr"`
}
```

TunnelCloud包含如下结构：

* HttpsServer：云端tunnel证书，key以及Addr map(key表示云端tunnel https协议监听端口，而value表示边端tunnel需要访问的地址(kubelet监听地址：`127.0.0.1:10250`))
* StreamCloud：包括StreamServer以及Dns配置：
  * StreamServer：包括云端tunnel grpc服务证书，key，以及地址
  * Dns：包括了云端coredns相关信息：
    * Configmap：云端coredns host plugin使用的挂载configmap，其中存放有云端tunnel ip以及边缘节点名映射列表
    * Hosts：云端tunnel对coredns host plugin使用的configmap的本地挂载文件
    * Service：云端tunnel service名称
* Tcp：包括了云端tunnel tcp监听地址以及边端节点某进程的tcp监听地址

TunnelCloud包含如下结构：

* HttpsClient：包括边缘https进程的证书，key
* StreamEdge：包括了云端tunnel service的dns以及地址ServerName

在介绍完tunnel的配置后，下面介绍tunnel使用的内部数据结构(github.com/superedge/superedge/pkg/tunnel/context)：

1、StreamMsg

StreamMsg为云边grpc隧道传输的数据格式：

```
message StreamMsg {
    string node = 1;
    string category = 2;
    string type = 3;
    string topic = 4;
    bytes data = 5;
    string addr = 6;
}
```

* node：表示边缘节点名称
* category：消息范畴
* type：消息类型
* topic：消息uid
* data：消息数据内容
* addr：相关地址

2、conn

```go
type conn struct {
	uid string
	ch  chan *proto.StreamMsg
}
```

conn表示tunnel grpc连接隧道上的连接：

* uid：表示conn uid
* ch：StreamMsg消息传递的管道


3、connContext

```go
type connContext struct {
	conns    map[string]*conn
	connLock sync.RWMutex
}
```

connContext表示本tunnel grpc上所有连接，其中conns key为conn uid，value为conn

4、node

```go
type node struct {
	name      string
	ch        chan *proto.StreamMsg
	conns     *[]string
	connsLock sync.RWMutex
}
```

node表示边缘节点相关连接信息：

* name：边缘节点名称
* ch：消息传输的管道
* conns：该边缘节点产生的所有conn uid列表

5、nodeContext

```go
type nodeContext struct {
	nodes    map[string]*node
	nodeLock sync.RWMutex
}
```

nodeContext表示本tunnel上所有相关节点信息，其中nodes key为边缘节点名称，value为node

在介绍完tunnel核心配置和数据结构后，下面开始分析源码

## tunnel源码分析



## 总结

## 展望

* 目前tunnel整体代码质量需要改善
* 支持更多的网络协议
* 支持云端访问边缘节点业务pod server
* 多副本云端tunnel configmap更新冲突解决