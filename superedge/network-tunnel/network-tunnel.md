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
  * StreamServer：包括云端tunnel grpc服务证书，key，以及监听端口
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

首先启动函数中会进行若干初始化：

```go
func NewTunnelCommand() *cobra.Command {
	option := options.NewTunnelOption()
	cmd := &cobra.Command{
		Use: "tunnel",
		Run: func(cmd *cobra.Command, args []string) {
			verflag.PrintAndExitIfRequested()

			klog.Infof("Versions: %#v\n", version.Get())
			util.PrintFlags(cmd.Flags())

			err := conf.InitConf(*option.TunnelMode, *option.TunnelConf)
			if err != nil {
				klog.Info("tunnel failed to load configuration file !")
				return
			}
			InitModules(*option.TunnelMode)
			stream.InitStream(*option.TunnelMode)
			tcp.InitTcp()
			https.InitHttps()
			LoadModules(*option.TunnelMode)
			ShutDown()
		},
	}
	fs := cmd.Flags()
	namedFlagSets := option.Addflag()
	for _, f := range namedFlagSets.FlagSets {
		fs.AddFlagSet(f)
	}
	return cmd
}
```

下面分别介绍：

* stream.InitStream

```go
func InitStream(mode string) {
	if mode == util.CLOUD {
		if !conf.TunnelConf.TunnlMode.Cloud.Stream.Dns.Debug {
			err := connect.InitDNS()
			if err != nil {
				klog.Errorf("init client-go fail err = %v", err)
				return
			}
		}
		err := token.InitTokenCache(conf.TunnelConf.TunnlMode.Cloud.Stream.Server.TokenFile)
		if err != nil {
			klog.Error("Error loading token file ！")
		}
	} else {
		err := connect.InitToken(os.Getenv(util.NODE_NAME_ENV), conf.TunnelConf.TunnlMode.EDGE.StreamEdge.Client.Token)
		if err != nil {
			klog.Errorf("initialize the edge node token err = %v", err)
			return
		}
	}
	model.Register(&Stream{})
	klog.Infof("init module: %s success !", util.STREAM)
}
```

InitStream首先判断tunnel是云端还是边缘，对于云端会执行InitDNS初始化coredns host plugins configmap刷新相关配置：

```go
func InitDNS() error {
	coreDns = &CoreDns{
		Update: make(chan struct{}),
	}
	coreDns.PodIp = os.Getenv(util.POD_IP_ENV)
	klog.Infof("endpoint of the proxycloud pod = %s ", coreDns.PodIp)
	config, err := rest.InClusterConfig()
	if err != nil {
		klog.Errorf("client-go get inclusterconfig  fail err = %v", err)
		return err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		klog.Errorf("get client fail err = %v", err)
		return err
	}
	coreDns.ClientSet = clientset
	coreDns.Namespace = os.Getenv(util.POD_NAMESPACE_ENV)
	return nil
}
```

coreDns.PodIp初始化为云端tunnel pod ip；coredns.Namespace初始化为云端tunnel pod所属namespace；同时根据kubeconfig创建kubeclient(inCluster模式)

而对于边端则会执行InitToken初始化clientToken，包括边缘节点名称以及通信携带的token

```go
// github.com/superedge/superedge/pkg/tunnel/proxy/stream/streammng/connect/streaminterceptor.go
var clientToken string
...
func InitToken(nodeName, tk string) error {
	var err error
	clientToken, err = token.GetTonken(nodeName, tk)
	klog.Infof("stream clinet token nodename = %s token = %s", nodeName, tk)
	if err != nil {
		klog.Error("client get token fail !")
	}
	return err
}
```

最后会注册stream模块(grpc连接隧道)

* tcp.InitTcp：注册了TcpProxy模块(建立在grpc隧道之上)
* https.InitHttps：注册了https模块(建立在grpc隧道之上)
* LoadModules：加载各模块，会执行上述已注册模块的Start函数
```go
func LoadModules(mode string) {
	modules := GetModules()
	for n, m := range modules {
		context.GetContext().AddModule(n)
		klog.Infof("starting module:%s", m.Name())
		m.Start(mode)
		klog.Infof("start module:%s success !", m.Name())
	}

}
```

如下分别介绍stream，tcpProxy以及https模块的Start函数：

1、stream

```go
func (stream *Stream) Start(mode string) {
	context.GetContext().RegisterHandler(util.STREAM_HEART_BEAT, util.STREAM, streammsg.HeartbeatHandler)
	var channelzAddr string
	if mode == util.CLOUD {
		go connect.StartServer()
		if !conf.TunnelConf.TunnlMode.Cloud.Stream.Dns.Debug {
			go connect.SynCorefile()
		}
		channelzAddr = conf.TunnelConf.TunnlMode.Cloud.Stream.Server.ChannelzAddr
	} else {
		go connect.StartSendClient()
		channelzAddr = conf.TunnelConf.TunnlMode.EDGE.StreamEdge.Client.ChannelzAddr
	}

	go connect.StartLogServer(mode)

	go connect.StartChannelzServer(channelzAddr)
}
```

首先调用RegisterHandler注册心跳消息处理函数HeartbeatHandler，其中util.STREAM以及util.STREAM_HEART_BEAT分别对应StreamMsg的category以及type字段

如果tunnel位于云端，则启动grpc server并监听StreamServer.GrpcPort，如下：

```go
func StartServer() {
	creds, err := credentials.NewServerTLSFromFile(conf.TunnelConf.TunnlMode.Cloud.Stream.Server.Cert, conf.TunnelConf.TunnlMode.Cloud.Stream.Server.Key)
	if err != nil {
		klog.Errorf("failed to create credentials: %v", err)
		return
	}
	opts := []grpc.ServerOption{grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp), grpc.StreamInterceptor(ServerStreamInterceptor), grpc.Creds(creds)}
	s := grpc.NewServer(opts...)
	proto.RegisterStreamServer(s, &stream.Server{})

	lis, err := net.Listen("tcp", "0.0.0.0:"+strconv.Itoa(conf.TunnelConf.TunnlMode.Cloud.Stream.Server.GrpcPort))
	klog.Infof("the https server of the cloud tunnel  listen on %s", "0.0.0.0:"+strconv.Itoa(conf.TunnelConf.TunnlMode.Cloud.Stream.Server.GrpcPort))
	if err != nil {
		klog.Fatalf("failed to listen: %v", err)
		return
	}
	if err := s.Serve(lis); err != nil {
		klog.Fatalf("failed to serve: %v", err)
		return
	}
}
```

之后会调用SynCorefile执行同步coredns host plugins configmap刷新逻辑，每隔一分钟执行依次一次checkHosts，如下：

```go
func SynCorefile() {
	for {
		klog.V(8).Infof("connected node total = %d nodes = %v", len(context.GetContext().GetNodes()), context.GetContext().GetNodes())
		err := coreDns.checkHosts()
		if err != nil {
			klog.Errorf("failed to synchronize hosts periodically err = %v", err)
		}
		time.Sleep(60 * time.Second)
	}
}
```

而checkHosts负责configmap具体的刷新操作：

```go
func (dns *CoreDns) checkHosts() error {
	nodes, flag := parseHosts()
	if !flag {
		return nil
	}
	var hostsBuffer bytes.Buffer
	for k, v := range nodes {
		hostsBuffer.WriteString(v)
		hostsBuffer.WriteString("    ")
		hostsBuffer.WriteString(k)
		hostsBuffer.WriteString("\n")
	}
	cm, err := dns.ClientSet.CoreV1().ConfigMaps(dns.Namespace).Get(cctx.TODO(), conf.TunnelConf.TunnlMode.Cloud.Stream.Dns.Configmap, metav1.GetOptions{})
	if err != nil {
		klog.Errorf("get configmap fail err = %v", err)
		return err
	}
	if hostsBuffer.Len() != 0 {
		cm.Data[util.COREFILE_HOSTS_FILE] = hostsBuffer.String()
	} else {
		cm.Data[util.COREFILE_HOSTS_FILE] = ""
	}
	_, err = dns.ClientSet.CoreV1().ConfigMaps(dns.Namespace).Update(cctx.TODO(), cm, metav1.UpdateOptions{})
	if err != nil {
		klog.Errorf("update configmap fail err = %v", err)
		return err
	}
	klog.Infof("update configmap success!")
	return nil
}
```

首先调用parseHosts获取所有云端tunnel连接的边缘节点名称以及对应云端tunnel pod ip映射列表，然后写入hostsBuffer(`tunnel pod ip` `nodeName`形式)，如果有变化则将这个内容覆盖写入configmap并更新

而如果tunnel位于边端，则会调用StartSendClient进行隧道的打通：

```go
func StartSendClient() {
	conn, clictx, cancle, err := StartClient()
	if err != nil {
		klog.Error("edge start client error !")
		klog.Flush()
		os.Exit(1)
	}
	streamConn = conn
	defer func() {
		conn.Close()
		cancle()
	}()

	go func(monitor *grpc.ClientConn) {
		mcount := 0
		for {
			if conn.GetState() == connectivity.Ready {
				mcount = 0
			} else {
				mcount += 1
			}
			klog.V(8).Infof("grpc connection status = %s count = %v", conn.GetState(), mcount)
			if mcount >= util.TIMEOUT_EXIT {
				klog.Error("grpc connection rebuild timed out, container exited !")
				klog.Flush()
				os.Exit(1)
			}
			klog.V(8).Infof("grpc connection status of node = %v", conn.GetState())
			time.Sleep(1 * time.Second)
		}
	}(conn)
	running := true
	count := 0
	for running {
		if conn.GetState() == connectivity.Ready {
			cli := proto.NewStreamClient(conn)
			stream.Send(cli, clictx)
			count = 0
		}
		count += 1
		klog.V(8).Infof("node connection status = %s count = %v", conn.GetState(), count)
		time.Sleep(1 * time.Second)
		if count >= util.TIMEOUT_EXIT {
			klog.Error("the streamClient retrying to establish a connection timed out and the container exited !")
			klog.Flush()
			os.Exit(1)
		}
	}
}
```

首先调用StartClient根据云端tunnel域名构建证书，并对云端tunnel服务地址调用grpc.Dial连接grpc连接，并返回grpc.ClientConn

```go
func StartClient() (*grpc.ClientConn, ctx.Context, ctx.CancelFunc, error) {
	creds, err := credentials.NewClientTLSFromFile(conf.TunnelConf.TunnlMode.EDGE.StreamEdge.Client.Cert, conf.TunnelConf.TunnlMode.EDGE.StreamEdge.Client.Dns)
	if err != nil {
		klog.Errorf("failed to load credentials: %v", err)
		return nil, nil, nil, err
	}
	opts := []grpc.DialOption{grpc.WithKeepaliveParams(kacp), grpc.WithStreamInterceptor(ClientStreamInterceptor), grpc.WithTransportCredentials(creds)}
	conn, err := grpc.Dial(conf.TunnelConf.TunnlMode.EDGE.StreamEdge.Client.ServerName, opts...)
	if err != nil {
		klog.Error("edge start client fail !")
		return nil, nil, nil, err
	}
	clictx, cancle := ctx.WithTimeout(ctx.Background(), time.Duration(math.MaxInt64))
	return conn, clictx, cancle, nil
}
```

之后等待grpc连接状态变为Ready(隧道建立好了)，然后调用proto.NewStreamClient在grpc.ClientConn上建立streamClient，并对streamClient执行stream.Send：

```go
func Send(client proto.StreamClient, clictx ctx.Context) {
	stream, err := client.TunnelStreaming(clictx)
	if err != nil {
		klog.Error("EDGE-SEND fetch stream failed !")
		return
	}
	klog.Info("streamClient created successfully")
	errChan := make(chan error, 2)
	go func(send proto.Stream_TunnelStreamingClient, sc chan error) {
		sendErr := send.SendMsg(nil)
		if sendErr != nil {
			klog.Errorf("streamClient failed to send message err = %v", sendErr)
		}
		sc <- sendErr
	}(stream, errChan)

	go func(recv proto.Stream_TunnelStreamingClient, rc chan error) {
		recvErr := recv.RecvMsg(nil)
		if recvErr != nil {
			klog.Errorf("streamClient failed to receive message err = %v", recvErr)
		}
		rc <- recvErr
	}(stream, errChan)

	e := <-errChan
	klog.Errorf("the stream of streamClient is disconnected err = %v", e)
	err = stream.CloseSend()
	if err != nil {
		klog.Errorf("failed to close stream send err: %v", err)
	}
}
```

stream.Send会向grpc连接对端，也即云端tunnel，发送空消息并等待对方回应

相应的，云端tunnel会对该消息进行接受并回应，如下：

```go
func StartServer() {
	creds, err := credentials.NewServerTLSFromFile(conf.TunnelConf.TunnlMode.Cloud.Stream.Server.Cert, conf.TunnelConf.TunnlMode.Cloud.Stream.Server.Key)
	if err != nil {
		klog.Errorf("failed to create credentials: %v", err)
		return
	}
	opts := []grpc.ServerOption{grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp), grpc.StreamInterceptor(ServerStreamInterceptor), grpc.Creds(creds)}
	s := grpc.NewServer(opts...)
	proto.RegisterStreamServer(s, &stream.Server{})

	lis, err := net.Listen("tcp", "0.0.0.0:"+strconv.Itoa(conf.TunnelConf.TunnlMode.Cloud.Stream.Server.GrpcPort))
	klog.Infof("the https server of the cloud tunnel  listen on %s", "0.0.0.0:"+strconv.Itoa(conf.TunnelConf.TunnlMode.Cloud.Stream.Server.GrpcPort))
	if err != nil {
		klog.Fatalf("failed to listen: %v", err)
		return
	}
	if err := s.Serve(lis); err != nil {
		klog.Fatalf("failed to serve: %v", err)
		return
	}
}

type Server struct{}

func (s *Server) TunnelStreaming(stream proto.Stream_TunnelStreamingServer) error {
	errChan := make(chan error, 2)

	go func(sendStream proto.Stream_TunnelStreamingServer, sendChan chan error) {
		sendErr := sendStream.SendMsg(nil)
		if sendErr != nil {
			klog.Errorf("streamServer failed to send message err = %v", sendErr)
		}
		sendChan <- sendErr
	}(stream, errChan)

	go func(recvStream proto.Stream_TunnelStreamingServer, recvChan chan error) {
		recvErr := stream.RecvMsg(nil)
		if recvErr != nil {
			klog.Errorf("streamServer failed to receive message err = %v", recvErr)
		}
		recvChan <- recvErr
	}(stream, errChan)

	e := <-errChan
	klog.Errorf("the stream of streamServer is disconnected err = %v", e)
	return e
}
```

之后StartSendClient会每隔1s发送空消息给云端tunnel，并接受回应，来保持连接一直处于Ready状态

2、tcpProxy



3、https


## 总结

## 展望

* 目前tunnel整体代码质量需要改善
* 支持更多的网络协议
* 支持云端访问边缘节点业务pod server
* 多副本云端tunnel configmap更新冲突解决