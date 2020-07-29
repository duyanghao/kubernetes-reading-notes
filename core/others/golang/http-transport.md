http transport
==============

## http transport usage demo

```go
package main

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
	"net"
)

func send_http_request(addr string, port int) error {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	// construct encoded endpoint
	Url, err := url.Parse(fmt.Sprintf("http://%s:%d", addr, port))
	if err != nil {
		return err
	}
	Url.Path += "/index"
	endpoint := Url.String()
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return err
	}
	// use httpClient to send request
	rsp, err := client.Do(req)
	if err != nil {
		return err
	}
	// close the connection to reuse it
	defer rsp.Body.Close()
	// check status code
	if rsp.StatusCode != http.StatusOK {
		return fmt.Errorf("get rsp error: %v", rsp)
	}
	return err
}

func main() {
	send_http_request("xxx", 8080)
}
```

## analysis

先看看http.Client结构体，如下：

```go
// A Client is an HTTP client. Its zero value (DefaultClient) is a
// usable client that uses DefaultTransport.
//
// The Client's Transport typically has internal state (cached TCP
// connections), so Clients should be reused instead of created as
// needed. Clients are safe for concurrent use by multiple goroutines.
//
// A Client is higher-level than a RoundTripper (such as Transport)
// and additionally handles HTTP details such as cookies and
// redirects.
//
// When following redirects, the Client will forward all headers set on the
// initial Request except:
//
// • when forwarding sensitive headers like "Authorization",
// "WWW-Authenticate", and "Cookie" to untrusted targets.
// These headers will be ignored when following a redirect to a domain
// that is not a subdomain match or exact match of the initial domain.
// For example, a redirect from "foo.com" to either "foo.com" or "sub.foo.com"
// will forward the sensitive headers, but a redirect to "bar.com" will not.
//
// • when forwarding the "Cookie" header with a non-nil cookie Jar.
// Since each redirect may mutate the state of the cookie jar,
// a redirect may possibly alter a cookie set in the initial request.
// When forwarding the "Cookie" header, any mutated cookies will be omitted,
// with the expectation that the Jar will insert those mutated cookies
// with the updated values (assuming the origin matches).
// If Jar is nil, the initial cookies are forwarded without change.
//
type Client struct {
	// Transport specifies the mechanism by which individual
	// HTTP requests are made.
	// If nil, DefaultTransport is used.
	Transport RoundTripper

	// CheckRedirect specifies the policy for handling redirects.
	// If CheckRedirect is not nil, the client calls it before
	// following an HTTP redirect. The arguments req and via are
	// the upcoming request and the requests made already, oldest
	// first. If CheckRedirect returns an error, the Client's Get
	// method returns both the previous Response (with its Body
	// closed) and CheckRedirect's error (wrapped in a url.Error)
	// instead of issuing the Request req.
	// As a special case, if CheckRedirect returns ErrUseLastResponse,
	// then the most recent response is returned with its body
	// unclosed, along with a nil error.
	//
	// If CheckRedirect is nil, the Client uses its default policy,
	// which is to stop after 10 consecutive requests.
	CheckRedirect func(req *Request, via []*Request) error

	// Jar specifies the cookie jar.
	//
	// The Jar is used to insert relevant cookies into every
	// outbound Request and is updated with the cookie values
	// of every inbound Response. The Jar is consulted for every
	// redirect that the Client follows.
	//
	// If Jar is nil, cookies are only sent if they are explicitly
	// set on the Request.
	Jar CookieJar

	// Timeout specifies a time limit for requests made by this
	// Client. The timeout includes connection time, any
	// redirects, and reading the response body. The timer remains
	// running after Get, Head, Post, or Do return and will
	// interrupt reading of the Response.Body.
	//
	// A Timeout of zero means no timeout.
	//
	// The Client cancels requests to the underlying Transport
	// as if the Request's Context ended.
	//
	// For compatibility, the Client will also use the deprecated
	// CancelRequest method on Transport if found. New
	// RoundTripper implementations should use the Request's Context
	// for cancellation instead of implementing CancelRequest.
	Timeout time.Duration
}
```

* Transport：http client实际发送请求结构体
* Timeout：http client请求超时设置(后续在详细分析)

在看Transport结构体(net/http/client.go)：

```go
// RoundTripper is an interface representing the ability to execute a
// single HTTP transaction, obtaining the Response for a given Request.
//
// A RoundTripper must be safe for concurrent use by multiple
// goroutines.
type RoundTripper interface {
	// RoundTrip executes a single HTTP transaction, returning
	// a Response for the provided Request.
	//
	// RoundTrip should not attempt to interpret the response. In
	// particular, RoundTrip must return err == nil if it obtained
	// a response, regardless of the response's HTTP status code.
	// A non-nil err should be reserved for failure to obtain a
	// response. Similarly, RoundTrip should not attempt to
	// handle higher-level protocol details such as redirects,
	// authentication, or cookies.
	//
	// RoundTrip should not modify the request, except for
	// consuming and closing the Request's Body. RoundTrip may
	// read fields of the request in a separate goroutine. Callers
	// should not mutate or reuse the request until the Response's
	// Body has been closed.
	//
	// RoundTrip must always close the body, including on errors,
	// but depending on the implementation may do so in a separate
	// goroutine even after RoundTrip returns. This means that
	// callers wanting to reuse the body for subsequent requests
	// must arrange to wait for the Close call before doing so.
	//
	// The Request's URL and Header fields must be initialized.
	RoundTrip(*Request) (*Response, error)
}
```

从注释可以看到RoundTripper负责HTTP请求的建立，发送，接收HTTP应答以及关闭；但是不应该对HTTP应答进行额外处理，例如：redirects, authentication, or cookies等上层协议细节。另外RoundTripper也是goroutines-safe的

其中RoundTrip方法的Request和Response参数如下(net/http/request.go)：

```go
// A Request represents an HTTP request received by a server
// or to be sent by a client.
//
// The field semantics differ slightly between client and server
// usage. In addition to the notes on the fields below, see the
// documentation for Request.Write and RoundTripper.
type Request struct {
	// Method specifies the HTTP method (GET, POST, PUT, etc.).
	// For client requests, an empty string means GET.
	//
	// Go's HTTP client does not support sending a request with
	// the CONNECT method. See the documentation on Transport for
	// details.
	Method string

	// URL specifies either the URI being requested (for server
	// requests) or the URL to access (for client requests).
	//
	// For server requests, the URL is parsed from the URI
	// supplied on the Request-Line as stored in RequestURI.  For
	// most requests, fields other than Path and RawQuery will be
	// empty. (See RFC 7230, Section 5.3)
	//
	// For client requests, the URL's Host specifies the server to
	// connect to, while the Request's Host field optionally
	// specifies the Host header value to send in the HTTP
	// request.
	URL *url.URL
    ...
	// Body is the request's body.
	//
	// For client requests, a nil body means the request has no
	// body, such as a GET request. The HTTP Client's Transport
	// is responsible for calling the Close method.
	//
	// For server requests, the Request Body is always non-nil
	// but will return EOF immediately when no body is present.
	// The Server will close the request body. The ServeHTTP
	// Handler does not need to.
	Body io.ReadCloser
    ...
}

...
// Response represents the response from an HTTP request.
//
// The Client and Transport return Responses from servers once
// the response headers have been received. The response body
// is streamed on demand as the Body field is read.
type Response struct {
	Status     string // e.g. "200 OK"
	StatusCode int    // e.g. 200
	Proto      string // e.g. "HTTP/1.0"
	ProtoMajor int    // e.g. 1
	ProtoMinor int    // e.g. 0
    ...
}
```

这里Request和Response就是我们熟悉的HTTP请求和应答结构体

这里我们看demo对Transport的使用如下(net/http/transport.go)：

```go
client := &http.Client{
    Transport: &http.Transport{
        Proxy: http.ProxyFromEnvironment,
        DialContext: (&net.Dialer{
            Timeout:   30 * time.Second,
            KeepAlive: 30 * time.Second,
            DualStack: true,
        }).DialContext,
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 100,
        IdleConnTimeout:     90 * time.Second,
    },
}

...
// Transport is an implementation of RoundTripper that supports HTTP,
// HTTPS, and HTTP proxies (for either HTTP or HTTPS with CONNECT).
//
// By default, Transport caches connections for future re-use.
// This may leave many open connections when accessing many hosts.
// This behavior can be managed using Transport's CloseIdleConnections method
// and the MaxIdleConnsPerHost and DisableKeepAlives fields.
//
// Transports should be reused instead of created as needed.
// Transports are safe for concurrent use by multiple goroutines.
//
// A Transport is a low-level primitive for making HTTP and HTTPS requests.
// For high-level functionality, such as cookies and redirects, see Client.
//
// Transport uses HTTP/1.1 for HTTP URLs and either HTTP/1.1 or HTTP/2
// for HTTPS URLs, depending on whether the server supports HTTP/2,
// and how the Transport is configured. The DefaultTransport supports HTTP/2.
// To explicitly enable HTTP/2 on a transport, use golang.org/x/net/http2
// and call ConfigureTransport. See the package docs for more about HTTP/2.
//
// Responses with status codes in the 1xx range are either handled
// automatically (100 expect-continue) or ignored. The one
// exception is HTTP status code 101 (Switching Protocols), which is
// considered a terminal status and returned by RoundTrip. To see the
// ignored 1xx responses, use the httptrace trace package's
// ClientTrace.Got1xxResponse.
//
// Transport only retries a request upon encountering a network error
// if the request is idempotent and either has no body or has its
// Request.GetBody defined. HTTP requests are considered idempotent if
// they have HTTP methods GET, HEAD, OPTIONS, or TRACE; or if their
// Header map contains an "Idempotency-Key" or "X-Idempotency-Key"
// entry. If the idempotency key value is an zero-length slice, the
// request is treated as idempotent but the header is not sent on the
// wire.
type Transport struct {
	idleMu       sync.Mutex
	closeIdle    bool                                // user has requested to close all idle conns
	idleConn     map[connectMethodKey][]*persistConn // most recently used at end
	idleConnWait map[connectMethodKey]wantConnQueue  // waiting getConns
	idleLRU      connLRU

	reqMu       sync.Mutex
	reqCanceler map[*Request]func(error)

	altMu    sync.Mutex   // guards changing altProto only
	altProto atomic.Value // of nil or map[string]RoundTripper, key is URI scheme

	connsPerHostMu   sync.Mutex
	connsPerHost     map[connectMethodKey]int
	connsPerHostWait map[connectMethodKey]wantConnQueue // waiting getConns

	// Proxy specifies a function to return a proxy for a given
	// Request. If the function returns a non-nil error, the
	// request is aborted with the provided error.
	//
	// The proxy type is determined by the URL scheme. "http",
	// "https", and "socks5" are supported. If the scheme is empty,
	// "http" is assumed.
	//
	// If Proxy is nil or returns a nil *URL, no proxy is used.
	Proxy func(*Request) (*url.URL, error)

	// DialContext specifies the dial function for creating unencrypted TCP connections.
	// If DialContext is nil (and the deprecated Dial below is also nil),
	// then the transport dials using package net.
	//
	// DialContext runs concurrently with calls to RoundTrip.
	// A RoundTrip call that initiates a dial may end up using
	// a connection dialed previously when the earlier connection
	// becomes idle before the later DialContext completes.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// Dial specifies the dial function for creating unencrypted TCP connections.
	//
	// Dial runs concurrently with calls to RoundTrip.
	// A RoundTrip call that initiates a dial may end up using
	// a connection dialed previously when the earlier connection
	// becomes idle before the later Dial completes.
	//
	// Deprecated: Use DialContext instead, which allows the transport
	// to cancel dials as soon as they are no longer needed.
	// If both are set, DialContext takes priority.
	Dial func(network, addr string) (net.Conn, error)

	// DialTLS specifies an optional dial function for creating
	// TLS connections for non-proxied HTTPS requests.
	//
	// If DialTLS is nil, Dial and TLSClientConfig are used.
	//
	// If DialTLS is set, the Dial hook is not used for HTTPS
	// requests and the TLSClientConfig and TLSHandshakeTimeout
	// are ignored. The returned net.Conn is assumed to already be
	// past the TLS handshake.
	DialTLS func(network, addr string) (net.Conn, error)

	// TLSClientConfig specifies the TLS configuration to use with
	// tls.Client.
	// If nil, the default configuration is used.
	// If non-nil, HTTP/2 support may not be enabled by default.
	TLSClientConfig *tls.Config

	// TLSHandshakeTimeout specifies the maximum amount of time waiting to
	// wait for a TLS handshake. Zero means no timeout.
	TLSHandshakeTimeout time.Duration

	// DisableKeepAlives, if true, disables HTTP keep-alives and
	// will only use the connection to the server for a single
	// HTTP request.
	//
	// This is unrelated to the similarly named TCP keep-alives.
	DisableKeepAlives bool

	// DisableCompression, if true, prevents the Transport from
	// requesting compression with an "Accept-Encoding: gzip"
	// request header when the Request contains no existing
	// Accept-Encoding value. If the Transport requests gzip on
	// its own and gets a gzipped response, it's transparently
	// decoded in the Response.Body. However, if the user
	// explicitly requested gzip it is not automatically
	// uncompressed.
	DisableCompression bool

	// MaxIdleConns controls the maximum number of idle (keep-alive)
	// connections across all hosts. Zero means no limit.
	MaxIdleConns int

	// MaxIdleConnsPerHost, if non-zero, controls the maximum idle
	// (keep-alive) connections to keep per-host. If zero,
	// DefaultMaxIdleConnsPerHost is used.
	MaxIdleConnsPerHost int

	// MaxConnsPerHost optionally limits the total number of
	// connections per host, including connections in the dialing,
	// active, and idle states. On limit violation, dials will block.
	//
	// Zero means no limit.
	MaxConnsPerHost int

	// IdleConnTimeout is the maximum amount of time an idle
	// (keep-alive) connection will remain idle before closing
	// itself.
	// Zero means no limit.
	IdleConnTimeout time.Duration

	// ResponseHeaderTimeout, if non-zero, specifies the amount of
	// time to wait for a server's response headers after fully
	// writing the request (including its body, if any). This
	// time does not include the time to read the response body.
	ResponseHeaderTimeout time.Duration

	// ExpectContinueTimeout, if non-zero, specifies the amount of
	// time to wait for a server's first response headers after fully
	// writing the request headers if the request has an
	// "Expect: 100-continue" header. Zero means no timeout and
	// causes the body to be sent immediately, without
	// waiting for the server to approve.
	// This time does not include the time to send the request header.
	ExpectContinueTimeout time.Duration

	// TLSNextProto specifies how the Transport switches to an
	// alternate protocol (such as HTTP/2) after a TLS NPN/ALPN
	// protocol negotiation. If Transport dials an TLS connection
	// with a non-empty protocol name and TLSNextProto contains a
	// map entry for that key (such as "h2"), then the func is
	// called with the request's authority (such as "example.com"
	// or "example.com:1234") and the TLS connection. The function
	// must return a RoundTripper that then handles the request.
	// If TLSNextProto is not nil, HTTP/2 support is not enabled
	// automatically.
	TLSNextProto map[string]func(authority string, c *tls.Conn) RoundTripper

	// ProxyConnectHeader optionally specifies headers to send to
	// proxies during CONNECT requests.
	ProxyConnectHeader Header

	// MaxResponseHeaderBytes specifies a limit on how many
	// response bytes are allowed in the server's response
	// header.
	//
	// Zero means to use a default limit.
	MaxResponseHeaderBytes int64

	// WriteBufferSize specifies the size of the write buffer used
	// when writing to the transport.
	// If zero, a default (currently 4KB) is used.
	WriteBufferSize int

	// ReadBufferSize specifies the size of the read buffer used
	// when reading from the transport.
	// If zero, a default (currently 4KB) is used.
	ReadBufferSize int

	// nextProtoOnce guards initialization of TLSNextProto and
	// h2transport (via onceSetNextProtoDefaults)
	nextProtoOnce      sync.Once
	h2transport        h2Transport // non-nil if http2 wired up
	tlsNextProtoWasNil bool        // whether TLSNextProto was nil when the Once fired

	// ForceAttemptHTTP2 controls whether HTTP/2 is enabled when a non-zero
	// Dial, DialTLS, or DialContext func or TLSClientConfig is provided.
	// By default, use of any those fields conservatively disables HTTP/2.
	// To use a custom dialer or TLS config and still attempt HTTP/2
	// upgrades, set this to true.
	ForceAttemptHTTP2 bool
}
```

http.Transport实现了http.RoundTripper，支持HTTP，HTTPS以及HTTP Proxy(for either HTTP or HTTPS with CONNECT)

http.Transport默认实现了TCP连接池，会复用底层TCP连接。所以推荐的做法是初始化一次http.Transport，然后重复使用

http Transport对HTTP URLs使用HTTP/1.1协议；对HTTPS URLs使用HTTP/1.1 or HTTP/2，具体使用哪种协议要取决于Transport的配置以及服务端是否支持HTTP/2协议

Transport默认支持HTTP/2；如果要强制开启HTTP/2，使用ConfigureTransport，详细参考golang.org/x/net/http2

Transport只有在遇到网络故障的情况下会重`试幂等`的请求。另外，http Transport实现了goroutine-safe

接下来我们分析一下`Transport`各字段：

* closeIdle：关闭所有空闲的连接
* idleConn：空闲连接池
* Proxy：对特定的请求返回代理
* DialContext：指定底层TCP连接的创建函数
* Dial(Deprecated)：和DialContext一样的功能，区别在于DialContext多了一个context.Context参数，用于取消dials功能
* DialTLS：为non-proxied HTTPS requests创建TLS connections
* TLSHandshakeTimeout：TLS handshake超时时间
* DisableKeepAlives：禁止HTTP keep-alives，一个连接只用于一次请求(注意区分TCP keep-alives。HTTP keep-alives用于连接复用；TCP keep-alives用于连接保活)
* MaxIdleConns：控制所有hosts的空闲连接最大数目(Zero means no limit.)
* MaxIdleConnsPerHost：控制某个host的空闲连接(keep-alives)最大数目(设置为0，则默认DefaultMaxIdleConnsPerHost=2)
* MaxConnsPerHost：控制某个host的所有连接，包括创建中，正在使用的，以及空闲的连接(including connections in the dialing, active, and idle states)。一旦超过限制，dial会阻塞(Zero means no limit)
* IdleConnTimeout：空闲连接(keep-alives)超时时间
* h2transport：HTTP/2协议对应的transport
* ForceAttemptHTTP2：当Dial, DialTLS, or DialContext func or TLSClientConfig提供时，默认情况下会禁止HTTP/2协议。当使用自定义的这些配置时，需要设置ForceAttemptHTTP2字段开启HTTP2

我们看一下DefaultTransport配置：

```go
// DefaultTransport is the default implementation of Transport and is
// used by DefaultClient. It establishes network connections as needed
// and caches them for reuse by subsequent calls. It uses HTTP proxies
// as directed by the $HTTP_PROXY and $NO_PROXY (or $http_proxy and
// $no_proxy) environment variables.
var DefaultTransport RoundTripper = &Transport{
	Proxy: ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}
```

重点看DialContext实例，展开net.Dialer结构体(net/dial.go)：

```go
// A Dialer contains options for connecting to an address.
//
// The zero value for each field is equivalent to dialing
// without that option. Dialing with the zero value of Dialer
// is therefore equivalent to just calling the Dial function.
type Dialer struct {
	// Timeout is the maximum amount of time a dial will wait for
	// a connect to complete. If Deadline is also set, it may fail
	// earlier.
	//
	// The default is no timeout.
	//
	// When using TCP and dialing a host name with multiple IP
	// addresses, the timeout may be divided between them.
	//
	// With or without a timeout, the operating system may impose
	// its own earlier timeout. For instance, TCP timeouts are
	// often around 3 minutes.
	Timeout time.Duration

	// Deadline is the absolute point in time after which dials
	// will fail. If Timeout is set, it may fail earlier.
	// Zero means no deadline, or dependent on the operating system
	// as with the Timeout option.
	Deadline time.Time

	// LocalAddr is the local address to use when dialing an
	// address. The address must be of a compatible type for the
	// network being dialed.
	// If nil, a local address is automatically chosen.
	LocalAddr Addr

	// DualStack previously enabled RFC 6555 Fast Fallback
	// support, also known as "Happy Eyeballs", in which IPv4 is
	// tried soon if IPv6 appears to be misconfigured and
	// hanging.
	//
	// Deprecated: Fast Fallback is enabled by default. To
	// disable, set FallbackDelay to a negative value.
	DualStack bool

	// FallbackDelay specifies the length of time to wait before
	// spawning a RFC 6555 Fast Fallback connection. That is, this
	// is the amount of time to wait for IPv6 to succeed before
	// assuming that IPv6 is misconfigured and falling back to
	// IPv4.
	//
	// If zero, a default delay of 300ms is used.
	// A negative value disables Fast Fallback support.
	FallbackDelay time.Duration

	// KeepAlive specifies the interval between keep-alive
	// probes for an active network connection.
	// If zero, keep-alive probes are sent with a default value
	// (currently 15 seconds), if supported by the protocol and operating
	// system. Network protocols or operating systems that do
	// not support keep-alives ignore this field.
	// If negative, keep-alive probes are disabled.
	KeepAlive time.Duration

	// Resolver optionally specifies an alternate resolver to use.
	Resolver *Resolver

	// Cancel is an optional channel whose closure indicates that
	// the dial should be canceled. Not all types of dials support
	// cancellation.
	//
	// Deprecated: Use DialContext instead.
	Cancel <-chan struct{}

	// If Control is not nil, it is called after creating the network
	// connection but before actually dialing.
	//
	// Network and address parameters passed to Control method are not
	// necessarily the ones passed to Dial. For example, passing "tcp" to Dial
	// will cause the Control function to be called with "tcp4" or "tcp6".
	Control func(network, address string, c syscall.RawConn) error
}
```

net.Dialer包含了创建TCP连接的各种选项：

* Timeout：TCP连接建立的超时时间(也即三次握手的超时时间)，操作系统的超时时间一般为3 minutes
* Deadline：与Timeout作用类似，只不过限制了确定的超时时刻
* LocalAddr：本地地址，TCP四元组的原始IP地址
* DualStack(Deprecated)：enabled RFC 6555 Fast Fallback Feature
* FallbackDelay：IPv6连接建立的等待时间，如果超时，则会切换到IPv4(A negative value disables Fast Fallback support.)
* KeepAlive：设置了活跃连接的TCP keep-alive探针间隔，需要协议层以及操作系统支持(If zero, keep-alive probes are sent with a default value(currently 15 seconds))
* Control：it is called after creating the network connection but before actually dialing ？

接下来我们分析net.Dialer.DialContext，如下：

```go
// Dial connects to the address on the named network.
//
// Known networks are "tcp", "tcp4" (IPv4-only), "tcp6" (IPv6-only),
// "udp", "udp4" (IPv4-only), "udp6" (IPv6-only), "ip", "ip4"
// (IPv4-only), "ip6" (IPv6-only), "unix", "unixgram" and
// "unixpacket".
//
// For TCP and UDP networks, the address has the form "host:port".
// The host must be a literal IP address, or a host name that can be
// resolved to IP addresses.
// The port must be a literal port number or a service name.
// If the host is a literal IPv6 address it must be enclosed in square
// brackets, as in "[2001:db8::1]:80" or "[fe80::1%zone]:80".
// The zone specifies the scope of the literal IPv6 address as defined
// in RFC 4007.
// The functions JoinHostPort and SplitHostPort manipulate a pair of
// host and port in this form.
// When using TCP, and the host resolves to multiple IP addresses,
// Dial will try each IP address in order until one succeeds.
//
// Examples:
//	Dial("tcp", "golang.org:http")
//	Dial("tcp", "192.0.2.1:http")
//	Dial("tcp", "198.51.100.1:80")
//	Dial("udp", "[2001:db8::1]:domain")
//	Dial("udp", "[fe80::1%lo0]:53")
//	Dial("tcp", ":80")
//
// For IP networks, the network must be "ip", "ip4" or "ip6" followed
// by a colon and a literal protocol number or a protocol name, and
// the address has the form "host". The host must be a literal IP
// address or a literal IPv6 address with zone.
// It depends on each operating system how the operating system
// behaves with a non-well known protocol number such as "0" or "255".
//
// Examples:
//	Dial("ip4:1", "192.0.2.1")
//	Dial("ip6:ipv6-icmp", "2001:db8::1")
//	Dial("ip6:58", "fe80::1%lo0")
//
// For TCP, UDP and IP networks, if the host is empty or a literal
// unspecified IP address, as in ":80", "0.0.0.0:80" or "[::]:80" for
// TCP and UDP, "", "0.0.0.0" or "::" for IP, the local system is
// assumed.
//
// For Unix networks, the address must be a file system path.
func Dial(network, address string) (Conn, error) {
	var d Dialer
	return d.Dial(network, address)
}

...

// DialContext connects to the address on the named network using
// the provided context.
//
// The provided Context must be non-nil. If the context expires before
// the connection is complete, an error is returned. Once successfully
// connected, any expiration of the context will not affect the
// connection.
//
// When using TCP, and the host in the address parameter resolves to multiple
// network addresses, any dial timeout (from d.Timeout or ctx) is spread
// over each consecutive dial, such that each is given an appropriate
// fraction of the time to connect.
// For example, if a host has 4 IP addresses and the timeout is 1 minute,
// the connect to each single address will be given 15 seconds to complete
// before trying the next one.
//
// See func Dial for a description of the network and address
// parameters.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (Conn, error) {
	if ctx == nil {
		panic("nil context")
	}
	deadline := d.deadline(ctx, time.Now())
	if !deadline.IsZero() {
		if d, ok := ctx.Deadline(); !ok || deadline.Before(d) {
			subCtx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			ctx = subCtx
		}
	}
	if oldCancel := d.Cancel; oldCancel != nil {
		subCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		go func() {
			select {
			case <-oldCancel:
				cancel()
			case <-subCtx.Done():
			}
		}()
		ctx = subCtx
	}

	// Shadow the nettrace (if any) during resolve so Connect events don't fire for DNS lookups.
	resolveCtx := ctx
	if trace, _ := ctx.Value(nettrace.TraceKey{}).(*nettrace.Trace); trace != nil {
		shadow := *trace
		shadow.ConnectStart = nil
		shadow.ConnectDone = nil
		resolveCtx = context.WithValue(resolveCtx, nettrace.TraceKey{}, &shadow)
	}

	addrs, err := d.resolver().resolveAddrList(resolveCtx, "dial", network, address, d.LocalAddr)
	if err != nil {
		return nil, &OpError{Op: "dial", Net: network, Source: nil, Addr: nil, Err: err}
	}

	sd := &sysDialer{
		Dialer:  *d,
		network: network,
		address: address,
	}

	var primaries, fallbacks addrList
	if d.dualStack() && network == "tcp" {
		primaries, fallbacks = addrs.partition(isIPv4)
	} else {
		primaries = addrs
	}

	var c Conn
	if len(fallbacks) > 0 {
		c, err = sd.dialParallel(ctx, primaries, fallbacks)
	} else {
		c, err = sd.dialSerial(ctx, primaries)
	}
	if err != nil {
		return nil, err
	}

	if tc, ok := c.(*TCPConn); ok && d.KeepAlive >= 0 {
		setKeepAlive(tc.fd, true)
		ka := d.KeepAlive
		if d.KeepAlive == 0 {
			ka = defaultTCPKeepAlive
		}
		setKeepAlivePeriod(tc.fd, ka)
		testHookSetKeepAlive(ka)
	}
	return c, nil
}
```

DialContext用于创建指定网络协议(例如tcp，udp)以及指定地址的连接，例如：

```
// Examples:
//	Dial("tcp", "golang.org:http")
//	Dial("tcp", "192.0.2.1:http")
//	Dial("tcp", "198.51.100.1:80")
//	Dial("udp", "[2001:db8::1]:domain")
//	Dial("udp", "[fe80::1%lo0]:53")
//	Dial("tcp", ":80")
```

分为三个阶段，如下：

* 1、resolveAddrList

```go
// resolveAddrList resolves addr using hint and returns a list of
// addresses. The result contains at least one address when error is
// nil.
func (r *Resolver) resolveAddrList(ctx context.Context, op, network, addr string, hint Addr) (addrList, error) {
	afnet, _, err := parseNetwork(ctx, network, true)
	if err != nil {
		return nil, err
	}
	if op == "dial" && addr == "" {
		return nil, errMissingAddress
	}
	switch afnet {
	case "unix", "unixgram", "unixpacket":
		addr, err := ResolveUnixAddr(afnet, addr)
		if err != nil {
			return nil, err
		}
		if op == "dial" && hint != nil && addr.Network() != hint.Network() {
			return nil, &AddrError{Err: "mismatched local address type", Addr: hint.String()}
		}
		return addrList{addr}, nil
	}
	addrs, err := r.internetAddrList(ctx, afnet, addr)
	if err != nil || op != "dial" || hint == nil {
		return addrs, err
	}
	var (
		tcp      *TCPAddr
		udp      *UDPAddr
		ip       *IPAddr
		wildcard bool
	)
	switch hint := hint.(type) {
	case *TCPAddr:
		tcp = hint
		wildcard = tcp.isWildcard()
	case *UDPAddr:
		udp = hint
		wildcard = udp.isWildcard()
	case *IPAddr:
		ip = hint
		wildcard = ip.isWildcard()
	}
	naddrs := addrs[:0]
	for _, addr := range addrs {
		if addr.Network() != hint.Network() {
			return nil, &AddrError{Err: "mismatched local address type", Addr: hint.String()}
		}
		switch addr := addr.(type) {
		case *TCPAddr:
			if !wildcard && !addr.isWildcard() && !addr.IP.matchAddrFamily(tcp.IP) {
				continue
			}
			naddrs = append(naddrs, addr)
		case *UDPAddr:
			if !wildcard && !addr.isWildcard() && !addr.IP.matchAddrFamily(udp.IP) {
				continue
			}
			naddrs = append(naddrs, addr)
		case *IPAddr:
			if !wildcard && !addr.isWildcard() && !addr.IP.matchAddrFamily(ip.IP) {
				continue
			}
			naddrs = append(naddrs, addr)
		}
	}
	if len(naddrs) == 0 {
		return nil, &AddrError{Err: errNoSuitableAddress.Error(), Addr: hint.String()}
	}
	return naddrs, nil
}

// An addrList represents a list of network endpoint addresses.
type addrList []Addr

// Addr represents a network end point address.
//
// The two methods Network and String conventionally return strings
// that can be passed as the arguments to Dial, but the exact form
// and meaning of the strings is up to the implementation.
type Addr interface {
	Network() string // name of the network (for example, "tcp", "udp")
	String() string  // string form of address (for example, "192.0.2.1:25", "[2001:db8::1]:80")
}
```

根据本地地址网路类型以及地址族分拆目标地址，返回地址列表

* 2、dialSerial

```go
// isIPv4 reports whether addr contains an IPv4 address.
func isIPv4(addr Addr) bool {
	switch addr := addr.(type) {
	case *TCPAddr:
		return addr.IP.To4() != nil
	case *UDPAddr:
		return addr.IP.To4() != nil
	case *IPAddr:
		return addr.IP.To4() != nil
	}
	return false
}

// partition divides an address list into two categories, using a
// strategy function to assign a boolean label to each address.
// The first address, and any with a matching label, are returned as
// primaries, while addresses with the opposite label are returned
// as fallbacks. For non-empty inputs, primaries is guaranteed to be
// non-empty.
func (addrs addrList) partition(strategy func(Addr) bool) (primaries, fallbacks addrList) {
	var primaryLabel bool
	for i, addr := range addrs {
		label := strategy(addr)
		if i == 0 || label == primaryLabel {
			primaryLabel = label
			primaries = append(primaries, addr)
		} else {
			fallbacks = append(fallbacks, addr)
		}
	}
	return
}

...
sd := &sysDialer{
    Dialer:  *d,
    network: network,
    address: address,
}

...
// dialSerial connects to a list of addresses in sequence, returning
// either the first successful connection, or the first error.
func (sd *sysDialer) dialSerial(ctx context.Context, ras addrList) (Conn, error) {
	var firstErr error // The error from the first address is most relevant.

	for i, ra := range ras {
		select {
		case <-ctx.Done():
			return nil, &OpError{Op: "dial", Net: sd.network, Source: sd.LocalAddr, Addr: ra, Err: mapErr(ctx.Err())}
		default:
		}

		deadline, _ := ctx.Deadline()
		partialDeadline, err := partialDeadline(time.Now(), deadline, len(ras)-i)
		if err != nil {
			// Ran out of time.
			if firstErr == nil {
				firstErr = &OpError{Op: "dial", Net: sd.network, Source: sd.LocalAddr, Addr: ra, Err: err}
			}
			break
		}
		dialCtx := ctx
		if partialDeadline.Before(deadline) {
			var cancel context.CancelFunc
			dialCtx, cancel = context.WithDeadline(ctx, partialDeadline)
			defer cancel()
		}

		c, err := sd.dialSingle(dialCtx, ra)
		if err == nil {
			return c, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}

	if firstErr == nil {
		firstErr = &OpError{Op: "dial", Net: sd.network, Source: nil, Addr: nil, Err: errMissingAddress}
	}
	return nil, firstErr
}

// dialSingle attempts to establish and returns a single connection to
// the destination address.
func (sd *sysDialer) dialSingle(ctx context.Context, ra Addr) (c Conn, err error) {
	trace, _ := ctx.Value(nettrace.TraceKey{}).(*nettrace.Trace)
	if trace != nil {
		raStr := ra.String()
		if trace.ConnectStart != nil {
			trace.ConnectStart(sd.network, raStr)
		}
		if trace.ConnectDone != nil {
			defer func() { trace.ConnectDone(sd.network, raStr, err) }()
		}
	}
	la := sd.LocalAddr
	switch ra := ra.(type) {
	case *TCPAddr:
		la, _ := la.(*TCPAddr)
		c, err = sd.dialTCP(ctx, la, ra)
	case *UDPAddr:
		la, _ := la.(*UDPAddr)
		c, err = sd.dialUDP(ctx, la, ra)
	case *IPAddr:
		la, _ := la.(*IPAddr)
		c, err = sd.dialIP(ctx, la, ra)
	case *UnixAddr:
		la, _ := la.(*UnixAddr)
		c, err = sd.dialUnix(ctx, la, ra)
	default:
		return nil, &OpError{Op: "dial", Net: sd.network, Source: la, Addr: ra, Err: &AddrError{Err: "unexpected address type", Addr: sd.address}}
	}
	if err != nil {
		return nil, &OpError{Op: "dial", Net: sd.network, Source: la, Addr: ra, Err: err} // c is non-nil interface containing nil pointer
	}
	return c, nil
}

func (sd *sysDialer) dialTCP(ctx context.Context, laddr, raddr *TCPAddr) (*TCPConn, error) {
	if testHookDialTCP != nil {
		return testHookDialTCP(ctx, sd.network, laddr, raddr)
	}
	return sd.doDialTCP(ctx, laddr, raddr)
}

// net/tcpsock_posix.go
func (sd *sysDialer) doDialTCP(ctx context.Context, laddr, raddr *TCPAddr) (*TCPConn, error) {
	fd, err := internetSocket(ctx, sd.network, laddr, raddr, syscall.SOCK_STREAM, 0, "dial", sd.Dialer.Control)

	// TCP has a rarely used mechanism called a 'simultaneous connection' in
	// which Dial("tcp", addr1, addr2) run on the machine at addr1 can
	// connect to a simultaneous Dial("tcp", addr2, addr1) run on the machine
	// at addr2, without either machine executing Listen. If laddr == nil,
	// it means we want the kernel to pick an appropriate originating local
	// address. Some Linux kernels cycle blindly through a fixed range of
	// local ports, regardless of destination port. If a kernel happens to
	// pick local port 50001 as the source for a Dial("tcp", "", "localhost:50001"),
	// then the Dial will succeed, having simultaneously connected to itself.
	// This can only happen when we are letting the kernel pick a port (laddr == nil)
	// and when there is no listener for the destination address.
	// It's hard to argue this is anything other than a kernel bug. If we
	// see this happen, rather than expose the buggy effect to users, we
	// close the fd and try again. If it happens twice more, we relent and
	// use the result. See also:
	//	https://golang.org/issue/2690
	//	https://stackoverflow.com/questions/4949858/
	//
	// The opposite can also happen: if we ask the kernel to pick an appropriate
	// originating local address, sometimes it picks one that is already in use.
	// So if the error is EADDRNOTAVAIL, we have to try again too, just for
	// a different reason.
	//
	// The kernel socket code is no doubt enjoying watching us squirm.
	for i := 0; i < 2 && (laddr == nil || laddr.Port == 0) && (selfConnect(fd, err) || spuriousENOTAVAIL(err)); i++ {
		if err == nil {
			fd.Close()
		}
		fd, err = internetSocket(ctx, sd.network, laddr, raddr, syscall.SOCK_STREAM, 0, "dial", sd.Dialer.Control)
	}

	if err != nil {
		return nil, err
	}
	return newTCPConn(fd), nil
}

func internetSocket(ctx context.Context, net string, laddr, raddr sockaddr, sotype, proto int, mode string, ctrlFn func(string, string, syscall.RawConn) error) (fd *netFD, err error) {
	if (runtime.GOOS == "aix" || runtime.GOOS == "windows" || runtime.GOOS == "openbsd" || runtime.GOOS == "nacl") && mode == "dial" && raddr.isWildcard() {
		raddr = raddr.toLocal(net)
	}
	family, ipv6only := favoriteAddrFamily(net, laddr, raddr, mode)
	return socket(ctx, net, family, sotype, proto, ipv6only, laddr, raddr, ctrlFn)
}

// socket returns a network file descriptor that is ready for
// asynchronous I/O using the network poller.
func socket(ctx context.Context, net string, family, sotype, proto int, ipv6only bool, laddr, raddr sockaddr, ctrlFn func(string, string, syscall.RawConn) error) (fd *netFD, err error) {
	s, err := sysSocket(family, sotype, proto)
	if err != nil {
		return nil, err
	}
	if err = setDefaultSockopts(s, family, sotype, ipv6only); err != nil {
		poll.CloseFunc(s)
		return nil, err
	}
	if fd, err = newFD(s, family, sotype, net); err != nil {
		poll.CloseFunc(s)
		return nil, err
	}

	// This function makes a network file descriptor for the
	// following applications:
	//
	// - An endpoint holder that opens a passive stream
	//   connection, known as a stream listener
	//
	// - An endpoint holder that opens a destination-unspecific
	//   datagram connection, known as a datagram listener
	//
	// - An endpoint holder that opens an active stream or a
	//   destination-specific datagram connection, known as a
	//   dialer
	//
	// - An endpoint holder that opens the other connection, such
	//   as talking to the protocol stack inside the kernel
	//
	// For stream and datagram listeners, they will only require
	// named sockets, so we can assume that it's just a request
	// from stream or datagram listeners when laddr is not nil but
	// raddr is nil. Otherwise we assume it's just for dialers or
	// the other connection holders.

	if laddr != nil && raddr == nil {
		switch sotype {
		case syscall.SOCK_STREAM, syscall.SOCK_SEQPACKET:
			if err := fd.listenStream(laddr, listenerBacklog(), ctrlFn); err != nil {
				fd.Close()
				return nil, err
			}
			return fd, nil
		case syscall.SOCK_DGRAM:
			if err := fd.listenDatagram(laddr, ctrlFn); err != nil {
				fd.Close()
				return nil, err
			}
			return fd, nil
		}
	}
	if err := fd.dial(ctx, laddr, raddr, ctrlFn); err != nil {
		fd.Close()
		return nil, err
	}
	return fd, nil
}

func newFD(sysfd, family, sotype int, net string) (*netFD, error) {
	ret := &netFD{
		pfd: poll.FD{
			Sysfd:         sysfd,
			IsStream:      sotype == syscall.SOCK_STREAM,
			ZeroReadIsEOF: sotype != syscall.SOCK_DGRAM && sotype != syscall.SOCK_RAW,
		},
		family: family,
		sotype: sotype,
		net:    net,
	}
	return ret, nil
}

// Network file descriptor.
type netFD struct {
	pfd poll.FD

	// immutable until Close
	family      int
	sotype      int
	isConnected bool // handshake completed or use of association with peer
	net         string
	laddr       Addr
	raddr       Addr
}

func newTCPConn(fd *netFD) *TCPConn {
	c := &TCPConn{conn{fd}}
	setNoDelay(c.fd, true)
	return c
}

// TCPConn is an implementation of the Conn interface for TCP network
// connections.
type TCPConn struct {
	conn
}

type conn struct {
	fd *netFD
}
```

对resolveAddrList返回的地址依次尝试创建连接，返回第一个创建成功的连接，否则返回第一个错误

* 3、setKeepAlive

创建完连接后，检查该连接是否为TCP连接，如果是TCP连接，则设置KeepAlive时间，如下(net/sockopt_posix.go)：

```go
...
if tc, ok := c.(*TCPConn); ok && d.KeepAlive >= 0 {
    setKeepAlive(tc.fd, true)
    ka := d.KeepAlive
    if d.KeepAlive == 0 {
        ka = defaultTCPKeepAlive
    }
    setKeepAlivePeriod(tc.fd, ka)
    testHookSetKeepAlive(ka)
}

...
func setKeepAlive(fd *netFD, keepalive bool) error {
	err := fd.pfd.SetsockoptInt(syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, boolint(keepalive))
	runtime.KeepAlive(fd)
	return wrapSyscallError("setsockopt", err)
}

...
// net/tcpsockopt_darwin.go
func setKeepAlivePeriod(fd *netFD, d time.Duration) error {
	// The kernel expects seconds so round to next highest second.
	d += (time.Second - time.Nanosecond)
	secs := int(d.Seconds())
	if err := fd.pfd.SetsockoptInt(syscall.IPPROTO_TCP, sysTCP_KEEPINTVL, secs); err != nil {
		return wrapSyscallError("setsockopt", err)
	}
	err := fd.pfd.SetsockoptInt(syscall.IPPROTO_TCP, syscall.TCP_KEEPALIVE, secs)
	runtime.KeepAlive(fd)
	return wrapSyscallError("setsockopt", err)
}

// defaultTCPKeepAlive is a default constant value for TCPKeepAlive times
// See golang.org/issue/31510
const (
	defaultTCPKeepAlive = 15 * time.Second
)
```

Transport.IdleConnTimeout与net.Dialer.KeepAlive有什么关系，哪一个是所谓的HTTP keep-alives？？？

回到最开始的http.Client的使用：

```go
// construct encoded endpoint
Url, err := url.Parse(fmt.Sprintf("http://%s:%d", addr, port))
if err != nil {
    return err
}
Url.Path += "/index"
endpoint := Url.String()
req, err := http.NewRequest("GET", endpoint, nil)
if err != nil {
    return err
}
// use httpClient to send request
rsp, err := client.Do(req)
if err != nil {
    return err
}
// close the connection to reuse it
defer rsp.Body.Close()
// check status code
if rsp.StatusCode != http.StatusOK {
    return fmt.Errorf("get rsp error: %v", rsp)
}
```

我们分析http.Client是如何使用http.Transport的：

* 创建http.Request

根据method，url，body创建http.Request：

```go
// NewRequest wraps NewRequestWithContext using the background context.
func NewRequest(method, url string, body io.Reader) (*Request, error) {
	return NewRequestWithContext(context.Background(), method, url, body)
}

// NewRequestWithContext returns a new Request given a method, URL, and
// optional body.
//
// If the provided body is also an io.Closer, the returned
// Request.Body is set to body and will be closed by the Client
// methods Do, Post, and PostForm, and Transport.RoundTrip.
//
// NewRequestWithContext returns a Request suitable for use with
// Client.Do or Transport.RoundTrip. To create a request for use with
// testing a Server Handler, either use the NewRequest function in the
// net/http/httptest package, use ReadRequest, or manually update the
// Request fields. For an outgoing client request, the context
// controls the entire lifetime of a request and its response:
// obtaining a connection, sending the request, and reading the
// response headers and body. See the Request type's documentation for
// the difference between inbound and outbound request fields.
//
// If body is of type *bytes.Buffer, *bytes.Reader, or
// *strings.Reader, the returned request's ContentLength is set to its
// exact value (instead of -1), GetBody is populated (so 307 and 308
// redirects can replay the body), and Body is set to NoBody if the
// ContentLength is 0.
func NewRequestWithContext(ctx context.Context, method, url string, body io.Reader) (*Request, error) {
	if method == "" {
		// We document that "" means "GET" for Request.Method, and people have
		// relied on that from NewRequest, so keep that working.
		// We still enforce validMethod for non-empty methods.
		method = "GET"
	}
	if !validMethod(method) {
		return nil, fmt.Errorf("net/http: invalid method %q", method)
	}
	if ctx == nil {
		return nil, errors.New("net/http: nil Context")
	}
	u, err := parseURL(url) // Just url.Parse (url is shadowed for godoc).
	if err != nil {
		return nil, err
	}
	rc, ok := body.(io.ReadCloser)
	if !ok && body != nil {
		rc = ioutil.NopCloser(body)
	}
	// The host's colon:port should be normalized. See Issue 14836.
	u.Host = removeEmptyPort(u.Host)
	req := &Request{
		ctx:        ctx,
		Method:     method,
		URL:        u,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(Header),
		Body:       rc,
		Host:       u.Host,
	}
	if body != nil {
		switch v := body.(type) {
		case *bytes.Buffer:
			req.ContentLength = int64(v.Len())
			buf := v.Bytes()
			req.GetBody = func() (io.ReadCloser, error) {
				r := bytes.NewReader(buf)
				return ioutil.NopCloser(r), nil
			}
		case *bytes.Reader:
			req.ContentLength = int64(v.Len())
			snapshot := *v
			req.GetBody = func() (io.ReadCloser, error) {
				r := snapshot
				return ioutil.NopCloser(&r), nil
			}
		case *strings.Reader:
			req.ContentLength = int64(v.Len())
			snapshot := *v
			req.GetBody = func() (io.ReadCloser, error) {
				r := snapshot
				return ioutil.NopCloser(&r), nil
			}
		default:
			// This is where we'd set it to -1 (at least
			// if body != NoBody) to mean unknown, but
			// that broke people during the Go 1.8 testing
			// period. People depend on it being 0 I
			// guess. Maybe retry later. See Issue 18117.
		}
		// For client requests, Request.ContentLength of 0
		// means either actually 0, or unknown. The only way
		// to explicitly say that the ContentLength is zero is
		// to set the Body to nil. But turns out too much code
		// depends on NewRequest returning a non-nil Body,
		// so we use a well-known ReadCloser variable instead
		// and have the http package also treat that sentinel
		// variable to mean explicitly zero.
		if req.GetBody != nil && req.ContentLength == 0 {
			req.Body = NoBody
			req.GetBody = func() (io.ReadCloser, error) { return NoBody, nil }
		}
	}

	return req, nil
}

// A Request represents an HTTP request received by a server
// or to be sent by a client.
//
// The field semantics differ slightly between client and server
// usage. In addition to the notes on the fields below, see the
// documentation for Request.Write and RoundTripper.
type Request struct {
	// Method specifies the HTTP method (GET, POST, PUT, etc.).
	// For client requests, an empty string means GET.
	//
	// Go's HTTP client does not support sending a request with
	// the CONNECT method. See the documentation on Transport for
	// details.
	Method string

	// URL specifies either the URI being requested (for server
	// requests) or the URL to access (for client requests).
	//
	// For server requests, the URL is parsed from the URI
	// supplied on the Request-Line as stored in RequestURI.  For
	// most requests, fields other than Path and RawQuery will be
	// empty. (See RFC 7230, Section 5.3)
	//
	// For client requests, the URL's Host specifies the server to
	// connect to, while the Request's Host field optionally
	// specifies the Host header value to send in the HTTP
	// request.
	URL *url.URL

	// The protocol version for incoming server requests.
	//
	// For client requests, these fields are ignored. The HTTP
	// client code always uses either HTTP/1.1 or HTTP/2.
	// See the docs on Transport for details.
	Proto      string // "HTTP/1.0"
	ProtoMajor int    // 1
	ProtoMinor int    // 0

	// Header contains the request header fields either received
	// by the server or to be sent by the client.
	//
	// If a server received a request with header lines,
	//
	//	Host: example.com
	//	accept-encoding: gzip, deflate
	//	Accept-Language: en-us
	//	fOO: Bar
	//	foo: two
	//
	// then
	//
	//	Header = map[string][]string{
	//		"Accept-Encoding": {"gzip, deflate"},
	//		"Accept-Language": {"en-us"},
	//		"Foo": {"Bar", "two"},
	//	}
	//
	// For incoming requests, the Host header is promoted to the
	// Request.Host field and removed from the Header map.
	//
	// HTTP defines that header names are case-insensitive. The
	// request parser implements this by using CanonicalHeaderKey,
	// making the first character and any characters following a
	// hyphen uppercase and the rest lowercase.
	//
	// For client requests, certain headers such as Content-Length
	// and Connection are automatically written when needed and
	// values in Header may be ignored. See the documentation
	// for the Request.Write method.
	Header Header

	// Body is the request's body.
	//
	// For client requests, a nil body means the request has no
	// body, such as a GET request. The HTTP Client's Transport
	// is responsible for calling the Close method.
	//
	// For server requests, the Request Body is always non-nil
	// but will return EOF immediately when no body is present.
	// The Server will close the request body. The ServeHTTP
	// Handler does not need to.
	Body io.ReadCloser

	// GetBody defines an optional func to return a new copy of
	// Body. It is used for client requests when a redirect requires
	// reading the body more than once. Use of GetBody still
	// requires setting Body.
	//
	// For server requests, it is unused.
	GetBody func() (io.ReadCloser, error)

	// ContentLength records the length of the associated content.
	// The value -1 indicates that the length is unknown.
	// Values >= 0 indicate that the given number of bytes may
	// be read from Body.
	//
	// For client requests, a value of 0 with a non-nil Body is
	// also treated as unknown.
	ContentLength int64

	// TransferEncoding lists the transfer encodings from outermost to
	// innermost. An empty list denotes the "identity" encoding.
	// TransferEncoding can usually be ignored; chunked encoding is
	// automatically added and removed as necessary when sending and
	// receiving requests.
	TransferEncoding []string

	// Close indicates whether to close the connection after
	// replying to this request (for servers) or after sending this
	// request and reading its response (for clients).
	//
	// For server requests, the HTTP server handles this automatically
	// and this field is not needed by Handlers.
	//
	// For client requests, setting this field prevents re-use of
	// TCP connections between requests to the same hosts, as if
	// Transport.DisableKeepAlives were set.
	Close bool

	// For server requests, Host specifies the host on which the URL
	// is sought. Per RFC 7230, section 5.4, this is either the value
	// of the "Host" header or the host name given in the URL itself.
	// It may be of the form "host:port". For international domain
	// names, Host may be in Punycode or Unicode form. Use
	// golang.org/x/net/idna to convert it to either format if
	// needed.
	// To prevent DNS rebinding attacks, server Handlers should
	// validate that the Host header has a value for which the
	// Handler considers itself authoritative. The included
	// ServeMux supports patterns registered to particular host
	// names and thus protects its registered Handlers.
	//
	// For client requests, Host optionally overrides the Host
	// header to send. If empty, the Request.Write method uses
	// the value of URL.Host. Host may contain an international
	// domain name.
	Host string

	// Form contains the parsed form data, including both the URL
	// field's query parameters and the PATCH, POST, or PUT form data.
	// This field is only available after ParseForm is called.
	// The HTTP client ignores Form and uses Body instead.
	Form url.Values

	// PostForm contains the parsed form data from PATCH, POST
	// or PUT body parameters.
	//
	// This field is only available after ParseForm is called.
	// The HTTP client ignores PostForm and uses Body instead.
	PostForm url.Values

	// MultipartForm is the parsed multipart form, including file uploads.
	// This field is only available after ParseMultipartForm is called.
	// The HTTP client ignores MultipartForm and uses Body instead.
	MultipartForm *multipart.Form

	// Trailer specifies additional headers that are sent after the request
	// body.
	//
	// For server requests, the Trailer map initially contains only the
	// trailer keys, with nil values. (The client declares which trailers it
	// will later send.)  While the handler is reading from Body, it must
	// not reference Trailer. After reading from Body returns EOF, Trailer
	// can be read again and will contain non-nil values, if they were sent
	// by the client.
	//
	// For client requests, Trailer must be initialized to a map containing
	// the trailer keys to later send. The values may be nil or their final
	// values. The ContentLength must be 0 or -1, to send a chunked request.
	// After the HTTP request is sent the map values can be updated while
	// the request body is read. Once the body returns EOF, the caller must
	// not mutate Trailer.
	//
	// Few HTTP clients, servers, or proxies support HTTP trailers.
	Trailer Header

	// RemoteAddr allows HTTP servers and other software to record
	// the network address that sent the request, usually for
	// logging. This field is not filled in by ReadRequest and
	// has no defined format. The HTTP server in this package
	// sets RemoteAddr to an "IP:port" address before invoking a
	// handler.
	// This field is ignored by the HTTP client.
	RemoteAddr string

	// RequestURI is the unmodified request-target of the
	// Request-Line (RFC 7230, Section 3.1.1) as sent by the client
	// to a server. Usually the URL field should be used instead.
	// It is an error to set this field in an HTTP client request.
	RequestURI string

	// TLS allows HTTP servers and other software to record
	// information about the TLS connection on which the request
	// was received. This field is not filled in by ReadRequest.
	// The HTTP server in this package sets the field for
	// TLS-enabled connections before invoking a handler;
	// otherwise it leaves the field nil.
	// This field is ignored by the HTTP client.
	TLS *tls.ConnectionState

	// Cancel is an optional channel whose closure indicates that the client
	// request should be regarded as canceled. Not all implementations of
	// RoundTripper may support Cancel.
	//
	// For server requests, this field is not applicable.
	//
	// Deprecated: Set the Request's context with NewRequestWithContext
	// instead. If a Request's Cancel field and context are both
	// set, it is undefined whether Cancel is respected.
	Cancel <-chan struct{}

	// Response is the redirect response which caused this request
	// to be created. This field is only populated during client
	// redirects.
	Response *Response

	// ctx is either the client or server context. It should only
	// be modified via copying the whole Request using WithContext.
	// It is unexported to prevent people from using Context wrong
	// and mutating the contexts held by callers of the same request.
	ctx context.Context
}
```

* client.Do(req)

使用http.Client发送请求，如下：

```go
// Do sends an HTTP request and returns an HTTP response, following
// policy (such as redirects, cookies, auth) as configured on the
// client.
//
// An error is returned if caused by client policy (such as
// CheckRedirect), or failure to speak HTTP (such as a network
// connectivity problem). A non-2xx status code doesn't cause an
// error.
//
// If the returned error is nil, the Response will contain a non-nil
// Body which the user is expected to close. If the Body is not both
// read to EOF and closed, the Client's underlying RoundTripper
// (typically Transport) may not be able to re-use a persistent TCP
// connection to the server for a subsequent "keep-alive" request.
//
// The request Body, if non-nil, will be closed by the underlying
// Transport, even on errors.
//
// On error, any Response can be ignored. A non-nil Response with a
// non-nil error only occurs when CheckRedirect fails, and even then
// the returned Response.Body is already closed.
//
// Generally Get, Post, or PostForm will be used instead of Do.
//
// If the server replies with a redirect, the Client first uses the
// CheckRedirect function to determine whether the redirect should be
// followed. If permitted, a 301, 302, or 303 redirect causes
// subsequent requests to use HTTP method GET
// (or HEAD if the original request was HEAD), with no body.
// A 307 or 308 redirect preserves the original HTTP method and body,
// provided that the Request.GetBody function is defined.
// The NewRequest function automatically sets GetBody for common
// standard library body types.
//
// Any returned error will be of type *url.Error. The url.Error
// value's Timeout method will report true if request timed out or was
// canceled.
func (c *Client) Do(req *Request) (*Response, error) {
	return c.do(req)
}

func (c *Client) do(req *Request) (retres *Response, reterr error) {
	if testHookClientDoResult != nil {
		defer func() { testHookClientDoResult(retres, reterr) }()
	}
	if req.URL == nil {
		req.closeBody()
		return nil, &url.Error{
			Op:  urlErrorOp(req.Method),
			Err: errors.New("http: nil Request.URL"),
		}
	}

	var (
		deadline      = c.deadline()
		reqs          []*Request
		resp          *Response
		copyHeaders   = c.makeHeadersCopier(req)
		reqBodyClosed = false // have we closed the current req.Body?

		// Redirect behavior:
		redirectMethod string
		includeBody    bool
	)
	uerr := func(err error) error {
		// the body may have been closed already by c.send()
		if !reqBodyClosed {
			req.closeBody()
		}
		var urlStr string
		if resp != nil && resp.Request != nil {
			urlStr = stripPassword(resp.Request.URL)
		} else {
			urlStr = stripPassword(req.URL)
		}
		return &url.Error{
			Op:  urlErrorOp(reqs[0].Method),
			URL: urlStr,
			Err: err,
		}
	}
	for {
		// For all but the first request, create the next
		// request hop and replace req.
		if len(reqs) > 0 {
			loc := resp.Header.Get("Location")
			if loc == "" {
				resp.closeBody()
				return nil, uerr(fmt.Errorf("%d response missing Location header", resp.StatusCode))
			}
			u, err := req.URL.Parse(loc)
			if err != nil {
				resp.closeBody()
				return nil, uerr(fmt.Errorf("failed to parse Location header %q: %v", loc, err))
			}
			host := ""
			if req.Host != "" && req.Host != req.URL.Host {
				// If the caller specified a custom Host header and the
				// redirect location is relative, preserve the Host header
				// through the redirect. See issue #22233.
				if u, _ := url.Parse(loc); u != nil && !u.IsAbs() {
					host = req.Host
				}
			}
			ireq := reqs[0]
			req = &Request{
				Method:   redirectMethod,
				Response: resp,
				URL:      u,
				Header:   make(Header),
				Host:     host,
				Cancel:   ireq.Cancel,
				ctx:      ireq.ctx,
			}
			if includeBody && ireq.GetBody != nil {
				req.Body, err = ireq.GetBody()
				if err != nil {
					resp.closeBody()
					return nil, uerr(err)
				}
				req.ContentLength = ireq.ContentLength
			}

			// Copy original headers before setting the Referer,
			// in case the user set Referer on their first request.
			// If they really want to override, they can do it in
			// their CheckRedirect func.
			copyHeaders(req)

			// Add the Referer header from the most recent
			// request URL to the new one, if it's not https->http:
			if ref := refererForURL(reqs[len(reqs)-1].URL, req.URL); ref != "" {
				req.Header.Set("Referer", ref)
			}
			err = c.checkRedirect(req, reqs)

			// Sentinel error to let users select the
			// previous response, without closing its
			// body. See Issue 10069.
			if err == ErrUseLastResponse {
				return resp, nil
			}

			// Close the previous response's body. But
			// read at least some of the body so if it's
			// small the underlying TCP connection will be
			// re-used. No need to check for errors: if it
			// fails, the Transport won't reuse it anyway.
			const maxBodySlurpSize = 2 << 10
			if resp.ContentLength == -1 || resp.ContentLength <= maxBodySlurpSize {
				io.CopyN(ioutil.Discard, resp.Body, maxBodySlurpSize)
			}
			resp.Body.Close()

			if err != nil {
				// Special case for Go 1 compatibility: return both the response
				// and an error if the CheckRedirect function failed.
				// See https://golang.org/issue/3795
				// The resp.Body has already been closed.
				ue := uerr(err)
				ue.(*url.Error).URL = loc
				return resp, ue
			}
		}

		reqs = append(reqs, req)
		var err error
		var didTimeout func() bool
		if resp, didTimeout, err = c.send(req, deadline); err != nil {
			// c.send() always closes req.Body
			reqBodyClosed = true
			if !deadline.IsZero() && didTimeout() {
				err = &httpError{
					// TODO: early in cycle: s/Client.Timeout exceeded/timeout or context cancellation/
					err:     err.Error() + " (Client.Timeout exceeded while awaiting headers)",
					timeout: true,
				}
			}
			return nil, uerr(err)
		}

		var shouldRedirect bool
		redirectMethod, shouldRedirect, includeBody = redirectBehavior(req.Method, resp, reqs[0])
		if !shouldRedirect {
			return resp, nil
		}

		req.closeBody()
	}
}
```

整个http.Client.Do逻辑分为两道，第一道执行send发送请求接收Response，关闭Req.Body；第二层对请求执行重定向等操作(若需要redirect)，并关闭Resp.Body

其中，send执行请求的发送和接收动作，展开如下：

```go
// didTimeout is non-nil only if err != nil.
func (c *Client) send(req *Request, deadline time.Time) (resp *Response, didTimeout func() bool, err error) {
	if c.Jar != nil {
		for _, cookie := range c.Jar.Cookies(req.URL) {
			req.AddCookie(cookie)
		}
	}
	resp, didTimeout, err = send(req, c.transport(), deadline)
	if err != nil {
		return nil, didTimeout, err
	}
	if c.Jar != nil {
		if rc := resp.Cookies(); len(rc) > 0 {
			c.Jar.SetCookies(req.URL, rc)
		}
	}
	return resp, nil, nil
}

// send issues an HTTP request.
// Caller should close resp.Body when done reading from it.
func send(ireq *Request, rt RoundTripper, deadline time.Time) (resp *Response, didTimeout func() bool, err error) {
	req := ireq // req is either the original request, or a modified fork

	if rt == nil {
		req.closeBody()
		return nil, alwaysFalse, errors.New("http: no Client.Transport or DefaultTransport")
	}

	if req.URL == nil {
		req.closeBody()
		return nil, alwaysFalse, errors.New("http: nil Request.URL")
	}

	if req.RequestURI != "" {
		req.closeBody()
		return nil, alwaysFalse, errors.New("http: Request.RequestURI can't be set in client requests.")
	}

	// forkReq forks req into a shallow clone of ireq the first
	// time it's called.
	forkReq := func() {
		if ireq == req {
			req = new(Request)
			*req = *ireq // shallow clone
		}
	}

	// Most the callers of send (Get, Post, et al) don't need
	// Headers, leaving it uninitialized. We guarantee to the
	// Transport that this has been initialized, though.
	if req.Header == nil {
		forkReq()
		req.Header = make(Header)
	}

	if u := req.URL.User; u != nil && req.Header.Get("Authorization") == "" {
		username := u.Username()
		password, _ := u.Password()
		forkReq()
		req.Header = cloneOrMakeHeader(ireq.Header)
		req.Header.Set("Authorization", "Basic "+basicAuth(username, password))
	}

	if !deadline.IsZero() {
		forkReq()
	}
	stopTimer, didTimeout := setRequestCancel(req, rt, deadline)

	resp, err = rt.RoundTrip(req)
	if err != nil {
		stopTimer()
		if resp != nil {
			log.Printf("RoundTripper returned a response & error; ignoring response")
		}
		if tlsErr, ok := err.(tls.RecordHeaderError); ok {
			// If we get a bad TLS record header, check to see if the
			// response looks like HTTP and give a more helpful error.
			// See golang.org/issue/11111.
			if string(tlsErr.RecordHeader[:]) == "HTTP/" {
				err = errors.New("http: server gave HTTP response to HTTPS client")
			}
		}
		return nil, didTimeout, err
	}
	if !deadline.IsZero() {
		resp.Body = &cancelTimerBody{
			stop:          stopTimer,
			rc:            resp.Body,
			reqDidTimeout: didTimeout,
		}
	}
	return resp, nil, nil
}

func (c *Client) transport() RoundTripper {
	if c.Transport != nil {
		return c.Transport
	}
	return DefaultTransport
}
```

入参为http.Request，http.Transport以及deadline(http.Client.Timeout)。函数处理逻辑具体分为两个步骤，如下：

1. setRequestCancel

设置请求超时时间为http.Client.Timeout：

```go
// setRequestCancel sets the Cancel field of req, if deadline is
// non-zero. The RoundTripper's type is used to determine whether the legacy
// CancelRequest behavior should be used.
//
// As background, there are three ways to cancel a request:
// First was Transport.CancelRequest. (deprecated)
// Second was Request.Cancel (this mechanism).
// Third was Request.Context.
func setRequestCancel(req *Request, rt RoundTripper, deadline time.Time) (stopTimer func(), didTimeout func() bool) {
	if deadline.IsZero() {
		return nop, alwaysFalse
	}

	initialReqCancel := req.Cancel // the user's original Request.Cancel, if any

	cancel := make(chan struct{})
	req.Cancel = cancel

	doCancel := func() {
		// The newer way (the second way in the func comment):
		close(cancel)

		// The legacy compatibility way, used only
		// for RoundTripper implementations written
		// before Go 1.5 or Go 1.6.
		type canceler interface {
			CancelRequest(*Request)
		}
		switch v := rt.(type) {
		case *Transport, *http2Transport:
			// Do nothing. The net/http package's transports
			// support the new Request.Cancel channel
		case canceler:
			v.CancelRequest(req)
		}
	}

	stopTimerCh := make(chan struct{})
	var once sync.Once
	stopTimer = func() { once.Do(func() { close(stopTimerCh) }) }

	timer := time.NewTimer(time.Until(deadline))
	var timedOut atomicBool

	go func() {
		select {
		case <-initialReqCancel:
			doCancel()
			timer.Stop()
		case <-timer.C:
			timedOut.setTrue()
			doCancel()
		case <-stopTimerCh:
			timer.Stop()
		}
	}()

	return stopTimer, timedOut.isSet
}

// A Request represents an HTTP request received by a server
// or to be sent by a client.
//
// The field semantics differ slightly between client and server
// usage. In addition to the notes on the fields below, see the
// documentation for Request.Write and RoundTripper.
type Request struct {
    ...
	// Cancel is an optional channel whose closure indicates that the client
	// request should be regarded as canceled. Not all implementations of
	// RoundTripper may support Cancel.
	//
	// For server requests, this field is not applicable.
	//
	// Deprecated: Set the Request's context with NewRequestWithContext
	// instead. If a Request's Cancel field and context are both
	// set, it is undefined whether Cancel is respected.
	Cancel <-chan struct{}

	// Response is the redirect response which caused this request
	// to be created. This field is only populated during client
	// redirects.
	Response *Response

	// ctx is either the client or server context. It should only
	// be modified via copying the whole Request using WithContext.
	// It is unexported to prevent people from using Context wrong
	// and mutating the contexts held by callers of the same request.
	ctx context.Context
}
```

有三种方式取消一个请求，如下：

* First was Transport.CancelRequest. (deprecated)
* Second was Request.Cancel (this mechanism).
* Third was Request.Context.

setRequestCancel执行了前面两种方式

2. resp, err = rt.RoundTrip(req)

在设置了超时timer后，执行具体的请求操作

回到http.Transport(net/http/transport.go)，Transport实现了RoundTripper接口，如下：

```go
client := &http.Client{
    Transport: &http.Transport{
        Proxy: http.ProxyFromEnvironment,
        DialContext: (&net.Dialer{
            Timeout:   30 * time.Second,
            KeepAlive: 30 * time.Second,
            DualStack: true,
        }).DialContext,
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 100,
        IdleConnTimeout:     90 * time.Second,
    },
}
...

// RoundTrip implements the RoundTripper interface.
//
// For higher-level HTTP client support (such as handling of cookies
// and redirects), see Get, Post, and the Client type.
//
// Like the RoundTripper interface, the error types returned
// by RoundTrip are unspecified.
func (t *Transport) RoundTrip(req *Request) (*Response, error) {
	return t.roundTrip(req)
}

// roundTrip implements a RoundTripper over HTTP.
func (t *Transport) roundTrip(req *Request) (*Response, error) {
	t.nextProtoOnce.Do(t.onceSetNextProtoDefaults)
	ctx := req.Context()
	trace := httptrace.ContextClientTrace(ctx)

	if req.URL == nil {
		req.closeBody()
		return nil, errors.New("http: nil Request.URL")
	}
	if req.Header == nil {
		req.closeBody()
		return nil, errors.New("http: nil Request.Header")
	}
	scheme := req.URL.Scheme
	isHTTP := scheme == "http" || scheme == "https"
	if isHTTP {
		for k, vv := range req.Header {
			if !httpguts.ValidHeaderFieldName(k) {
				return nil, fmt.Errorf("net/http: invalid header field name %q", k)
			}
			for _, v := range vv {
				if !httpguts.ValidHeaderFieldValue(v) {
					return nil, fmt.Errorf("net/http: invalid header field value %q for key %v", v, k)
				}
			}
		}
	}

	if t.useRegisteredProtocol(req) {
		altProto, _ := t.altProto.Load().(map[string]RoundTripper)
		if altRT := altProto[scheme]; altRT != nil {
			if resp, err := altRT.RoundTrip(req); err != ErrSkipAltProtocol {
				return resp, err
			}
		}
	}
	if !isHTTP {
		req.closeBody()
		return nil, &badStringError{"unsupported protocol scheme", scheme}
	}
	if req.Method != "" && !validMethod(req.Method) {
		return nil, fmt.Errorf("net/http: invalid method %q", req.Method)
	}
	if req.URL.Host == "" {
		req.closeBody()
		return nil, errors.New("http: no Host in request URL")
	}

	for {
		select {
		case <-ctx.Done():
			req.closeBody()
			return nil, ctx.Err()
		default:
		}

		// treq gets modified by roundTrip, so we need to recreate for each retry.
		treq := &transportRequest{Request: req, trace: trace}
		cm, err := t.connectMethodForRequest(treq)
		if err != nil {
			req.closeBody()
			return nil, err
		}

		// Get the cached or newly-created connection to either the
		// host (for http or https), the http proxy, or the http proxy
		// pre-CONNECTed to https server. In any case, we'll be ready
		// to send it requests.
		pconn, err := t.getConn(treq, cm)
		if err != nil {
			t.setReqCanceler(req, nil)
			req.closeBody()
			return nil, err
		}

		var resp *Response
		if pconn.alt != nil {
			// HTTP/2 path.
			t.setReqCanceler(req, nil) // not cancelable with CancelRequest
			resp, err = pconn.alt.RoundTrip(req)
		} else {
			resp, err = pconn.roundTrip(treq)
		}
		if err == nil {
			return resp, nil
		}

		// Failed. Clean up and determine whether to retry.

		_, isH2DialError := pconn.alt.(http2erringRoundTripper)
		if http2isNoCachedConnError(err) || isH2DialError {
			t.removeIdleConn(pconn)
			t.decConnsPerHost(pconn.cacheKey)
		}
		if !pconn.shouldRetryRequest(req, err) {
			// Issue 16465: return underlying net.Conn.Read error from peek,
			// as we've historically done.
			if e, ok := err.(transportReadFromServerError); ok {
				err = e.err
			}
			return nil, err
		}
		testHookRoundTripRetried()

		// Rewind the body if we're able to.
		if req.GetBody != nil {
			newReq := *req
			var err error
			newReq.Body, err = req.GetBody()
			if err != nil {
				return nil, err
			}
			req = &newReq
		}
	}
}
```















