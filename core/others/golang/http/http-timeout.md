http transport timeout
======================

本章分析http transport中的几个timeout设置，这也是我们使用net/http库一般会关注和遇到的问题

golang demo例子如下：

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

这其中涉及的几个timeout设置如下：

* http.Client.Timeout
* http.Client.IdleConnTimeout
* net.Dialer.Timeout
* net.Dialer.KeepAlive

下面我们依次从源码角度对这些Timeout配置作用进行分析

## http.Client.Timeout

```
http.Client.Do(req) => send(ireq *Request, rt RoundTripper, deadline time.Time)
  -> setRequestCancel(req, rt, deadline) 设置请求超时时间
  -> http.Client.RoundTrip(req)
```

从如上调用链出发，重点看setRequestCancel函数：
  
```go
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

func (c *Client) deadline() time.Time {
	if c.Timeout > 0 {
		return time.Now().Add(c.Timeout)
	}
	return time.Time{}
}

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
```

这里setRequestCancel函数在http.Client.Timeout时间超时之后会调用doCancel函数：

```go
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
```

而doCancel会关闭req.Cancel管道，如下：

```go
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
```

下面看如何在超时时取消请求：

```go
// send issues an HTTP request.
// Caller should close resp.Body when done reading from it.
func send(ireq *Request, rt RoundTripper, deadline time.Time) (resp *Response, didTimeout func() bool, err error) {
    ...
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

func (pc *persistConn) roundTrip(req *transportRequest) (resp *Response, err error) {
    ...
	if !pc.t.replaceReqCanceler(req.Request, pc.cancelRequest) {
		pc.t.putOrCloseIdleConn(pc)
		return nil, errRequestCanceled
	}
	defer func() {
		if err != nil {
			pc.t.setReqCanceler(req.Request, nil)
		}
	}()

	const debugRoundTrip = false

	// Write the request concurrently with waiting for a response,
	// in case the server decides to reply before reading our full
	// request body.
	startBytesWritten := pc.nwrite
	writeErrCh := make(chan error, 1)
	pc.writech <- writeRequest{req, writeErrCh, continueCh}

	resc := make(chan responseAndError)
	pc.reqch <- requestAndChan{
		req:        req.Request,
		ch:         resc,
		addedGzip:  requestedGzip,
		continueCh: continueCh,
		callerGone: gone,
	}

	var respHeaderTimer <-chan time.Time
	cancelChan := req.Request.Cancel
	ctxDoneChan := req.Context().Done()
	for {
		testHookWaitResLoop()
		select {
        ...
		case <-pc.closech:
			if debugRoundTrip {
				req.logf("closech recv: %T %#v", pc.closed, pc.closed)
			}
			return nil, pc.mapRoundTripError(req, startBytesWritten, pc.closed)
		case <-respHeaderTimer:
			if debugRoundTrip {
				req.logf("timeout waiting for response headers.")
			}
			pc.close(errTimeout)
			return nil, errTimeout
		case re := <-resc:
			if (re.res == nil) == (re.err == nil) {
				panic(fmt.Sprintf("internal error: exactly one of res or err should be set; nil=%v", re.res == nil))
			}
			if debugRoundTrip {
				req.logf("resc recv: %p, %T/%#v", re.res, re.err, re.err)
			}
			if re.err != nil {
				return nil, pc.mapRoundTripError(req, startBytesWritten, re.err)
			}
			return re.res, nil
		case <-cancelChan:
			pc.t.CancelRequest(req.Request)
			cancelChan = nil
		case <-ctxDoneChan:
			pc.t.cancelRequest(req.Request, req.Context().Err())
			cancelChan = nil
			ctxDoneChan = nil
		}
	}
}
```

看到这里`cancelChan := req.Request.Cancel`，当接收到close(req.Cancel)时，会执行：pc.t.CancelRequest(req.Request)，如下：

```go
type Transport struct {
	idleMu       sync.Mutex
	closeIdle    bool                                // user has requested to close all idle conns
	idleConn     map[connectMethodKey][]*persistConn // most recently used at end
	idleConnWait map[connectMethodKey]wantConnQueue  // waiting getConns
	idleLRU      connLRU

	reqMu       sync.Mutex
	reqCanceler map[*Request]func(error)
    ...
}

// replaceReqCanceler replaces an existing cancel function. If there is no cancel function
// for the request, we don't set the function and return false.
// Since CancelRequest will clear the canceler, we can use the return value to detect if
// the request was canceled since the last setReqCancel call.
func (t *Transport) replaceReqCanceler(r *Request, fn func(error)) bool {
	t.reqMu.Lock()
	defer t.reqMu.Unlock()
	_, ok := t.reqCanceler[r]
	if !ok {
		return false
	}
	if fn != nil {
		t.reqCanceler[r] = fn
	} else {
		delete(t.reqCanceler, r)
	}
	return true
}

// CancelRequest cancels an in-flight request by closing its connection.
// CancelRequest should only be called after RoundTrip has returned.
//
// Deprecated: Use Request.WithContext to create a request with a
// cancelable context instead. CancelRequest cannot cancel HTTP/2
// requests.
func (t *Transport) CancelRequest(req *Request) {
	t.cancelRequest(req, errRequestCanceled)
}

// Cancel an in-flight request, recording the error value.
func (t *Transport) cancelRequest(req *Request, err error) {
	t.reqMu.Lock()
	cancel := t.reqCanceler[req]
	delete(t.reqCanceler, req)
	t.reqMu.Unlock()
	if cancel != nil {
		cancel(err)
	}
}

func (pc *persistConn) cancelRequest(err error) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.canceledErr = err
	pc.closeLocked(errRequestCanceled)
}

func (pc *persistConn) closeLocked(err error) {
	if err == nil {
		panic("nil error")
	}
	pc.broken = true
	if pc.closed == nil {
		pc.closed = err
		pc.t.decConnsPerHost(pc.cacheKey)
		// Close HTTP/1 (pc.alt == nil) connection.
		// HTTP/2 closes its connection itself.
		if pc.alt == nil {
			if err != errCallerOwnsConn {
				pc.conn.Close()
			}
			close(pc.closech)
		}
	}
	pc.mutateHeaderFunc = nil
}

// decConnsPerHost decrements the per-host connection count for key,
// which may in turn give a different waiting goroutine permission to dial.
func (t *Transport) decConnsPerHost(key connectMethodKey) {
	if t.MaxConnsPerHost <= 0 {
		return
	}

	t.connsPerHostMu.Lock()
	defer t.connsPerHostMu.Unlock()
	n := t.connsPerHost[key]
	if n == 0 {
		// Shouldn't happen, but if it does, the counting is buggy and could
		// easily lead to a silent deadlock, so report the problem loudly.
		panic("net/http: internal error: connCount underflow")
	}

	// Can we hand this count to a goroutine still waiting to dial?
	// (Some goroutines on the wait list may have timed out or
	// gotten a connection another way. If they're all gone,
	// we don't want to kick off any spurious dial operations.)
	if q := t.connsPerHostWait[key]; q.len() > 0 {
		done := false
		for q.len() > 0 {
			w := q.popFront()
			if w.waiting() {
				go t.dialConnFor(w)
				done = true
				break
			}
		}
		if q.len() == 0 {
			delete(t.connsPerHostWait, key)
		} else {
			// q is a value (like a slice), so we have to store
			// the updated q back into the map.
			t.connsPerHostWait[key] = q
		}
		if done {
			return
		}
	}

	// Otherwise, decrement the recorded count.
	if n--; n == 0 {
		delete(t.connsPerHost, key)
	} else {
		t.connsPerHost[key] = n
	}
}
```

replaceReqCanceler将http.Request对应的reqCanceler函数设置为：http.persistConn.reqCanceler。它会关闭底层连接，同时将http.persistConn从http.Transport.connsPerHostWait以及http.Transport.connsPerHost中剔除

最后执行close(pc.closech)：

```go
func (pc *persistConn) roundTrip(req *transportRequest) (resp *Response, err error) {
	testHookEnterRoundTrip()
	if !pc.t.replaceReqCanceler(req.Request, pc.cancelRequest) {
		pc.t.putOrCloseIdleConn(pc)
		return nil, errRequestCanceled
	}
	pc.mu.Lock()
	pc.numExpectedResponses++
	headerFn := pc.mutateHeaderFunc
	pc.mu.Unlock()

	if headerFn != nil {
		headerFn(req.extraHeaders())
	}

	// Ask for a compressed version if the caller didn't set their
	// own value for Accept-Encoding. We only attempt to
	// uncompress the gzip stream if we were the layer that
	// requested it.
	requestedGzip := false
	if !pc.t.DisableCompression &&
		req.Header.Get("Accept-Encoding") == "" &&
		req.Header.Get("Range") == "" &&
		req.Method != "HEAD" {
		// Request gzip only, not deflate. Deflate is ambiguous and
		// not as universally supported anyway.
		// See: https://zlib.net/zlib_faq.html#faq39
		//
		// Note that we don't request this for HEAD requests,
		// due to a bug in nginx:
		//   https://trac.nginx.org/nginx/ticket/358
		//   https://golang.org/issue/5522
		//
		// We don't request gzip if the request is for a range, since
		// auto-decoding a portion of a gzipped document will just fail
		// anyway. See https://golang.org/issue/8923
		requestedGzip = true
		req.extraHeaders().Set("Accept-Encoding", "gzip")
	}

	var continueCh chan struct{}
	if req.ProtoAtLeast(1, 1) && req.Body != nil && req.expectsContinue() {
		continueCh = make(chan struct{}, 1)
	}

	if pc.t.DisableKeepAlives && !req.wantsClose() {
		req.extraHeaders().Set("Connection", "close")
	}

	gone := make(chan struct{})
	defer close(gone)

	defer func() {
		if err != nil {
			pc.t.setReqCanceler(req.Request, nil)
		}
	}()

	const debugRoundTrip = false

	// Write the request concurrently with waiting for a response,
	// in case the server decides to reply before reading our full
	// request body.
	startBytesWritten := pc.nwrite
	writeErrCh := make(chan error, 1)
	pc.writech <- writeRequest{req, writeErrCh, continueCh}

	resc := make(chan responseAndError)
	pc.reqch <- requestAndChan{
		req:        req.Request,
		ch:         resc,
		addedGzip:  requestedGzip,
		continueCh: continueCh,
		callerGone: gone,
	}

	var respHeaderTimer <-chan time.Time
	cancelChan := req.Request.Cancel
	ctxDoneChan := req.Context().Done()
	for {
		testHookWaitResLoop()
		select {
		case err := <-writeErrCh:
			if debugRoundTrip {
				req.logf("writeErrCh resv: %T/%#v", err, err)
			}
			if err != nil {
				pc.close(fmt.Errorf("write error: %v", err))
				return nil, pc.mapRoundTripError(req, startBytesWritten, err)
			}
			if d := pc.t.ResponseHeaderTimeout; d > 0 {
				if debugRoundTrip {
					req.logf("starting timer for %v", d)
				}
				timer := time.NewTimer(d)
				defer timer.Stop() // prevent leaks
				respHeaderTimer = timer.C
			}
		case <-pc.closech:
			if debugRoundTrip {
				req.logf("closech recv: %T %#v", pc.closed, pc.closed)
			}
			return nil, pc.mapRoundTripError(req, startBytesWritten, pc.closed)
		case <-respHeaderTimer:
			if debugRoundTrip {
				req.logf("timeout waiting for response headers.")
			}
			pc.close(errTimeout)
			return nil, errTimeout
		case re := <-resc:
			if (re.res == nil) == (re.err == nil) {
				panic(fmt.Sprintf("internal error: exactly one of res or err should be set; nil=%v", re.res == nil))
			}
			if debugRoundTrip {
				req.logf("resc recv: %p, %T/%#v", re.res, re.err, re.err)
			}
			if re.err != nil {
				return nil, pc.mapRoundTripError(req, startBytesWritten, re.err)
			}
			return re.res, nil
		case <-cancelChan:
			pc.t.CancelRequest(req.Request)
			cancelChan = nil
		case <-ctxDoneChan:
			pc.t.cancelRequest(req.Request, req.Context().Err())
			cancelChan = nil
			ctxDoneChan = nil
		}
	}
}

// mapRoundTripError returns the appropriate error value for
// persistConn.roundTrip.
//
// The provided err is the first error that (*persistConn).roundTrip
// happened to receive from its select statement.
//
// The startBytesWritten value should be the value of pc.nwrite before the roundTrip
// started writing the request.
func (pc *persistConn) mapRoundTripError(req *transportRequest, startBytesWritten int64, err error) error {
	if err == nil {
		return nil
	}

	// If the request was canceled, that's better than network
	// failures that were likely the result of tearing down the
	// connection.
	if cerr := pc.canceled(); cerr != nil {
		return cerr
	}

	// See if an error was set explicitly.
	req.mu.Lock()
	reqErr := req.err
	req.mu.Unlock()
	if reqErr != nil {
		return reqErr
	}

	if err == errServerClosedIdle {
		// Don't decorate
		return err
	}

	if _, ok := err.(transportReadFromServerError); ok {
		// Don't decorate
		return err
	}
	if pc.isBroken() {
		<-pc.writeLoopDone
		if pc.nwrite == startBytesWritten {
			return nothingWrittenError{err}
		}
		return fmt.Errorf("net/http: HTTP/1.x transport connection broken: %v", err)
	}
	return err
}
```

在persistConn.roundTrip中，如果接收到pc.closech信号，则直接返回错误：`return nil, pc.mapRoundTripError(req, startBytesWritten, pc.closed)`

**至此可以总结如下：http.Client.Timeout涵盖了HTTP请求从连接建立，请求发送，接收回应，重定向，以及读取http.Response.Body的整个生命周期的超时时间**

```
// Timeout specifies a time limit for requests made by this
// Client. The timeout includes connection time, any
// redirects, and reading the response body. The timer remains
// running after Get, Head, Post, or Do return and will
// interrupt reading of the Response.Body.
```

## http.Client.IdleConnTimeout

```go
func (pc *persistConn) readLoop() {
	closeErr := errReadLoopExiting // default value, if not changed below
	defer func() {
		pc.close(closeErr)
		pc.t.removeIdleConn(pc)
	}()

	tryPutIdleConn := func(trace *httptrace.ClientTrace) bool {
		if err := pc.t.tryPutIdleConn(pc); err != nil {
			closeErr = err
			if trace != nil && trace.PutIdleConn != nil && err != errKeepAlivesDisabled {
				trace.PutIdleConn(err)
			}
			return false
		}
		if trace != nil && trace.PutIdleConn != nil {
			trace.PutIdleConn(nil)
		}
		return true
	}
    
    ...

	alive := true
	for alive {
		pc.readLimit = pc.maxHeaderResponseSize()
		_, err := pc.br.Peek(1)

		pc.mu.Lock()
		if pc.numExpectedResponses == 0 {
			pc.readLoopPeekFailLocked(err)
			pc.mu.Unlock()
			return
		}
		pc.mu.Unlock()

		rc := <-pc.reqch
		trace := httptrace.ContextClientTrace(rc.req.Context())

		var resp *Response
		if err == nil {
			resp, err = pc.readResponse(rc, trace)
		} else {
			err = transportReadFromServerError{err}
			closeErr = err
		}

		if err != nil {
			if pc.readLimit <= 0 {
				err = fmt.Errorf("net/http: server response headers exceeded %d bytes; aborted", pc.maxHeaderResponseSize())
			}

			select {
			case rc.ch <- responseAndError{err: err}:
			case <-rc.callerGone:
				return
			}
			return
		}
		pc.readLimit = maxInt64 // effictively no limit for response bodies

		pc.mu.Lock()
		pc.numExpectedResponses--
		pc.mu.Unlock()

		bodyWritable := resp.bodyIsWritable()
		hasBody := rc.req.Method != "HEAD" && resp.ContentLength != 0

		if resp.Close || rc.req.Close || resp.StatusCode <= 199 || bodyWritable {
			// Don't do keep-alive on error if either party requested a close
			// or we get an unexpected informational (1xx) response.
			// StatusCode 100 is already handled above.
			alive = false
		}

		if !hasBody || bodyWritable {
			pc.t.setReqCanceler(rc.req, nil)

			// Put the idle conn back into the pool before we send the response
			// so if they process it quickly and make another request, they'll
			// get this same conn. But we use the unbuffered channel 'rc'
			// to guarantee that persistConn.roundTrip got out of its select
			// potentially waiting for this persistConn to close.
			// but after
			alive = alive &&
				!pc.sawEOF &&
				pc.wroteRequest() &&
				tryPutIdleConn(trace)

			if bodyWritable {
				closeErr = errCallerOwnsConn
			}

			select {
			case rc.ch <- responseAndError{res: resp}:
			case <-rc.callerGone:
				return
			}

			// Now that they've read from the unbuffered channel, they're safely
			// out of the select that also waits on this goroutine to die, so
			// we're allowed to exit now if needed (if alive is false)
			testHookReadLoopBeforeNextRead()
			continue
		}

		waitForBodyRead := make(chan bool, 2)
		body := &bodyEOFSignal{
			body: resp.Body,
			earlyCloseFn: func() error {
				waitForBodyRead <- false
				<-eofc // will be closed by deferred call at the end of the function
				return nil

			},
			fn: func(err error) error {
				isEOF := err == io.EOF
				waitForBodyRead <- isEOF
				if isEOF {
					<-eofc // see comment above eofc declaration
				} else if err != nil {
					if cerr := pc.canceled(); cerr != nil {
						return cerr
					}
				}
				return err
			},
		}

		resp.Body = body
		if rc.addedGzip && strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
			resp.Body = &gzipReader{body: body}
			resp.Header.Del("Content-Encoding")
			resp.Header.Del("Content-Length")
			resp.ContentLength = -1
			resp.Uncompressed = true
		}

		select {
		case rc.ch <- responseAndError{res: resp}:
		case <-rc.callerGone:
			return
		}

		// Before looping back to the top of this function and peeking on
		// the bufio.Reader, wait for the caller goroutine to finish
		// reading the response body. (or for cancellation or death)
		select {
		case bodyEOF := <-waitForBodyRead:
			pc.t.setReqCanceler(rc.req, nil) // before pc might return to idle pool
			alive = alive &&
				bodyEOF &&
				!pc.sawEOF &&
				pc.wroteRequest() &&
				tryPutIdleConn(trace)
			if bodyEOF {
				eofc <- struct{}{}
			}
        }
		testHookReadLoopBeforeNextRead()
	}
}

// tryPutIdleConn adds pconn to the list of idle persistent connections awaiting
// a new request.
// If pconn is no longer needed or not in a good state, tryPutIdleConn returns
// an error explaining why it wasn't registered.
// tryPutIdleConn does not close pconn. Use putOrCloseIdleConn instead for that.
func (t *Transport) tryPutIdleConn(pconn *persistConn) error {
	if t.DisableKeepAlives || t.MaxIdleConnsPerHost < 0 {
		return errKeepAlivesDisabled
	}
	if pconn.isBroken() {
		return errConnBroken
	}
	pconn.markReused()

	t.idleMu.Lock()
	defer t.idleMu.Unlock()

	// HTTP/2 (pconn.alt != nil) connections do not come out of the idle list,
	// because multiple goroutines can use them simultaneously.
	// If this is an HTTP/2 connection being “returned,” we're done.
	if pconn.alt != nil && t.idleLRU.m[pconn] != nil {
		return nil
	}

	// Deliver pconn to goroutine waiting for idle connection, if any.
	// (They may be actively dialing, but this conn is ready first.
	// Chrome calls this socket late binding.
	// See https://insouciant.org/tech/connection-management-in-chromium/.)
	key := pconn.cacheKey
	if q, ok := t.idleConnWait[key]; ok {
		done := false
		if pconn.alt == nil {
			// HTTP/1.
			// Loop over the waiting list until we find a w that isn't done already, and hand it pconn.
			for q.len() > 0 {
				w := q.popFront()
				if w.tryDeliver(pconn, nil) {
					done = true
					break
				}
			}
		} else {
			// HTTP/2.
			// Can hand the same pconn to everyone in the waiting list,
			// and we still won't be done: we want to put it in the idle
			// list unconditionally, for any future clients too.
			for q.len() > 0 {
				w := q.popFront()
				w.tryDeliver(pconn, nil)
			}
		}
		if q.len() == 0 {
			delete(t.idleConnWait, key)
		} else {
			t.idleConnWait[key] = q
		}
		if done {
			return nil
		}
	}

	if t.closeIdle {
		return errCloseIdle
	}
	if t.idleConn == nil {
		t.idleConn = make(map[connectMethodKey][]*persistConn)
	}
	idles := t.idleConn[key]
	if len(idles) >= t.maxIdleConnsPerHost() {
		return errTooManyIdleHost
	}
	for _, exist := range idles {
		if exist == pconn {
			log.Fatalf("dup idle pconn %p in freelist", pconn)
		}
	}
	t.idleConn[key] = append(idles, pconn)
	t.idleLRU.add(pconn)
	if t.MaxIdleConns != 0 && t.idleLRU.len() > t.MaxIdleConns {
		oldest := t.idleLRU.removeOldest()
		oldest.close(errTooManyIdle)
		t.removeIdleConnLocked(oldest)
	}

	// Set idle timer, but only for HTTP/1 (pconn.alt == nil).
	// The HTTP/2 implementation manages the idle timer itself
	// (see idleConnTimeout in h2_bundle.go).
	if t.IdleConnTimeout > 0 && pconn.alt == nil {
		if pconn.idleTimer != nil {
			pconn.idleTimer.Reset(t.IdleConnTimeout)
		} else {
			pconn.idleTimer = time.AfterFunc(t.IdleConnTimeout, pconn.closeConnIfStillIdle)
		}
	}
	pconn.idleAt = time.Now()
	return nil
}

// A wantConn records state about a wanted connection
// (that is, an active call to getConn).
// The conn may be gotten by dialing or by finding an idle connection,
// or a cancellation may make the conn no longer wanted.
// These three options are racing against each other and use
// wantConn to coordinate and agree about the winning outcome.
type wantConn struct {
	cm    connectMethod
	key   connectMethodKey // cm.key()
	ctx   context.Context  // context for dial
	ready chan struct{}    // closed when pc, err pair is delivered

	// hooks for testing to know when dials are done
	// beforeDial is called in the getConn goroutine when the dial is queued.
	// afterDial is called when the dial is completed or cancelled.
	beforeDial func()
	afterDial  func()

	mu  sync.Mutex // protects pc, err, close(ready)
	pc  *persistConn
	err error
}

// persistConn wraps a connection, usually a persistent one
// (but may be used for non-keep-alive requests as well)
type persistConn struct {
	// alt optionally specifies the TLS NextProto RoundTripper.
	// This is used for HTTP/2 today and future protocols later.
	// If it's non-nil, the rest of the fields are unused.
	alt RoundTripper

	t         *Transport
	cacheKey  connectMethodKey
	conn      net.Conn
	tlsState  *tls.ConnectionState
	br        *bufio.Reader       // from conn
	bw        *bufio.Writer       // to conn
	nwrite    int64               // bytes written
	reqch     chan requestAndChan // written by roundTrip; read by readLoop
	writech   chan writeRequest   // written by roundTrip; read by writeLoop
	closech   chan struct{}       // closed when conn closed
	isProxy   bool
	sawEOF    bool  // whether we've seen EOF from conn; owned by readLoop
	readLimit int64 // bytes allowed to be read; owned by readLoop
	// writeErrCh passes the request write error (usually nil)
	// from the writeLoop goroutine to the readLoop which passes
	// it off to the res.Body reader, which then uses it to decide
	// whether or not a connection can be reused. Issue 7569.
	writeErrCh chan error

	writeLoopDone chan struct{} // closed when write loop ends

	// Both guarded by Transport.idleMu:
	idleAt    time.Time   // time it last become idle
	idleTimer *time.Timer // holding an AfterFunc to close it

	mu                   sync.Mutex // guards following fields
	numExpectedResponses int
	closed               error // set non-nil when conn is closed, before closech is closed
	canceledErr          error // set non-nil if conn is canceled
	broken               bool  // an error has happened on this connection; marked broken so it's not reused.
	reused               bool  // whether conn has had successful request/response and is being reused.
	// mutateHeaderFunc is an optional func to modify extra
	// headers on each outbound request before it's written. (the
	// original Request given to RoundTrip is not modified)
	mutateHeaderFunc func(Header)
}

type requestAndChan struct {
	req *Request
	ch  chan responseAndError // unbuffered; always send in select on callerGone

	// whether the Transport (as opposed to the user client code)
	// added the Accept-Encoding gzip header. If the Transport
	// set it, only then do we transparently decode the gzip.
	addedGzip bool

	// Optional blocking chan for Expect: 100-continue (for send).
	// If the request has an "Expect: 100-continue" header and
	// the server responds 100 Continue, readLoop send a value
	// to writeLoop via this chan.
	continueCh chan<- struct{}

	callerGone <-chan struct{} // closed when roundTrip caller has returned
}

// A writeRequest is sent by the readLoop's goroutine to the
// writeLoop's goroutine to write a request while the read loop
// concurrently waits on both the write response and the server's
// reply.
type writeRequest struct {
	req *transportRequest
	ch  chan<- error

	// Optional blocking chan for Expect: 100-continue (for receive).
	// If not nil, writeLoop blocks sending request body until
	// it receives from this chan.
	continueCh <-chan struct{}
}

// tryDeliver attempts to deliver pc, err to w and reports whether it succeeded.
func (w *wantConn) tryDeliver(pc *persistConn, err error) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.pc != nil || w.err != nil {
		return false
	}

	w.pc = pc
	w.err = err
	if w.pc == nil && w.err == nil {
		panic("net/http: internal error: misuse of tryDeliver")
	}
	close(w.ready)
	return true
}
```

在一次请求(send http.Request以及read http.Response.Body)之后，http.persistConn.readLoop会执行tryPutIdleConn操作

tryPutIdleConn首先查看idleConnWait(map[connectMethodKey]wantConnQueue)中是否存在需要http.persistConn对应host的连接。

如果存在，则将该连接http.persistConn赋予http.wantConn，同时将http.wantConn从Transport.idleConnWait中移除，并返回

如果不存在，则将http.persistConn添加到http.Transport.idleConn(map[connectMethodKey][]*persistConn)空闲连接池中(不超过MaxIdleConns以及MaxIdleConnsPerHost的情况下)

最后设置http.persistConn空闲超时时间(HTTP keep-alives时间)：

```go
// Set idle timer, but only for HTTP/1 (pconn.alt == nil).
// The HTTP/2 implementation manages the idle timer itself
// (see idleConnTimeout in h2_bundle.go).
if t.IdleConnTimeout > 0 && pconn.alt == nil {
    if pconn.idleTimer != nil {
        pconn.idleTimer.Reset(t.IdleConnTimeout)
    } else {
        pconn.idleTimer = time.AfterFunc(t.IdleConnTimeout, pconn.closeConnIfStillIdle)
    }
}
pconn.idleAt = time.Now()

...
// closeConnIfStillIdle closes the connection if it's still sitting idle.
// This is what's called by the persistConn's idleTimer, and is run in its
// own goroutine.
func (pc *persistConn) closeConnIfStillIdle() {
	t := pc.t
	t.idleMu.Lock()
	defer t.idleMu.Unlock()
	if _, ok := t.idleLRU.m[pc]; !ok {
		// Not idle.
		return
	}
	t.removeIdleConnLocked(pc)
	pc.close(errIdleConnTimeout)
}

// t.idleMu must be held.
func (t *Transport) removeIdleConnLocked(pconn *persistConn) {
	if pconn.idleTimer != nil {
		pconn.idleTimer.Stop()
	}
	t.idleLRU.remove(pconn)
	key := pconn.cacheKey
	pconns := t.idleConn[key]
	switch len(pconns) {
	case 0:
		// Nothing
	case 1:
		if pconns[0] == pconn {
			delete(t.idleConn, key)
		}
	default:
		for i, v := range pconns {
			if v != pconn {
				continue
			}
			// Slide down, keeping most recently-used
			// conns at the end.
			copy(pconns[i:], pconns[i+1:])
			t.idleConn[key] = pconns[:len(pconns)-1]
			break
		}
	}
}
```

在http.Transport.IdleConnTimeout时间内，如果http.persistConn一直没有使用，则会触发超时逻辑，将连接从http.Transport.idleConn连接池中剔除；同时删除http.persistConn对应的底层TCP连接

这里如果说http.persistConn从连接池中被再次使用了，则不会触发超时逻辑，如下：

```go
// closeConnIfStillIdle closes the connection if it's still sitting idle.
// This is what's called by the persistConn's idleTimer, and is run in its
// own goroutine.
func (pc *persistConn) closeConnIfStillIdle() {
	t := pc.t
	t.idleMu.Lock()
	defer t.idleMu.Unlock()
	if _, ok := t.idleLRU.m[pc]; !ok {
		// Not idle.
		return
	}
	t.removeIdleConnLocked(pc)
	pc.close(errIdleConnTimeout)
}

// getConn dials and creates a new persistConn to the target as
// specified in the connectMethod. This includes doing a proxy CONNECT
// and/or setting up TLS.  If this doesn't return an error, the persistConn
// is ready to write requests to.
func (t *Transport) getConn(treq *transportRequest, cm connectMethod) (pc *persistConn, err error) {
	req := treq.Request
	trace := treq.trace
	ctx := req.Context()
	if trace != nil && trace.GetConn != nil {
		trace.GetConn(cm.addr())
	}

	w := &wantConn{
		cm:         cm,
		key:        cm.key(),
		ctx:        ctx,
		ready:      make(chan struct{}, 1),
		beforeDial: testHookPrePendingDial,
		afterDial:  testHookPostPendingDial,
	}
	defer func() {
		if err != nil {
			w.cancel(t, err)
		}
	}()

	// Queue for idle connection.
	if delivered := t.queueForIdleConn(w); delivered {
		pc := w.pc
		// Trace only for HTTP/1.
		// HTTP/2 calls trace.GotConn itself.
		if pc.alt == nil && trace != nil && trace.GotConn != nil {
			trace.GotConn(pc.gotIdleConnTrace(pc.idleAt))
		}
		// set request canceler to some non-nil function so we
		// can detect whether it was cleared between now and when
		// we enter roundTrip
		t.setReqCanceler(req, func(error) {})
		return pc, nil
	}

	cancelc := make(chan error, 1)
	t.setReqCanceler(req, func(err error) { cancelc <- err })

	// Queue for permission to dial.
	t.queueForDial(w)

	// Wait for completion or cancellation.
	select {
	case <-w.ready:
		// Trace success but only for HTTP/1.
		// HTTP/2 calls trace.GotConn itself.
		if w.pc != nil && w.pc.alt == nil && trace != nil && trace.GotConn != nil {
			trace.GotConn(httptrace.GotConnInfo{Conn: w.pc.conn, Reused: w.pc.isReused()})
		}
		if w.err != nil {
			// If the request has been cancelled, that's probably
			// what caused w.err; if so, prefer to return the
			// cancellation error (see golang.org/issue/16049).
			select {
			case <-req.Cancel:
				return nil, errRequestCanceledConn
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case err := <-cancelc:
				if err == errRequestCanceled {
					err = errRequestCanceledConn
				}
				return nil, err
			default:
				// return below
			}
		}
		return w.pc, w.err
	case <-req.Cancel:
		return nil, errRequestCanceledConn
	case <-req.Context().Done():
		return nil, req.Context().Err()
	case err := <-cancelc:
		if err == errRequestCanceled {
			err = errRequestCanceledConn
		}
		return nil, err
	}
}

// queueForIdleConn queues w to receive the next idle connection for w.cm.
// As an optimization hint to the caller, queueForIdleConn reports whether
// it successfully delivered an already-idle connection.
func (t *Transport) queueForIdleConn(w *wantConn) (delivered bool) {
	if t.DisableKeepAlives {
		return false
	}

	t.idleMu.Lock()
	defer t.idleMu.Unlock()

	// Stop closing connections that become idle - we might want one.
	// (That is, undo the effect of t.CloseIdleConnections.)
	t.closeIdle = false

	if w == nil {
		// Happens in test hook.
		return false
	}

	// Look for most recently-used idle connection.
	if list, ok := t.idleConn[w.key]; ok {
		stop := false
		delivered := false
		for len(list) > 0 && !stop {
			pconn := list[len(list)-1]
			if pconn.isBroken() {
				// persistConn.readLoop has marked the connection broken,
				// but Transport.removeIdleConn has not yet removed it from the idle list.
				// Drop on floor on behalf of Transport.removeIdleConn.
				list = list[:len(list)-1]
				continue
			}
			delivered = w.tryDeliver(pconn, nil)
			if delivered {
				if pconn.alt != nil {
					// HTTP/2: multiple clients can share pconn.
					// Leave it in the list.
				} else {
					// HTTP/1: only one client can use pconn.
					// Remove it from the list.
					t.idleLRU.remove(pconn)
					list = list[:len(list)-1]
				}
			}
			stop = true
		}
		if len(list) > 0 {
			t.idleConn[w.key] = list
		} else {
			delete(t.idleConn, w.key)
		}
		if stop {
			return delivered
		}
	}

	// Register to receive next connection that becomes idle.
	if t.idleConnWait == nil {
		t.idleConnWait = make(map[connectMethodKey]wantConnQueue)
	}
	q := t.idleConnWait[w.key]
	q.cleanFront()
	q.pushBack(w)
	t.idleConnWait[w.key] = q
	return false
}
```

如上所示，如果http.persistConn从空闲连接池中被捞了出来复用，则会执行：t.idleLRU.remove(pconn)，将persistConn从http.Transport.idleLRU中剔除(表示不空闲了)

这样当timer时间触发(HTTP keep-alives超时)调用closeConnIfStillIdle时就会直接返回，不会进行实际性的操作(空操作)

也即：

http.persistConn在使用完毕放入空闲连接池时，会重置http.Client.IdleConnTimeout的HTTP keep-alives超时时间，如果在这段时间内还没有被复用，则会触发超时，执行关闭逻辑

http.persistConn在从空闲连接池中被捞出来复用时，会设置为非空闲状态，不会触发实际的超时操作

## net.Dialer.Timeout

net.Dialer.Timeout在创建连接时会触发，如下：

```go
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

// deadline returns the earliest of:
//   - now+Timeout
//   - d.Deadline
//   - the context's deadline
// Or zero, if none of Timeout, Deadline, or context's deadline is set.
func (d *Dialer) deadline(ctx context.Context, now time.Time) (earliest time.Time) {
	if d.Timeout != 0 { // including negative, for historical reasons
		earliest = now.Add(d.Timeout)
	}
	if d, ok := ctx.Deadline(); ok {
		earliest = minNonzeroTime(earliest, d)
	}
	return minNonzeroTime(earliest, d.Deadline)
}

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

...
func (fd *netFD) connect(ctx context.Context, la, ra syscall.Sockaddr) (rsa syscall.Sockaddr, ret error) {
	// Do not need to call fd.writeLock here,
	// because fd is not yet accessible to user,
	// so no concurrent operations are possible.
	switch err := connectFunc(fd.pfd.Sysfd, ra); err {
	case syscall.EINPROGRESS, syscall.EALREADY, syscall.EINTR:
	case nil, syscall.EISCONN:
		select {
		case <-ctx.Done():
			return nil, mapErr(ctx.Err())
		default:
		}
		if err := fd.pfd.Init(fd.net, true); err != nil {
			return nil, err
		}
		runtime.KeepAlive(fd)
		return nil, nil
	case syscall.EINVAL:
		// On Solaris and illumos we can see EINVAL if the socket has
		// already been accepted and closed by the server.  Treat this
		// as a successful connection--writes to the socket will see
		// EOF.  For details and a test case in C see
		// https://golang.org/issue/6828.
		if runtime.GOOS == "solaris" || runtime.GOOS == "illumos" {
			return nil, nil
		}
		fallthrough
	default:
		return nil, os.NewSyscallError("connect", err)
	}
	if err := fd.pfd.Init(fd.net, true); err != nil {
		return nil, err
	}
	if deadline, _ := ctx.Deadline(); !deadline.IsZero() {
		fd.pfd.SetWriteDeadline(deadline)
		defer fd.pfd.SetWriteDeadline(noDeadline)
	}

	// Start the "interrupter" goroutine, if this context might be canceled.
	// (The background context cannot)
	//
	// The interrupter goroutine waits for the context to be done and
	// interrupts the dial (by altering the fd's write deadline, which
	// wakes up waitWrite).
	if ctx != context.Background() {
		// Wait for the interrupter goroutine to exit before returning
		// from connect.
		done := make(chan struct{})
		interruptRes := make(chan error)
		defer func() {
			close(done)
			if ctxErr := <-interruptRes; ctxErr != nil && ret == nil {
				// The interrupter goroutine called SetWriteDeadline,
				// but the connect code below had returned from
				// waitWrite already and did a successful connect (ret
				// == nil). Because we've now poisoned the connection
				// by making it unwritable, don't return a successful
				// dial. This was issue 16523.
				ret = mapErr(ctxErr)
				fd.Close() // prevent a leak
			}
		}()
		go func() {
			select {
			case <-ctx.Done():
				// Force the runtime's poller to immediately give up
				// waiting for writability, unblocking waitWrite
				// below.
				fd.pfd.SetWriteDeadline(aLongTimeAgo)
				testHookCanceledDial()
				interruptRes <- ctx.Err()
			case <-done:
				interruptRes <- nil
			}
		}()
	}

	for {
		// Performing multiple connect system calls on a
		// non-blocking socket under Unix variants does not
		// necessarily result in earlier errors being
		// returned. Instead, once runtime-integrated network
		// poller tells us that the socket is ready, get the
		// SO_ERROR socket option to see if the connection
		// succeeded or failed. See issue 7474 for further
		// details.
		if err := fd.pfd.WaitWrite(); err != nil {
			select {
			case <-ctx.Done():
				return nil, mapErr(ctx.Err())
			default:
			}
			return nil, err
		}
		nerr, err := getsockoptIntFunc(fd.pfd.Sysfd, syscall.SOL_SOCKET, syscall.SO_ERROR)
		if err != nil {
			return nil, os.NewSyscallError("getsockopt", err)
		}
		switch err := syscall.Errno(nerr); err {
		case syscall.EINPROGRESS, syscall.EALREADY, syscall.EINTR:
		case syscall.EISCONN:
			return nil, nil
		case syscall.Errno(0):
			// The runtime poller can wake us up spuriously;
			// see issues 14548 and 19289. Check that we are
			// really connected; if not, wait again.
			if rsa, err := syscall.Getpeername(fd.pfd.Sysfd); err == nil {
				return rsa, nil
			}
		default:
			return nil, os.NewSyscallError("connect", err)
		}
		runtime.KeepAlive(fd)
	}
}
```

如上所示，创建连接的超时deadline由取值于如下几个参数中最早的一个：

```go
// deadline returns the earliest of:
     //   - now+Timeout
     //   - d.Deadline
     //   - the context's deadline
     // Or zero, if none of Timeout, Deadline, or context's deadline is set.
```

另外，如果说目标地址是多个地址，则会将deadline平均设置成每个地址的连接建立超时时间，最后由context.WithTimeout + ctx.Done() 触发，如下：

```go
// When using TCP, and the host in the address parameter resolves to multiple
// network addresses, any dial timeout (from d.Timeout or ctx) is spread
// over each consecutive dial, such that each is given an appropriate
// fraction of the time to connect.
// For example, if a host has 4 IP addresses and the timeout is 1 minute,
// the connect to each single address will be given 15 seconds to complete
// before trying the next one.
```

也即net.Dialer.Timeout影响底层连接建立的超时时间

## net.Dialer.KeepAlive

最后，我们分析一下`net.Dialer.KeepAlive`作用，如下：

```go
func (d *Dialer) DialContext(ctx context.Context, network, address string) (Conn, error) {
    ...
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

func setKeepAlive(fd *netFD, keepalive bool) error {
	err := fd.pfd.SetsockoptInt(syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, boolint(keepalive))
	runtime.KeepAlive(fd)
	return wrapSyscallError("setsockopt", err)
}

func setKeepAlivePeriod(fd *netFD, d time.Duration) error {
	// The kernel expects seconds so round to next highest second.
	d += (time.Second - time.Nanosecond)
	secs := int(d.Seconds())
	if err := fd.pfd.SetsockoptInt(syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, secs); err != nil {
		return wrapSyscallError("setsockopt", err)
	}
	err := fd.pfd.SetsockoptInt(syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, secs)
	runtime.KeepAlive(fd)
	return wrapSyscallError("setsockopt", err)
}
```

net.Dialer.KeepAlive用于设置TCP的keepalive参数(syscall.TCP_KEEPINTVL以及syscall.TCP_KEEPIDLE)，这里先介绍一下TCP keepalive

### [TCP keepalive](https://tldp.org/HOWTO/TCP-Keepalive-HOWTO/overview.html)

>> In order to understand what TCP keepalive (which we will just call keepalive) does, you need do nothing more than read the name: keep TCP alive. This means that you will be able to check your connected socket (also known as TCP sockets), and determine whether the connection is still up and running or if it has broken.
   
>> The keepalive concept is very simple: when you set up a TCP connection, you associate a set of timers. Some of these timers deal with the keepalive procedure. When the keepalive timer reaches zero, you send your peer a keepalive probe packet with no data in it and the ACK flag turned on. You can do this because of the TCP/IP specifications, as a sort of duplicate ACK, and the remote endpoint will have no arguments, as TCP is a stream-oriented protocol. On the other hand, you will receive a reply from the remote host (which doesn't need to support keepalive at all, just TCP/IP), with no data and the ACK set.

TCP keepalive用于检查TCP sockets是否存活。它会在TCP socket空闲(没有数据包发送or接收)一段时间后，向对端发出不包含数据(zero-length)的探测包(keepalive probe packet)，并在没有收到回应的情况下按照固定间隔重试若干次，如果一直没有回应，则认为对端已经死了，TCP sockets失效，最终关闭连接

TCP keepalive是无侵入的，应用程序感知不到它的存在(由内核完成)

默认情况下TCP keepalive是关闭的，需要应用程序使用setsockopt开启TCP sockets的keepalive功能。另外，linux提供了如下三个keepalive参数供用户使用：

* tcp_keepalive_time: the interval between the last data packet sent (simple ACKs are not considered data) and the first keepalive probe; after the connection is marked to need keepalive, this counter is not used any further
* tcp_keepalive_intvl: the interval between subsequential keepalive probes, regardless of what the connection has exchanged in the meantime
* tcp_keepalive_probes: the number of unacknowledged probes to send before considering the connection dead and notifying the application layer
   
操作示例如下：

```bash
# The first two parameters are expressed in seconds, and the last is the pure number. This means that the keepalive routines wait for two hours (7200 secs) before sending the first keepalive probe, and then resend it every 75 seconds. If no ACK response is received for nine consecutive times, the connection is marked as broken.
# cat /proc/sys/net/ipv4/tcp_keepalive_time
7200

# cat /proc/sys/net/ipv4/tcp_keepalive_intvl
75

# cat /proc/sys/net/ipv4/tcp_keepalive_probes
9

# Modifying this value is straightforward: you need to write new values into the files. Suppose you decide to configure the host so that keepalive starts after ten minutes of channel inactivity, and then send probes in intervals of one minute. Because of the high instability of our network trunk and the low value of the interval, suppose you also want to increase the number of probes to 20.
# To be sure that all succeeds, recheck the files and confirm these new values are showing in place of the old ones.
# echo 600 > /proc/sys/net/ipv4/tcp_keepalive_time

# echo 60 > /proc/sys/net/ipv4/tcp_keepalive_intvl

# echo 20 > /proc/sys/net/ipv4/tcp_keepalive_probes
```

### [HTTP keep-alive](https://en.wikipedia.org/wiki/HTTP_persistent_connection)

>> HTTP persistent connection, also called HTTP keep-alive, or HTTP connection reuse, is the idea of using a single TCP connection to send and receive multiple HTTP requests/responses, as opposed to opening a new connection for every single request/response pair. The newer HTTP/2 protocol uses the same idea and takes it further to allow multiple concurrent requests/responses to be multiplexed over a single connection.

HTTP keep-alive，也即HTTP长连接，表示在同一个TCP socket上发送多个HTTP请求和回应；对应的HTTP短连接则表示在一次HTTP请求回应后，立刻关闭TCP socket

支持情况：

* HTTP 1.0默认不开启keep-alive，需要在请求报头中添加："Connection: keep-alive"开启该特性，另外回应报文中也会添加该报头
* HTTP 1.1默认开启keep-alive，需要在请求报头中添加："Connection: close"关闭该特性

### TCP keepalive vs HTTP keep-alive(区别)

* TCP keepalive：用于探测TCP sockets是否存活
* HTTP keep-alive：用于复用TCP sockets
* HTTP连接池：用于管理HTTP keep-alive sockets，供HTTP请求使用

## 总结

* http.Client.Timeout：http.Client.Timeout涵盖了HTTP请求从连接建立，请求发送，接收回应，重定向，以及读取http.Response.Body的整个生命周期的超时时间
* http.Client.IdleConnTimeout：HTTP keep-alives超时时间(http.persistConn在使用完毕放入空闲连接池时，会重置http.Client.IdleConnTimeout的HTTP keep-alives超时时间，如果在这段时间内还没有被复用，则会触发超时，执行关闭逻辑；http.persistConn在从空闲连接池中被捞出来复用时，会设置为非空闲状态，不会触发实际的超时操作)
* net.Dialer.Timeout：底层连接建立的超时时间
* net.Dialer.KeepAlive：设置TCP的keepalive参数(syscall.TCP_KEEPINTVL以及syscall.TCP_KEEPIDLE)

## Refs

* [Notes on TCP keepalive in Go](https://thenotexpert.com/golang-tcp-keepalive/)
* [Using TCP keepalive with Go](https://felixge.de/2014/08/26/tcp-keepalive-with-golang.html)
* [TCP keepalive overview](https://tldp.org/HOWTO/TCP-Keepalive-HOWTO/overview.html)
* [Using TCP keepalive under Linux](https://tldp.org/HOWTO/TCP-Keepalive-HOWTO/usingkeepalive.html)

