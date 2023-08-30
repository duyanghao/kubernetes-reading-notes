总结工作过程中对golang使用上的一些实战技巧，不断补充……

原则：实用

### remove duplicate values from slices

```go
seen := make(map[string]struct{})
for _, item := range items {
    if _, ok := seen[item]; !ok {
        seen[item] = struct{}{}
        // TODO: unduplicated operations ...
    }
}
```

### httpclient

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
// parse rsp body
err = json.NewDecoder(rsp.Body).Decode(&xxx)
if err != nil {
	return err
}
return err
```

### Singleton Pattern

```go
type singleton struct {
}

var instance *singleton
var once sync.Once

func GetInstance() *singleton {
    once.Do(func() {
        instance = &singleton{}
    })
    return instance
}
```

### goroutine pool

```go
func goroutine_pool(number, taskNum int) {
	var wg sync.WaitGroup
	channels := make(chan int, taskNum)
	for i := 0; i < taskNum; i++ {
		channels <- i
	}
	close(channels)
	if taskNum < number {
		number = taskNum
	}
	for i := 0; i < number; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			for ch := range channels {
				// TODO: goroutine process logic code
				fmt.Printf("task: %d in goroutine: %d ...\n", ch, index)
			}
		}(i)
	}
	wg.Wait()
}

func main() {
	goroutine_pool(5, 20)
}
```

参考[kubernetes实现](https://github.com/kubernetes/client-go/blob/master/util/workqueue/parallelizer.go)：

```go
package workqueue

import (
	"context"
	"sync"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

type DoWorkPieceFunc func(piece int)

// ParallelizeUntil is a framework that allows for parallelizing N
// independent pieces of work until done or the context is canceled.
func ParallelizeUntil(ctx context.Context, workers, pieces int, doWorkPiece DoWorkPieceFunc) {
	var stop <-chan struct{}
	if ctx != nil {
		stop = ctx.Done()
	}

	toProcess := make(chan int, pieces)
	for i := 0; i < pieces; i++ {
		toProcess <- i
	}
	close(toProcess)

	if pieces < workers {
		workers = pieces
	}

	wg := sync.WaitGroup{}
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer utilruntime.HandleCrash()
			defer wg.Done()
			for piece := range toProcess {
				select {
				case <-stop:
					return
				default:
					doWorkPiece(piece)
				}
			}
		}()
	}
	wg.Wait()
}
```

### Sort(Refes to [helm/helm kind_sorter.go](https://github.com/helm/helm/blob/master/pkg/releaseutil/kind_sorter.go))

```go
...
// KindSortOrder is an ordering of Kinds.
type KindSortOrder []string

// InstallOrder is the order in which manifests should be installed (by Kind).
//
// Those occurring earlier in the list get installed before those occurring later in the list.
var InstallOrder KindSortOrder = []string{
	"Namespace",
	"NetworkPolicy",
	"ResourceQuota",
}

// UninstallOrder is the order in which manifests should be uninstalled (by Kind).
//
// Those occurring earlier in the list get uninstalled before those occurring later in the list.
var UninstallOrder KindSortOrder = []string{
	"APIService",
	"Ingress",
}

// sortByKind does an in-place sort of manifests by Kind.
//
// Results are sorted by 'ordering', keeping order of items with equal kind/priority
func sortByKind(manifests []Manifest, ordering KindSortOrder) []Manifest {
	ks := newKindSorter(manifests, ordering)
	sort.Stable(ks)
	return ks.manifests
}

type kindSorter struct {
	ordering  map[string]int
	manifests []Manifest
}

func newKindSorter(m []Manifest, s KindSortOrder) *kindSorter {
	o := make(map[string]int, len(s))
	for v, k := range s {
		o[k] = v
	}

	return &kindSorter{
		manifests: m,
		ordering:  o,
	}
}

func (k *kindSorter) Len() int { return len(k.manifests) }

func (k *kindSorter) Swap(i, j int) { k.manifests[i], k.manifests[j] = k.manifests[j], k.manifests[i] }

func (k *kindSorter) Less(i, j int) bool {
	a := k.manifests[i]
	b := k.manifests[j]
	first, aok := k.ordering[a.Head.Kind]
	second, bok := k.ordering[b.Head.Kind]

	if !aok && !bok {
		// if both are unknown then sort alphabetically by kind, keep original order if same kind
		if a.Head.Kind != b.Head.Kind {
			return a.Head.Kind < b.Head.Kind
		}
		return first < second
	}
	// unknown kind is last
	if !aok {
		return false
	}
	if !bok {
		return true
	}
	// sort different kinds, keep original order if same priority
	return first < second
}
```

### Golang可变参数(Refes to [grpc/grpc-go](https://github.com/grpc/grpc-go/blob/master/dialoptions.go))

```go
// dialOptions configure a Dial call. dialOptions are set by the DialOption
// values passed to Dial.
type dialOptions struct {
	unaryInt  UnaryClientInterceptor
	streamInt StreamClientInterceptor
    ...
}

// DialOption configures how we set up the connection.
type DialOption interface {
	apply(*dialOptions)
}

// funcDialOption wraps a function that modifies dialOptions into an
// implementation of the DialOption interface.
type funcDialOption struct {
	f func(*dialOptions)
}

func (fdo *funcDialOption) apply(do *dialOptions) {
	fdo.f(do)
}

func newFuncDialOption(f func(*dialOptions)) *funcDialOption {
	return &funcDialOption{
		f: f,
	}
}

// WithWriteBufferSize determines how much data can be batched before doing a
// write on the wire. The corresponding memory allocation for this buffer will
// be twice the size to keep syscalls low. The default value for this buffer is
// 32KB.
//
// Zero will disable the write buffer such that each write will be on underlying
// connection. Note: A Send call may not directly translate to a write.
func WithWriteBufferSize(s int) DialOption {
	return newFuncDialOption(func(o *dialOptions) {
		o.copts.WriteBufferSize = s
	})
}

// WithReadBufferSize lets you set the size of read buffer, this determines how
// much data can be read at most for each read syscall.
//
// The default value for this buffer is 32KB. Zero will disable read buffer for
// a connection so data framer can access the underlying conn directly.
func WithReadBufferSize(s int) DialOption {
	return newFuncDialOption(func(o *dialOptions) {
		o.copts.ReadBufferSize = s
	})
}
```

### AppendIf

```go
func appendIf(actions []action, a action, shouldAppend bool) []action {
	if shouldAppend {
		actions = append(actions, a)
	}
	return actions
}

...
// k8s.io/kubernetes/vendor/k8s.io/apiserver/pkg/endpoints/installer.go:436
actions = appendIf(actions, action{"LIST", resourcePath, resourceParams, namer, false}, isLister)
actions = appendIf(actions, action{"POST", resourcePath, resourceParams, namer, false}, isCreater)
actions = appendIf(actions, action{"DELETECOLLECTION", resourcePath, resourceParams, namer, false}
```

### 必须实现某个接口

```go
// Implement ShortNamesProvider
var _ rest.ShortNamesProvider = &REST{}
```

### append正确用法

* 错误使用

```go
// len(dms) = 4(!= 2)
func main() {
    testSlice := []string{"a", "b"}
    dms := make([]string, len(testSlice))
    for _, item := range testSlice {
        dms = append(dms, item)
    }
}
```

* 正确使用1

```go
// len(dms) = 2
func main() {
    testSlice := []string{"a", "b"}
    dms := make([]string, 0)
    for _, item := range testSlice {
       	dms = append(dms, item)
    }
}
```

* 正确使用2(推荐)

```go
// len(dms) = 2
func main() {
    testSlice := []string{"a", "b"}
    var dms []string
    for _, item := range testSlice {
       	dms = append(dms, item)
    }
}
```

### range临时变量踩坑

* 错误使用

```go
type Union struct {
	Id string
	// ...
}

// map[2621754f-c80c-4bd7-a060-66850d2c0ab1:0xc001961d40 7f9e180c-e0bc-45c7-8d11-9507f9a4b087:0xc001961d40 a2997835-c915-477a-b23b-5dc5078a629b:0xc001961d40]
func convertUnion2Map(unionSlice []Union) map[string]Union {
    unionMap := make(map[string]*Union)
    for _, union := range unionSlice {
        unionMap[union.Id] = &union
    }
    return unionMap
}
```

这种情况map中每个key指向相同的地址，也即range中临时变量产生一次，每次覆盖值

* 正确使用

```go
type Union struct {
	Id string
	// ...
}

func convertUnion2Map(unionSlice []Union) map[string]Union {
    unionMap := make(map[string]*Union)
    for index := range unionSlice {
        unionMap[unionSlice[index].Id] = &unionSlice[index]
    }
    return unionMap
}
```

## Refs

* [singleton-pattern-in-go](http://marcio.io/2015/07/singleton-pattern-in-go/)
* [如何裸写一个goroutine pool](http://legendtkl.com/2016/09/06/go-pool/)
