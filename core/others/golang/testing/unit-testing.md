Go测试总结
=========

Table of Contents
=================

* [单元测试](#单元测试)
  * [table driven tests](#table-driven-tests)
  * [子测试(Subtests)](#子测试(Subtests))
  * [帮助函数](#帮助函数)
  * [网络测试](#网络测试)
* [基准测试](#基准测试)
  * [比较型基准测试](#比较型基准测试)
  * [并发基准测试](#并发基准测试)
* [GoMock](#gomock)
* [Conclusion](#conclusion)
* [Refs](#refs)

本文总结日常开发中基础的Go测试知识，以便可以更加快速和高效进行Go测试用例编写

## 单元测试

testing 为 Go 语言 package 提供自动化测试的支持，通过 `go test` 命令，能够自动执行如下形式的任何函数：

```go
func TestXxx(*testing.T)
```

Xxx 可以是任何字母数字字符串，但是第一个字母不能是小写字母

在这些函数中，使用 `Error`、`Fail` 或相关方法来发出失败信号

要编写一个新的测试文件，需要创建一个名称以 _test.go 结尾的文件，该文件包含 `TestXxx` 函数，如上所述。 将该文件放在与被测试文件相同的包中。该文件将被排除在正常的程序包之外，但在运行 `go test` 命令时将被包含

**通常功能函数和测试函数是一对一的关系**，如下：

示例代码：

```go
// fib.go
func Fib(n int) int {
        if n < 2 {
                return n
        }
        return Fib(n-1) + Fib(n-1)
}
```

测试代码：

```go
// fib_test.go
func TestFib(t *testing.T) {
        var (
                in       = 7
                expected = 13
        )
        actual := Fib(in)
        if actual != expected {
                t.Fatalf("Fib(%d) = %d; expected %d", in, actual, expected)
        }
}
```

执行`go test .`显示失败，输出：

```go
$ go test .
--- FAIL: TestFib (0.00s)
    fib_test.go:15: Fib(7) = 64; expected 13
FAIL
FAIL    _/root/test     0.002s
FAIL
```

这里再添加一个测试用例：

```go
func TestFib2(t *testing.T) {
        // ...
}
```

执行`go test -v`，结果如下：

```go
$ go test -run TestFib -v -cover
=== RUN   TestFib
    fib_test.go:15: Fib(7) = 64; expected 13
--- FAIL: TestFib (0.00s)
=== RUN   TestFib2
--- PASS: TestFib2 (0.00s)
FAIL
coverage: 100.0% of statements
exit status 1
FAIL    _/root/test     0.002s
```

通过上述例子可以总结如下：

* 运行 `go test`，该 package 下所有的测试用例都会被执行
* `go test -v`，`-v` 参数会显示每个用例的测试结果，另外 `-cover` 参数可以查看覆盖率
* 如果只想运行其中的一个用例，例如 `TestFib`，可以用 `-run` 参数指定，该参数支持通配符 `*`和部分正则表达式，例如 `^`、`$`

### table driven tests

对于一些测试类型相同，测试目的相同的样例可以以表格的形式集中在一起进行测试，这样代码会更加精巧，不会显得那么重复和多余，也即table driven tests：

示例代码：

```go
package split

import (
        "strings"
)

// Split slices s into all substrings separated by sep and
// returns a slice of the substrings between those separators.
func Split(s, sep string) []string {
        var result []string
        i := strings.Index(s, sep)
        for i > -1 {
                result = append(result, s[:i])
                s = s[i+len(sep):]
                i = strings.Index(s, sep)
        }
        return append(result, s)
}
```

测试代码：

```go
func TestSplit(t *testing.T) {
        tests := []struct {
                input string
                sep   string
                want  []string
        }{
                {input: "a/b/c", sep: "/", want: []string{"a", "b", "c"}},
                {input: "a/b/c", sep: ",", want: []string{"a/b"}},
                {input: "abc", sep: "/", want: []string{"ab"}},
        }

        for _, tc := range tests {
                got := Split(tc.input, tc.sep)
                if !reflect.DeepEqual(tc.want, got) {
                        t.Fatalf("expected: %v, got: %v", tc.want, got)
                }
        }
}
```

运行如下：

```bash
$ go test -run=TestSplit -v
=== RUN   TestSplit
    split_test.go:45: expected: [a/b], got: [a/b/c]
--- FAIL: TestSplit (0.00s)
FAIL
exit status 1
FAIL    _/root/test/split       0.002s
```

如果换成t.Errorf，则运行结果如下：

```bash
$ go test -run=TestSplit -v
=== RUN   TestSplit
    split_test.go:45: expected: [a/b], got: [a/b/c]
    split_test.go:45: expected: [ab], got: [abc]
--- FAIL: TestSplit (0.00s)
FAIL
exit status 1
FAIL    _/root/test/split       0.002s
```

t.Errorf遇错不停，还会继续执行其他的测试用例；而t.Fatalf遇错即停

### 子测试(Subtests)

在上述table driven test示例中，我们利用表格将多个测试用例集成在一个测试函数中，这样虽然可以解决因为功能类似导致代码重复的问题，但是如果测试出现问题则只能根据日志查看，可读性稍微差点；另外，如果使用了t.Fatalf，这样其中任意一个测试失败，则会终止整个函数执行，最终无法判断剩余用例的正确性

因此我们可以在上述基础上添加子测试。子测试是 Go 语言内置支持的，可以在某个测试用例中，根据测试场景使用 `t.Run`创建不同的子测试用例，示例如下：

```go
func TestSplit(t *testing.T) {
        tests := map[string]struct {
                input string
                sep   string
                want  []string
        }{
                "simple":       {input: "a/b/c", sep: "/", want: []string{"a", "b", "c"}},
                "trailing sep": {input: "a/b/c/", sep: "/", want: []string{"a", "b", "c"}},
                "wrong sep":    {input: "a/b/c", sep: ",", want: []string{"a/b/c"}},
                "no sep":       {input: "abc", sep: "/", want: []string{"abc"}},
        }

        for name, tc := range tests {
                t.Run(name, func(t *testing.T) {
                        got := Split(tc.input, tc.sep)
                        if !reflect.DeepEqual(tc.want, got) {
                                t.Fatalf("expected: %v, got: %v", tc.want, got)
                        }
                })
        }
}
```

运行如下：

```bash
$ go test -run=TestSplit -v
=== RUN   TestSplit
=== RUN   TestSplit/simple
=== RUN   TestSplit/trailing_sep
    split_test.go:25: expected: [a b c], got: [a b c ]
=== RUN   TestSplit/wrong_sep
=== RUN   TestSplit/no_sep
--- FAIL: TestSplit (0.00s)
    --- PASS: TestSplit/simple (0.00s)
    --- FAIL: TestSplit/trailing_sep (0.00s)
    --- PASS: TestSplit/wrong_sep (0.00s)
    --- PASS: TestSplit/no_sep (0.00s)
FAIL
exit status 1
FAIL    _/root/test/split       0.002s
```

可以看到当trailing_sep子测试失败后，其它测试依旧可以正常完成，而且每个子测试有对应相关信息输出

而关于子测试的好处可以总结如下：

- 新增用例非常简单，只需给 cases 新增一条测试数据即可
- 测试代码可读性好，可以直观看到每个子测试的参数和期待的返回值
- 用例失败时，报错信息的格式比较统一，测试报告易于阅读

### 帮助函数

对一些重复的逻辑，抽取出来作为公共的帮助函数(helpers)，可以增加测试代码的可读性和可维护性。 借助帮助函数，可以让测试用例的主逻辑看起来更清晰。例如，我们可以将创建子测试功能的逻辑抽取出来：

```go
package mul

import "testing"

type calcCase struct{ A, B, Expected int }

func createMulTestCase(t *testing.T, c *calcCase) {
        // t.Helper()
        if ans := Mul(c.A, c.B); ans != c.Expected {
                t.Fatalf("%d * %d expected %d, but %d got",
                        c.A, c.B, c.Expected, ans)
        }

}

func TestMul(t *testing.T) {
        createMulTestCase(t, &calcCase{2, 3, 6})
        createMulTestCase(t, &calcCase{2, -3, -6})
        createMulTestCase(t, &calcCase{2, 0, 1}) // wrong case
}
```

运行如下：

```bash
$ go test -v
=== RUN   TestMul
    calc_test.go:10: 2 * 0 expected 1, but 0 got
--- FAIL: TestMul (0.00s)
FAIL
exit status 1
FAIL    _/root/test/mul 0.002s
```

可以看到，错误发生在第11行，也就是帮助函数 `createMulTestCase` 内部。17, 18, 19行都调用了该方法，我们第一时间并不能够确定是哪一行发生了错误。有些帮助函数还可能在不同的函数中被调用，报错信息都在同一处，不方便问题定位。因此，Go 语言在 1.9 版本中引入了 `t.Helper()`，用于标注该函数是帮助函数，报错时将输出帮助函数调用者的信息，而不是帮助函数的内部信息

修改 `createMulTestCase`，调用 `t.Helper()`，测试如下：

```bash
$ go test -v
=== RUN   TestMul
    calc_test.go:19: 2 * 0 expected 1, but 0 got
--- FAIL: TestMul (0.00s)
FAIL
exit status 1
FAIL    _/root/test/mul 0.002s
```

可以看到错误信息变成createMulTestCase(t, &calcCase{2, 0, 1})这一行了

另外，如果换成子测试，则运行结果又会不一样，如下：

```go
package mul

import "testing"

type calcCase struct {
        Name     string
        A        int
        B        int
        Expected int
}

func createMulTestCase(t *testing.T, c *calcCase) {
        t.Helper()
        t.Run(c.Name, func(t *testing.T) {
                if ans := Mul(c.A, c.B); ans != c.Expected {
                        t.Fatalf("%d * %d expected %d, but %d got",
                                c.A, c.B, c.Expected, ans)
                }
        })
}

func TestMul(t *testing.T) {
        createMulTestCase(t, &calcCase{"subtest#1", 2, 3, 6})
        createMulTestCase(t, &calcCase{"subtest#2", 2, -3, -6})
        createMulTestCase(t, &calcCase{"subtest#3", 2, 0, 1}) // wrong case
}
```

测试如下：

```bash
$ go test -v
=== RUN   TestMul
=== RUN   TestMul/subtest#1
=== RUN   TestMul/subtest#2
=== RUN   TestMul/subtest#3
    calc_test.go:16: 2 * 0 expected 1, but 0 got
--- FAIL: TestMul (0.00s)
    --- PASS: TestMul/subtest#1 (0.00s)
    --- PASS: TestMul/subtest#2 (0.00s)
    --- FAIL: TestMul/subtest#3 (0.00s)
FAIL
exit status 1
FAIL    _/root/test/mul 0.002s
```

可以看到错误行又变成createMulTestCase函数内部了，而不是帮助函数调用处了。这里其实也比较好理解，因为子测试已经有标识了(TestMul/subtest#3)，那么就可以很容易定位到是哪里调用帮助函数了(createMulTestCase(t, &calcCase{"subtest#3", 2, 0, 1}))

另外，这里给出关于`helper`函数的2个建议：

- 不要返回错误，帮助函数内部直接使用`t.Error`或`t.Fatal`即可；在用例主逻辑中不应该出现太多的错误处理代码，影响可读性
- 调用`t.Helper()`让报错信息更准确，有助于定位

### 网络测试

假设需要测试某个 API 接口的 handler 能够正常工作，例如 helloHandler：

```go
// conn.go
func helloHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("hello world"))
}
```

可以创建真实的网络连接进行测试：

```go
// conn_test.go
package conn

import (
        "io/ioutil"
        "net"
        "net/http"
        "testing"
)

func handleError(t *testing.T, err error) {
        t.Helper()
        if err != nil {
                t.Fatal("failed", err)
        }
}

func TestConn(t *testing.T) {
        ln, err := net.Listen("tcp", "127.0.0.1:80")
        handleError(t, err)
        defer ln.Close()

        http.HandleFunc("/hello", helloHandler)
        go http.Serve(ln, nil)

        resp, err := http.Get("http://" + ln.Addr().String() + "/hello")
        handleError(t, err)

        defer resp.Body.Close()
        body, err := ioutil.ReadAll(resp.Body)
        handleError(t, err)

        if string(body) != "hello world" {
                t.Fatal("expected hello world, but got", string(body))
        }
}
```

运行如下：

```bash
$ go test -v
=== RUN   TestConn
--- PASS: TestConn (0.00s)
PASS
ok      _/root/test/conn        0.004s
```

- `net.Listen("tcp", "127.0.0.1:80")`：监听一个未被占用的端口，并返回 Listener
- 调用 `http.Serve(ln, nil)` 启动 http 服务
- 使用 `http.Get` 发起一个 Get 请求，检查返回值是否正确
- 尽量不对 `http` 和 `net` 库使用 mock，这样可以覆盖较为真实的场景

而针对 http 开发的场景，使用标准库 `net/http/httptest` 进行测试则更为高效，上述测试用例可以改写如下：

```go
package conn

import (
        "io/ioutil"
        "net/http/httptest"
        "testing"
)

func TestConn(t *testing.T) {
        req := httptest.NewRequest("GET", "http://example.com/foo", nil)
        w := httptest.NewRecorder()
        helloHandler(w, req)
        bytes, _ := ioutil.ReadAll(w.Result().Body)

        if string(bytes) != "hello world" {
                t.Fatal("expected hello world, but got", string(bytes))
        }
}
```

运行如下：

```bash
$ go test -v
=== RUN   TestConn
--- PASS: TestConn (0.00s)
PASS
ok      _/root/test/conn        0.003s
```

这里使用 httptest 模拟请求对象(req)和响应对象(w)，达到了相同的目的，而且不需要专门写defer释放相关资源

## 基准测试

基准测试是测量一个程序在固定工作负载下的性能。在Go语言中，基准测试函数和单元测试函数写法类似，但是以Benchmark为前缀名，并且带有一个`*testing.B`类型的参数；`*testing.B`参数除了提供和`*testing.T`类似的方法，还有额外一些和性能测量相关的方法。它还提供了一个整数N，用于指定操作执行的循环次数：

```go
func BenchmarkFib10(b *testing.B) {
        for n := 0; n < b.N; n++ {
                Fib(10)
        }
}
```

基准函数会运行目标代码 b.N 次。在基准执行期间，程序会自动调整 b.N 直到基准测试函数持续足够长的时间。执行如下：

```bash
$ go test -bench=Fib10 -benchmem
goos: linux
goarch: amd64
BenchmarkFib10-16         496747              2395 ns/op               0 B/op          0 allocs/op
PASS
ok      _/root/test     1.219s
```

- `BenchmarkFib10-16`：16，表示运行时对应的GOMAXPROCS的值，这对于一些与并发相关的基准测试是重要的信息
- `496747` ：基准测试的迭代总次数 b.N
- `2395 ns/op`：平均每次迭代所消耗的纳秒数
- `0 B/op`：平均每次迭代内存所分配的字节数
- `0 allocs/op`：平均每次迭代的内存分配次数

由于这里没有Fib没有使用内存(除了函数栈桢以外)，所以这里关于内存的两个指标都为0

### 比较型基准测试

比较型的基准测试通常是单参数的函数，由几个不同数量级的基准测试函数调用，例如：

```go
func benchmarkFib(b *testing.B, size int) {
        for n := 0; n < b.N; n++ {
                Fib(size)
        }
}

func BenchmarkFib1(b *testing.B)  { benchmarkFib(b, 1) }
func BenchmarkFib10(b *testing.B) { benchmarkFib(b, 10) }
func BenchmarkFib20(b *testing.B) { benchmarkFib(b, 20) }
```

比较型的基准测试反映出的模式在程序设计阶段是很有帮助的，它可以用来比较不同数量级下的基准测试数据：

```bash
$ go test -bench=. -benchmem
goos: linux
goarch: amd64
BenchmarkFib1-16        478089406                2.51 ns/op            0 B/op          0 allocs/op
BenchmarkFib10-16         500757              2394 ns/op               0 B/op          0 allocs/op
BenchmarkFib20-16            484           2458204 ns/op               0 B/op          0 allocs/op
PASS
ok      _/root/test     4.123s
```

默认情况下，每个基准测试最少运行 1 秒。如果基准测试函数返回时，还不到 1 秒钟，`b.N` 的值会按照序列 1,2,5,10,20,50,... 增加，同时再次运行基准测试函数

### 并发基准测试

可以使用 `RunParallel` 测试并发基准性能，如下：

```go
func BenchmarkParallel(b *testing.B) {
        templ := template.Must(template.New("test").Parse("Hello, {{.}}!"))
        b.RunParallel(func(pb *testing.PB) {
                var buf bytes.Buffer
                for pb.Next() {
                        // 所有 goroutine 一起，循环一共执行 b.N 次
                        buf.Reset()
                        templ.Execute(&buf, "World")
                }
        })
}
```

运行如下：

```bash
$ go test -benchmem -bench=BenchmarkParallel .
goos: linux
goarch: amd64
BenchmarkParallel-16            21238836                56.9 ns/op            48 B/op          1 allocs/op
PASS
ok      _/root/test     2.251s
```

## GoMock

当待测试的函数/对象的依赖关系很复杂，并且有些依赖不能直接创建，例如数据库连接、文件I/O等。这种场景就非常适合使用 mock/stub 测试。简单来说，就是用 mock 对象模拟依赖项的行为

常用的Go mock/stub框架主要有：

* GoStub：支持全局变量，函数，过程打桩；但是不支持为接口以及方法打桩
* Monkey：支持函数，过程，方法打桩
* GoMock：支持接口打桩

日常工作中会结合使用上述工具，本文主要介绍如何使用GoMock测试框架：

[GoMock](https://github.com/golang/mock)是由Go官方开发维护的测试框架，实现了较为完整的基于interface的Mock功能，能够与Go内置的testing包良好集成，也能用于其它的测试环境中。GoMock测试框架包含了GoMock包和mockgen工具两部分，其中GoMock包完成对Mock对象生命周期的管理，mockgen工具用来生成interface对应的Mock类源文件。使用如下命令即可安装：

```bash
$ go get -u github.com/golang/mock/gomock
$ go get -u github.com/golang/mock/mockgen
```

文档如下：

```bash
Standard usage:

    (1) Define an interface that you wish to mock.
          type MyInterface interface {
            SomeMethod(x int64, y string)
          }
    (2) Use mockgen to generate a mock from the interface.
    (3) Use the mock in a test:
          func TestMyThing(t *testing.T) {
            mockCtrl := gomock.NewController(t)
            defer mockCtrl.Finish()

            mockObj := something.NewMockMyInterface(mockCtrl)
            mockObj.EXPECT().SomeMethod(4, "blah")
            // pass mockObj to a real object and play with it.
          }
```

这里以一个实际例子来说明上述GoMock使用步骤：

step1 - 构建接口

整个目录结构如下：

```bash
server/
|-- server.go
`-- server_test.go
db/
|-- db.go
|-- db_mock.go
```

编写db源文件如下，其中包含MyDB接口和User结构体：

```go
// db.go
package db

type User struct {
        ID   string `json:"id"`
        Name string `json:"name"`
        Age int `json:age`
}

type MyDB interface {
        Retrieve(key string) (*User, error)
        // TODO
}
```

step2 - 生成mock

通过gomock生成mock文件，如下：

```bash
mockgen -source=./db/db.go -destination=./db/db_mock.go -package=db
```

db_mock.go文件内容如下：

```go
// Code generated by MockGen. DO NOT EDIT.
// Source: db/db.go

// Package db is a generated GoMock package.
package db

import (
        gomock "github.com/golang/mock/gomock"
        reflect "reflect"
)

// MockMyDB is a mock of MyDB interface
type MockMyDB struct {
        ctrl     *gomock.Controller
        recorder *MockMyDBMockRecorder
}

// MockMyDBMockRecorder is the mock recorder for MockMyDB
type MockMyDBMockRecorder struct {
        mock *MockMyDB
}

// NewMockMyDB creates a new mock instance
func NewMockMyDB(ctrl *gomock.Controller) *MockMyDB {
        mock := &MockMyDB{ctrl: ctrl}
        mock.recorder = &MockMyDBMockRecorder{mock}
        return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockMyDB) EXPECT() *MockMyDBMockRecorder {
        return m.recorder
}

// Retrieve mocks base method
func (m *MockMyDB) Retrieve(key string) (*User, error) {
        m.ctrl.T.Helper()
        ret := m.ctrl.Call(m, "Retrieve", key)
        ret0, _ := ret[0].(*User)
        ret1, _ := ret[1].(error)
        return ret0, ret1
}

// Retrieve indicates an expected call of Retrieve
func (mr *MockMyDBMockRecorder) Retrieve(key interface{}) *gomock.Call {
        mr.mock.ctrl.T.Helper()
        return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Retrieve", reflect.TypeOf((*MockMyDB)(nil).Retrieve), key)
}
```

step3 - 使用mock

假设有如下代码使用了上述db，如下：

```go
// server.go
package server

import (
        "db"
)

type Server struct {
        db db.MyDB
}

func (s *Server) AddUserAge(key string) (*db.User, error) {
        user, _ := s.db.Retrieve(key)
        user.Age++
        return user, nil
}
```

该函数逻辑很简单，就是获取用户，并对用户年龄加1

接着编写测试文件如下：

```go
// server_test.go
package server

import (
        "db"
        "github.com/golang/mock/gomock"
        "testing"
)

func TestAddUserAge(t *testing.T) {
        ctl := gomock.NewController(t)
        defer ctl.Finish()

        mockMyDB := db.NewMockMyDB(ctl)

        mockMyDB.EXPECT().Retrieve("1").Return(&db.User{
                ID:   "1",
                Name: "duyanghao",
                Age:  27,
        }, nil)

        server := &Server{
                db: mockMyDB,
        }

        user, _ := server.AddUserAge("1")

        if user.Age != 28 {
                t.Fatal("expected age 28, but got", user.Age)
        }
}
```

可以看到利用GoMock模拟了MyDB接口的Retrieve函数，整个测试流程如下：

* ctl := gomock.NewController(t)实例化mock控制器
* ctl.Finish() 每个控制器都需要调用这个方法，确保mock的断言被引用(It is not idempotent and therefore can only be invoked once.)
* db.NewMockMyDB(ctl)：注入控制器创建mock对象
* Retrieve("1") Mock输入参数
* Return() 定义返回值

运行测试如下：

```go
$ go test .
ok      _/root/test/server      0.002s
```

除了上述规定明确参数和返回值的基本打桩用法以外，GoMock还支持其它更加高级和灵活的打桩技巧，例如：检测调用次数(Times)、调用顺序(InOrder or After)，动态设置返回值(DoAndReturn)等，这里不展开介绍

## Conclusion

本文先概述了Go单元测试，并通过例子展开介绍了table driven tests，子测试，帮助函数以及网络测试，这些都是日常开发过程中经常会遇到的单元测试使用场景。接着介绍了测量程序在固定工作负载下性能的Go基准测试，并引入了比较型基准测试以及并发基准测试。最后介绍了Go mock/stub 测试框架GoMock，并以一个例子说明了GoMock的使用流程。希望通过本文对Go测试有一个基本的了解和使用

## Refs

* [Go Test 单元测试简明教程](https://geektutu.com/post/quick-go-test.html)
* [Prefer table driven tests](https://dave.cheney.net/2019/05/07/prefer-table-driven-tests)
* [testing - 单元测试](https://books.studygolang.com/The-Golang-Standard-Library-by-Example/chapter09/09.1.html)
* [GO单元测试之一 （GoMock）](https://juejin.cn/post/6857189382307184647)
* [What's the difference between a mock & stub?](https://stackoverflow.com/questions/3459287/whats-the-difference-between-a-mock-stub)