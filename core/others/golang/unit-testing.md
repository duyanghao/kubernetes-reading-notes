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
* [GoMock](#gomock)
* [Refs](#refs)

本文总结日常开发中常用的golang单元测试经验

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
        t.Errorf("Fib(%d) = %d; expected %d", in, actual, expected)
    }
}
```

执行 `go test .`显示失败，输出：

```go
$ go test .
--- FAIL: TestFib (0.00s)
    fib_test.go:15: Fib(7) = 64; expected 13
FAIL
FAIL    _/root/test     0.002s
FAIL

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

* 运行 `go test`，该 package 下所有的测试用例都会被执行

* `go test -v`，`-v` 参数会显示每个用例的测试结果，另外 `-cover` 参数可以查看覆盖率
* 如果只想运行其中的一个用例，例如 `TestFib`，可以用 `-run` 参数指定，该参数支持通配符 `*`和部分正则表达式，例如 `^`、`$`

### table driven tests

对于一些测试类型相同，测试目的相同的样例可以以表格的形式集中在一起进行测试，这样代码会更加精巧，不会显得那么重复和多余，也即table driven tests：

示例代码：

```go
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
            t.Errorf("expected: %v, got: %v", tc.want, got)
        }
    }
}

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

```bash
func TestSplit(t *testing.T) {
    tests := map[string]struct {
        input string
        sep   string
        want  []string
    }{
        "simple":       {input: "a/b/c", sep: "/", want: []string{"a", "b", "c"}},
        "wrong sep":    {input: "a/b/c", sep: ",", want: []string{"a/b/c"}},
        "no sep":       {input: "abc", sep: "/", want: []string{"abc"}},
        "trailing sep": {input: "a/b/c/", sep: "/", want: []string{"a", "b", "c"}},
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

可以看到当trailing_sep子测试失败后，其它测试依旧可以正常完成，而且每个子测试有对应相关信息输出。而关于子测试的好处可以总结如下：

- 新增用例非常简单，只需给 cases 新增一条测试数据即可
- 测试代码可读性好，直观地能够看到每个子测试的参数和期待的返回值
- 用例失败时，报错信息的格式比较统一，测试报告易于阅读

### 帮助函数

对一些重复的逻辑，抽取出来作为公共的帮助函数(helpers)，可以增加测试代码的可读性和可维护性。 借助帮助函数，可以让测试用例的主逻辑看起来更清晰。例如，我们可以将创建子测试的逻辑抽取出来：

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

```go
# go test -v
=== RUN   TestMul
    calc_test.go:10: 2 * 0 expected 1, but 0 got
--- FAIL: TestMul (0.00s)
FAIL
exit status 1
FAIL    _/root/test/mul 0.002s
```

可以看到，错误发生在第11行，也就是帮助函数 `createMulTestCase` 内部。17, 18, 19行都调用了该方法，我们第一时间并不能够确定是哪一行发生了错误。有些帮助函数还可能在不同的函数中被调用，报错信息都在同一处，不方便问题定位。因此，Go 语言在 1.9 版本中引入了 `t.Helper()`，用于标注该函数是帮助函数，报错时将输出帮助函数调用者的信息，而不是帮助函数的内部信息

修改 `createMulTestCase`，调用 `t.Helper()`，测试如下：

```go
$ go test -v
=== RUN   TestMul
    calc_test.go:19: 2 * 0 expected 1, but 0 got
--- FAIL: TestMul (0.00s)
FAIL
exit status 1
FAIL    _/root/test/mul 0.002s
```

可以看到错误信息变成createMulTestCase(t, &calcCase{2, 0, 1})这一行了

另外，如果换成子函数，则运行结果又会不一样，如下：

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

关于 `helper` 函数的 2 个建议：

- 不要返回错误， 帮助函数内部直接使用 `t.Error` 或 `t.Fatal` 即可，在用例主逻辑中不会因为太多的错误处理代码，影响可读性
- 调用 `t.Helper()` 让报错信息更准确，有助于定位

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

基准测试是测量一个程序在固定工作负载下的性能。在Go语言中，基准测试函数和普通测试函数写法类似，但是以Benchmark为前缀名，并且带有一个`*testing.B`类型的参数；`*testing.B`参数除了提供和`*testing.T`类似的方法，还有额外一些和性能测量相关的方法。它还提供了一个整数N，用于指定操作执行的循环次数：

```go
func BenchmarkFib10(b *testing.B) {
        for n := 0; n < b.N; n++ {
                Fib(10)
        }
}
```

基准函数会运行目标代码 b.N 次。在基准执行期间，程序会自动调整 b.N 直到基准测试函数持续足够长的时间。执行如下：

```go
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
func BenchmarkFib100(b *testing.B) { benchmarkFib(b, 100) }
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

## GoMock



## Refs

* [Go Test 单元测试简明教程](https://geektutu.com/post/quick-go-test.html)
* [Prefer table driven tests](https://dave.cheney.net/2019/05/07/prefer-table-driven-tests)
* [testing - 单元测试](https://books.studygolang.com/The-Golang-Standard-Library-by-Example/chapter09/09.1.html)
