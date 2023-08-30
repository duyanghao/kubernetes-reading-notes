Go 最佳实践总结（30条）
===================

* package的名字和目录必须保持一致(main包除外)，采用有意义的包名，通过名字即可了解包的功能
* 文件名除开特殊用途文件以外(LICENSE、OWNERS等)，应该全小写单词，不同单词之间使用下划线连接
* 目录名除开特殊用途以外（CHANGELOG、LICENSES等）必须全小写，允许使用中划线"-"连接组合，但是不能以"-"开头或者结尾
* 采用驼峰命名法，首字母根据访问控制大写或者小写，包外可见首字母大写
* 内容和注释符之间要有一个空格，可以使用流利的中/英文进行注释说明
* 当某个部分等待完成时，可用 TODO: 开头的注释来提醒维护人员
* 函数的返回值应尽量避免使用命名返回值，使用命名变量很容易引起隐藏的bug，比如在defer场景下，命名返回值和匿名返回值会有不一样的结果
* 函数/方法嵌套层数建议不超过5层，当嵌套层数太多了，可读性和维护性就比较差，需要考虑进行重构
* 对于函数参数是sync.Mutex 或者类似的用于同步的类型，参数传递时需使用指针传递，避免造成死锁
* 错误处理的原则就是不能丢弃任何有返回err的调用，不要使用 _ 丢弃，必须全部处理。接收到错误，要么返回err，或者使用log记录下来
* 错误描述如果是英文必须为小写，不需要标点结尾
* err作为函数参数返回值时，一般是放在最后一个 
* 谨慎使用panic，如果有panic需要内部recover进行处理，并返回该err： 
  * 在程序启动的时候，如果有强依赖的服务出现故障时 panic 退出
  * 在程序启动的时候，如果发现有配置明显不符合要求， 可以 panic 退出（防御编程）
  * 其他情况下只要不是不可恢复的程序错误，都不应该直接 panic ，而是应该返回 error
* 一个文件只能定义一个init函数。一个包内有多个init函数时，各自之间不能有任何依赖关系，因为在同一个包的init执行顺序，golang没有明确定义
* 尽量避免使用init函数，如果使用 init函数，init函数中的代码应该保证：
  * 函数定义的内容不对环境或调用方式有任何依赖，具有完全确定性
  * 避免访问或操作全局或环境状态，如：机器信息、环境变量、工作目录、程序参数/输入等
  * 避免 I/O 操作，包括：文件系统、网络和系统调用
* 禁止for range遍历slice与map过程中使用指针，会导致重复取值
* 禁止在遍历slice和map过程中对结构本身进行修改，会导致很有未知的问题
* 如果函数存在有多个返回的地方，可采用defer来完成，如关闭资源，解锁等清理操作
* defer释放锁的场景下，如果程序有高性能要求的，需抛弃defer释放锁，改成程序业务逻辑自行控制锁释放，以免锁粒度过大
* 避免过度使用defer，defer本身也存在不小的性能损耗，且过度使用后也会导致逻辑变复杂 
* 声明channel时限定类型，保证最小权限（只读、只写、读写） 
* 使用channel时确保对channel是否关闭进行检查
* 禁止在nil和closed的channel进行接收，发送，关闭操作
* 避免频繁创建对象导致GC处理性能问题，可使用sync.Pool复用对象
* 高性能场景下，对于字符串的连接，建议使用bytes.Buffer或者strings.Builder进行处理
* 高性能场景下，string和bytes切片的转换建议结合unsafe.Pointer，0内存分配
* 高并发时避免并发冲突，在编译时可采用go build -race进行数据竞争检测
* 为高并发的轻量级任务处理创建goroutine池，因为机器运行的内存是有限的，每个协程至少要消耗2KB的内存空间
* 所有的goroutine都是要求能够退出的，避免造成内存泄漏
* 在项目工程根目录下增加.golangci.yml文件，具体内容如下：
```yaml
run:
  # timeout for analysis, e.g. 30s, 5m, default is 1m
  timeout: 5m
  skip-dirs:
  skip-dirs-use-default: true
  modules-download-mode: mod
linters:
  enable:
    # linters maintained by golang.org
    - gofmt
    - goimports
    - revive
    - govet
    # linters default enabled by golangci-lint .
    - deadcode
    - errcheck
    - gosimple
    - ineffassign
    - staticcheck
    - structcheck
    - typecheck
    - unused
    - varcheck
    # other linters supported by golangci-lint.
    - gocyclo
    - gosec
    - whitespace
    - dupl

linters-settings:
  goimports:
    # go.mod中项目工程module名称
    local-prefixes: github.com/xxx/xxx
  gocyclo:
    # minimal cyclomatic complexity to report
    min-complexity: 15
  dupl:
    threshold: 300
```

在makefile中添加：
```sh
lint:
  golangci-lint run -c golangci.yml
```
代码上库之前执行make lint命令即可完成静态代码检查



