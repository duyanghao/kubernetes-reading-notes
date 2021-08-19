Kubernetes WebShell
===================

在Pass平台建设中，常规的Kubernetes运维操作包括：远程登录，上传以及下载容器文件，下面总结一下如上功能的后端实现

## 远程登录

远程登录容器核心代码如下：

1、监听websocket

```go
func main() {
	...
	go func() {
		http.HandleFunc("/websocket", websocket.ServeWebSocket)
		http.ListenAndServe(":8080", nil)
	}()
	...
}
```

2、升级http协议为websocket协议

```go
func ServeWebSocket(w http.ResponseWriter, r *http.Request) {
	clusterName := r.URL.Query().Get("cluster")
	namespace := r.URL.Query().Get("namespace")
	pod := r.URL.Query().Get("pod")
	container := r.URL.Query().Get("container")
	cmd := r.URL.Query().Get("cmd")

	log.Infof("ServeWebSocket container: %s/%s/%s/%s and command: %s ...", clusterName, namespace, pod, container, cmd)
	websocket.Handler(func(ws *websocket.Conn) {
		ws.PayloadType = websocket.BinaryFrame
		err := ExecPod(ws, clusterName, namespace, pod, container, cmd)
		if err != nil {
			log.Errorf("Exec pod error: %v", err)
		}
		defer ws.Close()
		_, _ = ws.Write([]byte("\r\nconnection closed!!!\r\n"))
	}).ServeHTTP(w, r)
}
```

3、处理webshell输入输出

```go
// ExecPod executes stream webshell commands interactively.
func ExecPod(ws *websocket.Conn, clusterName, namespace, podName, container, cmd string) error {
	...
	req := kubeclient.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec")
	req.VersionedParams(&corev1.PodExecOptions{
		Container: container,
		Command:   []string{cmd},
		Stdin:     true,
		Stdout:    true,
		Stderr:    true,
		TTY:       true,
	}, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(kubeconfig, http.MethodPost, req.URL())
	if err != nil {
		log.Infof("NewSPDYExecutor error %s", err.Error())
		return err
	}
	read, write := io.Pipe()
	que := Que{Size: make(chan remotecommand.TerminalSize, 10)}
	go func() {
		buf := make([]byte, 256)
		for {
			var arg ResizeTerminal
			l, err := ws.Read(buf)
			if err != nil {
				_ = write.Close()
				return
			}
			err = json.Unmarshal(buf[:l], &arg)
			if err == nil {
				fmt.Print(arg)
				size := remotecommand.TerminalSize{Width: uint16(arg.Cols), Height: uint16(arg.Rows)}
				que.Size <- size
				continue
			}
			_, _ = write.Write(buf[:l])
		}
	}()

	if err = executor.Stream(remotecommand.StreamOptions{
		Stdin:             read,
		Stdout:            ws,
		Stderr:            ws,
		Tty:               true,
		TerminalSizeQueue: que,
	}); err != nil {
		return err
	}
	return nil
}
```

如上即可实现webshell的功能，效果如下：

```bash
/ # ls
bin    dev    etc    home   lib    media  mnt    opt    proc   root   run    sbin   srv    sys    tmp    usr    var
/ # 
```

## 文件下载

文件下载的处理逻辑如下：

```go
// K8sClient holds a clientset and a config
type K8sClient struct {
	ClientSet *clientset.Clientset
	Config    *rest.Config
}
...

// DownloadPod downloads file from pod container.
func DownloadPod(writer http.ResponseWriter, clusterName, namespace, podName, container, path string) error {
	...
	k8sClient := &util.K8sClient{
		ClientSet: kubeclient,
		Config:    kubeconfig,
	}
	if err = util.DownloadFromK8s(k8sClient, filepath.Join(namespace, podName, container, path), writer); err != nil {
		return err
	}
	_, fileName := filepath.Split(path)
	header := writer.Header()
	header["Content-Type"] = []string{"application/octet-stream"}
	header["Content-Disposition"] = []string{"attachment; filename=" + fileName}
	return nil
}

// DownloadFromK8s downloads a single file from Kubernetes
func DownloadFromK8s(iClient interface{}, path string, writer io.Writer) error {
	client := *iClient.(*K8sClient)
	pSplit := strings.Split(path, "/")
	if err := validateK8sPath(pSplit); err != nil {
		return err
	}
	namespace, podName, containerName, pathToCopy := initK8sVariables(pSplit)
	command := []string{"cat", pathToCopy}

	attempts := 3
	attempt := 0
	for attempt < attempts {
		attempt++

		stderr, err := Exec(client, namespace, podName, containerName, command, nil, writer)
		if attempt == attempts {
			if len(stderr) != 0 {
				return fmt.Errorf("STDERR: " + (string)(stderr))
			}
			if err != nil {
				return err
			}
		}
		if err == nil {
			return nil
		}
		utils.Sleep(attempt)
	}

	return nil
}
...
// Exec executes a command in a given container
func Exec(client K8sClient, namespace, podName, containerName string, command []string, stdin io.Reader, stdout io.Writer) ([]byte, error) {
	clientset, config := client.ClientSet, client.Config

	req := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec")
	req.VersionedParams(&corev1.PodExecOptions{
		Command:   command,
		Container: containerName,
		Stdin:     stdin != nil,
		Stdout:    stdout != nil,
		Stderr:    true,
		TTY:       false,
	}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(config, http.MethodPost, req.URL())
	if err != nil {
		return nil, fmt.Errorf("NewSPDYExecutor error: %s", err.Error())
	}

	var stderr bytes.Buffer
	if err = exec.Stream(remotecommand.StreamOptions{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: &stderr,
		Tty:    false,
	}); err != nil {
		return nil, fmt.Errorf("Stream error: %s", err.Error())
	}

	return stderr.Bytes(), nil
}
```

## 文件上传

文件上传的处理逻辑如下：

```go
// UploadPod uploads file to pod container.
func UploadPod(clusterName, namespace, podName, container, srcPath, dstPath string) error {
	...
	k8sClient := &util.K8sClient{
		ClientSet: kubeclient,
		Config:    kubeconfig,
	}

	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	if err = util.UploadToK8s(k8sClient, filepath.Join(namespace, podName, container, dstPath), f); err != nil {
		return err
	}
	return nil
}
...
// UploadToK8s uploads a single file to Kubernetes
func UploadToK8s(iClient interface{}, path string, reader io.Reader) error {
	client := *iClient.(*K8sClient)
	pSplit := strings.Split(path, "/")
	if err := validateK8sPath(pSplit); err != nil {
		return err
	}

	namespace, podName, containerName, pathToCopy := initK8sVariables(pSplit)

	attempts := 3
	attempt := 0
	for attempt < attempts {
		attempt++
		dir, _ := filepath.Split(pathToCopy)
		command := []string{"mkdir", "-p", dir}
		stderr, err := Exec(client, namespace, podName, containerName, command, nil, nil)

		if len(stderr) != 0 {
			if attempt == attempts {
				return fmt.Errorf("STDERR: " + (string)(stderr))
			}
			utils.Sleep(attempt)
			continue
		}
		if err != nil {
			if attempt == attempts {
				return err
			}
			utils.Sleep(attempt)
			continue
		}

		command = []string{"touch", pathToCopy}
		stderr, err = Exec(client, namespace, podName, containerName, command, nil, nil)

		if len(stderr) != 0 {
			if attempt == attempts {
				return fmt.Errorf("STDERR: " + (string)(stderr))
			}
			utils.Sleep(attempt)
			continue
		}
		if err != nil {
			if attempt == attempts {
				return err
			}
			utils.Sleep(attempt)
			continue
		}

		command = []string{"cp", "/dev/stdin", pathToCopy}
		stderr, err = Exec(client, namespace, podName, containerName, command, readerWrapper{reader}, nil)

		if len(stderr) != 0 {
			if attempt == attempts {
				return fmt.Errorf("STDERR: " + (string)(stderr))
			}
			utils.Sleep(attempt)
			continue
		}
		if err != nil {
			if attempt == attempts {
				return err
			}
			utils.Sleep(attempt)
			continue
		}
		return nil
	}

	return nil
}
```

综上是远程登录，上传以及下载容器文件的后端核心实现