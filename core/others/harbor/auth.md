本文从源码层面描述harbor 认证&鉴权流程

Table of Contents
=================

* [harbor auth流程](#auth流程)
* [docker distribution token协议流程](#token协议流程)
* [Refs](#refs)
      
## auth流程

以[harbor v1.8.1](https://github.com/goharbor/harbor/tree/v1.8.1)为例进行分析，目录结构日下：

```bash
src/
|-- Gopkg.lock
|-- Gopkg.toml
|-- chartserver
|-- cmd
|-- common
|-- core
	|-- api
	|-- auth
	|-- config
	|-- controllers
	|-- filter
	|-- label
	|-- main.go
	|-- notifier
	|-- promgr
	|-- proxy
	|-- router.go
	|-- service
	|-- systeminfo
	|-- utils
	`-- views
|-- favicon.ico
|-- jobservice
|-- portal
|-- registryctl
|-- replication
|-- testing
`-- vendor
```

auth入口在`core/filter/security.go`文件：

```go
// Init ReqCtxMofiers list
func Init() {
	// integration with admiral
	if config.WithAdmiral() {
		reqCtxModifiers = []ReqCtxModifier{
			&secretReqCtxModifier{config.SecretStore},
			&tokenReqCtxModifier{},
			&basicAuthReqCtxModifier{},
			&unauthorizedReqCtxModifier{}}
		return
	}

	// standalone
	reqCtxModifiers = []ReqCtxModifier{
		&configCtxModifier{},
		&secretReqCtxModifier{config.SecretStore},
		&oidcCliReqCtxModifier{},
		&idTokenReqCtxModifier{},
		&authProxyReqCtxModifier{},
		&robotAuthReqCtxModifier{},
		&basicAuthReqCtxModifier{},
		&sessionReqCtxModifier{},
		&unauthorizedReqCtxModifier{}}
}
```

逐层认证，直到一个成功为止：

```go
// SecurityFilter authenticates the request and passes a security context
// and a project manager with it which can be used to do some authN & authZ
func SecurityFilter(ctx *beegoctx.Context) {
	if ctx == nil {
		return
	}

	req := ctx.Request
	if req == nil {
		return
	}

	// add security context and project manager to request context
	for _, modifier := range reqCtxModifiers {
		if modifier.Modify(ctx) {
			break
		}
	}
}
```

这里以`basicAuthReqCtxModifier`为例看认证逻辑，如下：

```go
type basicAuthReqCtxModifier struct{}

func (b *basicAuthReqCtxModifier) Modify(ctx *beegoctx.Context) bool {
	username, password, ok := ctx.Request.BasicAuth()
	if !ok {
		return false
	}
	log.Debug("got user information via basic auth")

	// integration with admiral
	if config.WithAdmiral() {
		// Can't get a token from Admiral's login API, we can only
		// create a project manager with the token of the solution user.
		// That way may cause some wrong permission promotion in some API
		// calls, so we just handle the requests which are necessary
		match := false
		var err error
		path := ctx.Request.URL.Path
		for _, pattern := range basicAuthReqPatterns {
			match, err = regexp.MatchString(pattern.path, path)
			if err != nil {
				log.Errorf("failed to match %s with pattern %s", path, pattern)
				continue
			}
			if match {
				break
			}
		}
		if !match {
			log.Debugf("basic auth is not supported for request %s %s, skip",
				ctx.Request.Method, ctx.Request.URL.Path)
			return false
		}

		token, err := config.TokenReader.ReadToken()
		if err != nil {
			log.Errorf("failed to read solution user token: %v", err)
			return false
		}
		authCtx, err := authcontext.Login(config.AdmiralClient,
			config.AdmiralEndpoint(), username, password, token)
		if err != nil {
			log.Errorf("failed to authenticate %s: %v", username, err)
			return false
		}

		log.Debug("using global project manager...")
		pm := config.GlobalProjectMgr
		log.Debug("creating admiral security context...")
		securCtx := admr.NewSecurityContext(authCtx, pm)

		setSecurCtxAndPM(ctx.Request, securCtx, pm)
		return true
	}

	// standalone
	user, err := auth.Login(models.AuthModel{
		Principal: username,
		Password:  password,
	})
	if err != nil {
		log.Errorf("failed to authenticate %s: %v", username, err)
		return false
	}
	if user == nil {
		log.Debug("basic auth user is nil")
		return false
	}
	log.Debug("using local database project manager")
	pm := config.GlobalProjectMgr
	log.Debug("creating local database security context...")
	securCtx := local.NewSecurityContext(user, pm)
	setSecurCtxAndPM(ctx.Request, securCtx, pm)
	return true
}
```

首先是`auth.Login`，如下：

```go
// standalone
user, err := auth.Login(models.AuthModel{
	Principal: username,
	Password:  password,
})
if err != nil {
	log.Errorf("failed to authenticate %s: %v", username, err)
	return false
}
if user == nil {
	log.Debug("basic auth user is nil")
	return false
}
```

这里会用到`core/auth/authenticator.go`，逻辑如下：

```go
// Login authenticates user credentials based on setting.
func Login(m models.AuthModel) (*models.User, error) {

	authMode, err := config.AuthMode()
	if err != nil {
		return nil, err
	}
	if authMode == "" || dao.IsSuperUser(m.Principal) {
		authMode = common.DBAuth
	}
	log.Debug("Current AUTH_MODE is ", authMode)

	authenticator, ok := registry[authMode]
	if !ok {
		return nil, fmt.Errorf("Unrecognized auth_mode: %s", authMode)
	}
	if lock.IsLocked(m.Principal) {
		log.Debugf("%s is locked due to login failure, login failed", m.Principal)
		return nil, nil
	}
	user, err := authenticator.Authenticate(m)
	if err != nil {
		if _, ok = err.(ErrAuth); ok {
			log.Debugf("Login failed, locking %s, and sleep for %v", m.Principal, frozenTime)
			lock.Lock(m.Principal)
			time.Sleep(frozenTime)
		}
		return nil, err
	}
	err = authenticator.PostAuthenticate(user)
	return user, err
}
```

获取认证模式，然后调用对应的`Authenticate`函数。这里认证模式总共有：`db_auth`、`ldap`、`uaa(oauth2)`、`oidc`这几种，这里以最简单的`db_auth`为例分析：

```bash
src/core/auth/
|-- auth_test.go
|-- authenticator.go
|-- authproxy
|-- db
|-- ldap
|-- lock.go
`-- uaa
```

```go
// Authenticate calls dao to authenticate user.
func (d *Auth) Authenticate(m models.AuthModel) (*models.User, error) {
	u, err := dao.LoginByDb(m)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, auth.NewErrAuth("Invalid credentials")
	}
	return u, nil
}

func init() {
	auth.Register("db_auth", &Auth{})
}

// LoginByDb is used for user to login with database auth mode.
func LoginByDb(auth models.AuthModel) (*models.User, error) {
	o := GetOrmer()

	var users []models.User
	n, err := o.Raw(`select * from harbor_user where (username = ? or email = ?) and deleted = false`,
		auth.Principal, auth.Principal).QueryRows(&users)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}

	user := users[0]

	if user.Password != utils.Encrypt(auth.Password, user.Salt) {
		return nil, nil
	}

	user.Password = "" // do not return the password

	return &user, nil
}

// User holds the details of a user.
type User struct {
	UserID   int    `orm:"pk;auto;column(user_id)" json:"user_id"`
	Username string `orm:"column(username)" json:"username"`
	Email    string `orm:"column(email)" json:"email"`
	Password string `orm:"column(password)" json:"password"`
	Realname string `orm:"column(realname)" json:"realname"`
	Comment  string `orm:"column(comment)" json:"comment"`
	Deleted  bool   `orm:"column(deleted)" json:"deleted"`
	Rolename string `orm:"-" json:"role_name"`
	// if this field is named as "RoleID", beego orm can not map role_id
	// to it.
	Role int `orm:"-" json:"role_id"`
	//	RoleList     []Role `json:"role_list"`
	HasAdminRole bool         `orm:"column(sysadmin_flag)" json:"has_admin_role"`
	ResetUUID    string       `orm:"column(reset_uuid)" json:"reset_uuid"`
	Salt         string       `orm:"column(salt)" json:"-"`
	CreationTime time.Time    `orm:"column(creation_time);auto_now_add" json:"creation_time"`
	UpdateTime   time.Time    `orm:"column(update_time);auto_now" json:"update_time"`
	GroupList    []*UserGroup `orm:"-" json:"-"`
	OIDCUserMeta *OIDCUser    `orm:"-" json:"oidc_user_meta,omitempty"`
}
```

查询PostgreSQL数据库，若存在，则返回用户信息。之后构建`project manager`（project操作管理）以及`security context`（rbac鉴权）：

```go
log.Debug("using global project manager...")
pm := config.GlobalProjectMgr
log.Debug("creating admiral security context...")
securCtx := admr.NewSecurityContext(authCtx, pm)

setSecurCtxAndPM(ctx.Request, securCtx, pm)
return true
```

对于`project manager`这里简单默认为：`local driver`(PostgreSQL)，如下：

```bash
src/core/promgr/pmsdriver/
|-- admiral
|-- driver.go
`-- local
```

```go
var (
	// SecretStore manages secrets
	SecretStore *secret.Store
	// GlobalProjectMgr is initialized based on the deploy mode
	GlobalProjectMgr promgr.ProjectManager
	keyProvider      comcfg.KeyProvider
	// AdmiralClient is initialized only under integration deploy mode
	// and can be passed to project manager as a parameter
	AdmiralClient *http.Client
	// TokenReader is used in integration mode to read token
	TokenReader admiral.TokenReader
	// defined as a var for testing.
	defaultCACertPath = "/etc/core/ca/ca.crt"
	cfgMgr            *comcfg.CfgManager
)

func initProjectManager() error {
	var driver pmsdriver.PMSDriver
	if WithAdmiral() {
		log.Debugf("Initialising Admiral client with certificate: %s", defaultCACertPath)
		content, err := ioutil.ReadFile(defaultCACertPath)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(content); !ok {
			return fmt.Errorf("failed to append cert content into cert worker")
		}
		AdmiralClient = &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				TLSClientConfig: &tls.Config{
					RootCAs: pool,
				},
			},
		}

		// integration with admiral
		log.Info("initializing the project manager based on PMS...")
		path := os.Getenv("SERVICE_TOKEN_FILE_PATH")
		if len(path) == 0 {
			path = defaultTokenFilePath
		}
		log.Infof("service token file path: %s", path)
		TokenReader = &admiral.FileTokenReader{
			Path: path,
		}
		driver = admiral.NewDriver(AdmiralClient, AdmiralEndpoint(), TokenReader)
	} else {
		// standalone
		log.Info("initializing the project manager based on local database...")
		driver = local.NewDriver()
	}
	GlobalProjectMgr = promgr.NewDefaultProjectManager(driver, true)
	return nil

}
```

对于`security context`这里创建为：`local SecurityContext`（其它认证对应不同的`authz SecurityContext`），如下：

```go
securCtx := local.NewSecurityContext(user, pm)

func setSecurCtxAndPM(req *http.Request, ctx security.Context, pm promgr.ProjectManager) {
	addToReqContext(req, SecurCtxKey, ctx)
	addToReqContext(req, PmKey, pm)
}
```

```bash
src/common/security/
|-- admiral
|-- context.go
|-- local
|-- robot
`-- secret
```

这里看`local SecurityContext`，如下：

```go
// Can returns whether the user can do action on resource
func (s *SecurityContext) Can(action rbac.Action, resource rbac.Resource) bool {
	ns, err := resource.GetNamespace()
	if err == nil {
		switch ns.Kind() {
		case "project":
			projectIDOrName := ns.Identity()
			isPublicProject, _ := s.pm.IsPublic(projectIDOrName)
			projectNamespace := rbac.NewProjectNamespace(projectIDOrName, isPublicProject)
			user := project.NewUser(s, projectNamespace, s.GetProjectRoles(projectIDOrName)...)
			return rbac.HasPermission(user, resource, action)
		}
	}

	return false
}
```

总结：

* 目录结构：

```bash
src/common/security/——鉴权
src/core/auth/——认证
src/core/filter/security.go——auth入口
```

* 这里若要添加一种认证和鉴权，则只需要分别在auth目录和security目录分别创建一个目录，对应认证和鉴权逻辑

## token协议流程

![](images/v2-registry-auth.png)

```bash
docker login x.x.x.x
```

login日志：

```
May  6 15:21:24 x.x.x.x proxy[xxxx]: x.x.x.x - "GET /v2/ HTTP/1.1" 401 87 "-" "docker/18.09.5 go/go1.10.8 git-commit/e8ff056 kernel/3.10.0-957.el7.x86_64 os/linux arch/amd64 UpstreamClient(Docker-Client/18.09.5 \x5C(linux\x5C))" 0.008 0.008 .
May  6 15:21:24 x.x.x.x proxy[xxxx]: x.x.x.x - "GET /service/token?account=xxx&client_id=docker&offline_token=true&service=harbor-registry HTTP/1.1" 200 893 "-" "docker/18.09.5 go/go1.10.8 git-commit/e8ff056 kernel/3.10.0-957.el7.x86_64 os/linux arch/amd64 UpstreamClient(Docker-Client/18.09.5 \x5C(linux\x5C))" 0.025 0.025 .
May  6 15:21:24 x.x.x.x proxy[xxxx]: x.x.x.x - "GET /v2/ HTTP/1.1" 200 2 "-" "docker/18.09.5 go/go1.10.8 git-commit/e8ff056 kernel/3.10.0-957.el7.x86_64 os/linux arch/amd64 UpstreamClient(Docker-Client/18.09.5 \x5C(linux\x5C))" 0.004 0.004 .
```

harbor core proxy入口：

```go
beego.Router("/v2/*", &controllers.RegistryProxy{}, "*:Handle")
...
// Handle is the only entrypoint for incoming requests, all requests must go through this func.
func (p *RegistryProxy) Handle() {
	req := p.Ctx.Request
	rw := p.Ctx.ResponseWriter
	proxy.Handle(rw, req)
}
...
// Init initialize the Proxy instance and handler chain.
func Init(urls ...string) error {
	var err error
	var registryURL string
	if len(urls) > 1 {
		return fmt.Errorf("the parm, urls should have only 0 or 1 elements")
	}
	if len(urls) == 0 {
		registryURL, err = config.RegistryURL()
		if err != nil {
			return err
		}
	} else {
		registryURL = urls[0]
	}
	targetURL, err := url.Parse(registryURL)
	if err != nil {
		return err
	}
	Proxy = httputil.NewSingleHostReverseProxy(targetURL)
	handlers = handlerChain{head: readonlyHandler{next: urlHandler{next: listReposHandler{next: contentTrustHandler{next: vulnerableHandler{next: Proxy}}}}}}
	return nil
}

// Handle handles the request.
func Handle(rw http.ResponseWriter, req *http.Request) {
	handlers.head.ServeHTTP(rw, req)
}
```

这里会经过5层handler，最后到达proxy，也即：`docker distribution`

* 1、访问`docker distribution`，获取`auth server`地址

```
May  6 15:21:24 x.x.x.x proxy[xxxx]: x.x.x.x - "GET /v2/ HTTP/1.1" 401 87 "-" "docker/18.09.5 go/go1.10.8 git-commit/e8ff056 kernel/3.10.0-957.el7.x86_64 os/linux arch/amd64 UpstreamClient(Docker-Client/18.09.5 \x5C(linux\x5C))" 0.008 0.008 .
```

`/v2/`请求会直接到`docker distribution`，根据[v2 token](https://docs.docker.com/registry/spec/auth/token/)协议返回401，并在报头`Www-Authenticate`中返回token服务器地址进行后续认证，如下：

```
HTTP/1.1 401 Unauthorized
Content-Type: application/json; charset=utf-8
Docker-Distribution-Api-Version: registry/2.0
Www-Authenticate: Bearer realm="http://x.x.x.x/service/token",service="harbor-registry"
Date: Mon, 06 May 2019 07:57:46 GMT
Content-Length: 87

{"errors":[{"code":"UNAUTHORIZED","message":"authentication required","detail":null}]}
```

* 2、访问`token server`获取`token`

```
May  6 15:21:24 x.x.x.x proxy[xxxx]: x.x.x.x - "GET /service/token?account=xxx&client_id=docker&offline_token=true&service=harbor-registry HTTP/1.1" 200 893 "-" "docker/18.09.5 go/go1.10.8 git-commit/e8ff056 kernel/3.10.0-957.el7.x86_64 os/linux arch/amd64 UpstreamClient(Docker-Client/18.09.5 \x5C(linux\x5C))" 0.025 0.025 .
```

```
GET /service/token?account=xxx&client_id=docker&offline_token=true&service=harbor-registry HTTP/1.1
Host: x.x.x.x
User-Agent: docker/18.09.5 go/go1.10.8 git-commit/e8ff056 kernel/3.10.0-957.el7.x86_64 os/linux arch/amd64 UpstreamClient(Docker-Client/18.09.5 \(linux\))
Authorization: Basic xxxxxxxxxxxxxx
Accept-Encoding: gzip
Connection: close
```

根据路由：

```go
beego.Router("/service/token", &token.Handler{})
...
// Handler handles request on /service/token, which is the auth provider for registry.
type Handler struct {
	beego.Controller
}

// Get handles GET request, it checks the http header for user credentials
// and parse service and scope based on docker registry v2 standard,
// checkes the permission against local DB and generates jwt token.
func (h *Handler) Get() {
	request := h.Ctx.Request
	log.Debugf("URL for token request: %s", request.URL.String())
	service := h.GetString("service")
	tokenCreator, ok := creatorMap[service]
	if !ok {
		errMsg := fmt.Sprintf("Unable to handle service: %s", service)
		log.Errorf(errMsg)
		h.CustomAbort(http.StatusBadRequest, errMsg)
	}
	token, err := tokenCreator.Create(request)
	if err != nil {
		if _, ok := err.(*unauthorizedError); ok {
			h.CustomAbort(http.StatusUnauthorized, "")
		}
		log.Errorf("Unexpected error when creating the token, error: %v", err)
		h.CustomAbort(http.StatusInternalServerError, "")
	}
	h.Data["json"] = token
	h.ServeJSON()

}
...
const (
	// Notary service
	Notary = "harbor-notary"
	// Registry service
	Registry = "harbor-registry"
)

// InitCreators initialize the token creators for different services
func InitCreators() {
	creatorMap = make(map[string]Creator)
	registryFilterMap = map[string]accessFilter{
		"repository": &repositoryFilter{
			parser: &basicParser{},
		},
		"registry": &registryFilter{},
	}
	ext, err := config.ExtURL()
	if err != nil {
		log.Warningf("Failed to get ext url, err: %v, the token service will not be functional with notary requests", err)
	} else {
		notaryFilterMap = map[string]accessFilter{
			"repository": &repositoryFilter{
				parser: &endpointParser{
					endpoint: ext,
				},
			},
		}
		creatorMap[Notary] = &generalCreator{
			service:   Notary,
			filterMap: notaryFilterMap,
		}
	}

	creatorMap[Registry] = &generalCreator{
		service:   Registry,
		filterMap: registryFilterMap,
	}
}
```

根据service值:`harbor-registry`，会跳转到`generalCreator`的`Create`，如下：

```go
func (g generalCreator) Create(r *http.Request) (*models.Token, error) {
	var err error
	scopes := parseScopes(r.URL)
	log.Debugf("scopes: %v", scopes)

	ctx, err := filter.GetSecurityContext(r)
	if err != nil {
		return nil, fmt.Errorf("failed to  get security context from request")
	}

	pm, err := filter.GetProjectManager(r)
	if err != nil {
		return nil, fmt.Errorf("failed to  get project manager from request")
	}

	// for docker login
	if !ctx.IsAuthenticated() {
		if len(scopes) == 0 {
			return nil, &unauthorizedError{}
		}
	}
	access := GetResourceActions(scopes)
	err = filterAccess(access, ctx, pm, g.filterMap)
	if err != nil {
		return nil, err
	}
	return MakeToken(ctx.GetUsername(), g.service, access)
}
```

**这里会用到harbor的认证和鉴权如下：**

```go
func setSecurCtxAndPM(req *http.Request, ctx security.Context, pm promgr.ProjectManager) {
	addToReqContext(req, SecurCtxKey, ctx)
	addToReqContext(req, PmKey, pm)
}

func addToReqContext(req *http.Request, key, value interface{}) {
	*req = *(req.WithContext(context.WithValue(req.Context(), key, value)))
}

// GetSecurityContext tries to get security context from request and returns it
func GetSecurityContext(req *http.Request) (security.Context, error) {
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}

	ctx := req.Context().Value(SecurCtxKey)
	if ctx == nil {
		return nil, fmt.Errorf("the security context got from request is nil")
	}

	c, ok := ctx.(security.Context)
	if !ok {
		return nil, fmt.Errorf("the variable got from request is not security context type")
	}

	return c, nil
}

// GetProjectManager tries to get project manager from request and returns it
func GetProjectManager(req *http.Request) (promgr.ProjectManager, error) {
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}

	pm := req.Context().Value(PmKey)
	if pm == nil {
		return nil, fmt.Errorf("the project manager got from request is nil")
	}

	p, ok := pm.(promgr.ProjectManager)
	if !ok {
		return nil, fmt.Errorf("the variable got from request is not project manager type")
	}

	return p, nil
}
```

对于`docker login`，若没有认证成功，则返回认证失败；对于`docker pull`、`docker push`等操作，则会进行鉴权，如下：

```go
// filterAccess iterate a list of resource actions and try to use the filter that matches the resource type to filter the actions.
func filterAccess(access []*token.ResourceActions, ctx security.Context,
	pm promgr.ProjectManager, filters map[string]accessFilter) error {
	var err error
	for _, a := range access {
		f, ok := filters[a.Type]
		if !ok {
			a.Actions = []string{}
			log.Warningf("No filter found for access type: %s, skip filter, the access of resource '%s' will be set empty.", a.Type, a.Name)
			continue
		}
		err = f.filter(ctx, pm, a)
		log.Debugf("user: %s, access: %v", ctx.GetUsername(), a)
		if err != nil {
			return err
		}
	}
	return nil
}

const (
	// Notary service
	Notary = "harbor-notary"
	// Registry service
	Registry = "harbor-registry"
)

// InitCreators initialize the token creators for different services
func InitCreators() {
	creatorMap = make(map[string]Creator)
	registryFilterMap = map[string]accessFilter{
		"repository": &repositoryFilter{
			parser: &basicParser{},
		},
		"registry": &registryFilter{},
	}
	ext, err := config.ExtURL()
	if err != nil {
		log.Warningf("Failed to get ext url, err: %v, the token service will not be functional with notary requests", err)
	} else {
		notaryFilterMap = map[string]accessFilter{
			"repository": &repositoryFilter{
				parser: &endpointParser{
					endpoint: ext,
				},
			},
		}
		creatorMap[Notary] = &generalCreator{
			service:   Notary,
			filterMap: notaryFilterMap,
		}
	}

	creatorMap[Registry] = &generalCreator{
		service:   Registry,
		filterMap: registryFilterMap,
	}
}

// An accessFilter will filter access based on userinfo
type accessFilter interface {
	filter(ctx security.Context, pm promgr.ProjectManager, a *token.ResourceActions) error
}

type registryFilter struct {
}

func (reg registryFilter) filter(ctx security.Context, pm promgr.ProjectManager,
	a *token.ResourceActions) error {
	// Do not filter if the request is to access registry catalog
	if a.Name != "catalog" {
		return fmt.Errorf("Unable to handle, type: %s, name: %s", a.Type, a.Name)
	}
	if !ctx.IsSysAdmin() {
		// Set the actions to empty is the user is not admin
		a.Actions = []string{}
	}
	return nil
}

// repositoryFilter filters the access based on Harbor's permission model
type repositoryFilter struct {
	parser imageParser
}

func (rep repositoryFilter) filter(ctx security.Context, pm promgr.ProjectManager,
	a *token.ResourceActions) error {
	// clear action list to assign to new acess element after perm check.
	img, err := rep.parser.parse(a.Name)
	if err != nil {
		return err
	}
	projectName := img.namespace
	permission := ""

	exist, err := pm.Exists(projectName)
	if err != nil {
		return err
	}
	if !exist {
		log.Debugf("project %s does not exist, set empty permission", projectName)
		a.Actions = []string{}
		return nil
	}

	resource := rbac.NewProjectNamespace(projectName).Resource(rbac.ResourceRepository)
	if ctx.Can(rbac.ActionPush, resource) && ctx.Can(rbac.ActionPull, resource) {
		permission = "RWM"
	} else if ctx.Can(rbac.ActionPush, resource) {
		permission = "RW"
	} else if ctx.Can(rbac.ActionPull, resource) {
		permission = "R"
	}

	a.Actions = permToActions(permission)
	return nil
}

func permToActions(p string) []string {
	res := []string{}
	if strings.Contains(p, "W") {
		res = append(res, "push")
	}
	if strings.Contains(p, "M") {
		res = append(res, "*")
	}
	if strings.Contains(p, "R") {
		res = append(res, "pull")
	}
	return res
}
```

按照逻辑是会返回一个`token`，如下：

```go
// MakeToken makes a valid jwt token based on parms.
func MakeToken(username, service string, access []*token.ResourceActions) (*models.Token, error) {
	pk, err := libtrust.LoadKeyFile(privateKey)
	if err != nil {
		return nil, err
	}
	expiration, err := config.TokenExpiration()
	if err != nil {
		return nil, err
	}

	tk, expiresIn, issuedAt, err := makeTokenCore(issuer, username, service, expiration, access, pk)
	if err != nil {
		return nil, err
	}
	rs := fmt.Sprintf("%s.%s", tk.Raw, base64UrlEncode(tk.Signature))
	return &models.Token{
		Token:     rs,
		ExpiresIn: expiresIn,
		IssuedAt:  issuedAt.Format(time.RFC3339),
	}, nil
}
```

数据如下：

```
{"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IlBZWU86VEVXVTpWN0pIOjI2SlY6QVFUWjpMSkMzOlNYVko6WEdIQTozNEYyOjJMQVE6WlJNSzpaN1E2In0.eyJpc3MiOiJhdXRoLmRvY2tlci5jb20iLCJzdWIiOiJqbGhhd24iLCJhdWQiOiJyZWdpc3RyeS5kb2NrZXIuY29tIiwiZXhwIjoxNDE1Mzg3MzE1LCJuYmYiOjE0MTUzODcwMTUsImlhdCI6MTQxNTM4NzAxNSwianRpIjoidFlKQ08xYzZjbnl5N2tBbjBjN3JLUGdiVjFIMWJGd3MiLCJhY2Nlc3MiOlt7InR5cGUiOiJyZXBvc2l0b3J5IiwibmFtZSI6InNhbWFsYmEvbXktYXBwIiwiYWN0aW9ucyI6WyJwdXNoIl19XX0.QhflHPfbd6eVF4lM9bwYpFZIV0PfikbyXuLx959ykRTBpe3CYnzs6YBK8FToVb5R47920PVLrh8zuLzdCr9t3w", "expires_in": 3600,"issued_at": "2019-8-2T23:00:00Z"}
```

* 3、携带`token`访问`docker distribution`

```
May  6 15:21:24 x.x.x.x proxy[xxxx]: x.x.x.x - "GET /v2/ HTTP/1.1" 200 2 "-" "docker/18.09.5 go/go1.10.8 git-commit/e8ff056 kernel/3.10.0-957.el7.x86_64 os/linux arch/amd64 UpstreamClient(Docker-Client/18.09.5 \x5C(linux\x5C))" 0.004 0.004 .
```

```
GET /v2/ HTTP/1.1
Host: x.x.x.x
User-Agent: docker/18.09.5 go/go1.10.8 git-commit/e8ff056 kernel/3.10.0-957.el7.x86_64 os/linux arch/amd64 UpstreamClient(Docker-Client/18.09.5 \(linux\))
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IlBZWU86VEVXVTpWN0pIOjI2SlY6QVFUWjpMSkMzOlNYVko6WEdIQTozNEYyOjJMQVE6WlJNSzpaN1E2In0.eyJpc3MiOiJhdXRoLmRvY2tlci5jb20iLCJzdWIiOiJqbGhhd24iLCJhdWQiOiJyZWdpc3RyeS5kb2NrZXIuY29tIiwiZXhwIjoxNDE1Mzg3MzE1LCJuYmYiOjE0MTUzODcwMTUsImlhdCI6MTQxNTM4NzAxNSwianRpIjoidFlKQ08xYzZjbnl5N2tBbjBjN3JLUGdiVjFIMWJGd3MiLCJhY2Nlc3MiOlt7InR5cGUiOiJyZXBvc2l0b3J5IiwibmFtZSI6InNhbWFsYmEvbXktYXBwIiwiYWN0aW9ucyI6WyJwdXNoIl19XX0.QhflHPfbd6eVF4lM9bwYpFZIV0PfikbyXuLx959ykRTBpe3CYnzs6YBK8FToVb5R47920PVLrh8zuLzdCr9t3w
Accept-Encoding: gzip
Connection: close
```

## Refs 

* [token protocol](https://docs.docker.com/registry/spec/auth/token/)
* [jeremyxu2010](https://jeremyxu2010.github.io/2018/09/harbor%E6%BA%90%E7%A0%81%E8%A7%A3%E8%AF%BB/)