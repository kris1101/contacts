package server

import (
	"fmt"
	"net"
	"sync"
	"strconv"
	"context"
	"errors"
	"os/signal"
	"net/http"
	"crypto/tls"
	"crypto/x509"
	"time"
	"os"
	"io/ioutil"
	"syscall"
	"strings"
	until "ihub/until"
	"ihub/logging"
	"github.com/gorilla/mux"
	"net/http/pprof"
	"github.com/gin-gonic/gin"
	agent "github.com/google/gops/agent"
	"ihub/dbutil"
)

const (
	logModule = "server"
)

var logger = logging.NewLogger(logModule)

const (
	ServerProfilePort = "SERVER_PROFILE_PORT"
)

type SrvHttp struct {
	HomeDir        string
	BlockingStart  bool
	RestConfigFile string
	Config     *ServerConfig

	db *dbutil.DB
	listener   net.Listener
	serveError error
	wait       chan bool
	signal     chan os.Signal

	mutex sync.Mutex
	TokenConf *MW_Token
	Router    http.Handler
	Server    *http.Server
}

func NewServer(homeDir string,
	blockStarting bool,
	restConfigFile string) *SrvHttp {

	server := &SrvHttp{
		HomeDir:        homeDir,
		BlockingStart:  blockStarting,
		RestConfigFile: restConfigFile,
	}
	return server
}

func (s *SrvHttp) InitTokenSrv(isToken bool) error {
	s.TokenConf = new(MW_Token)
	s.TokenConf.AuthType = noAuth
	return nil
}

func (s *SrvHttp) Start() error {
	s.serveError = nil

	if s.listener != nil {
		return errors.New("server is already started")
	}

	err := s.init()
	if err != nil {
		return err
	}

	s.addRoute()
	return s.listenAndServe()
}

func (s *SrvHttp) initConfig() error {
	var err error = nil
	if s.HomeDir == "" {
		s.HomeDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("Failed to get server's home directory: %s", err)
		}
	}

	restConfig, err := until.InitConfigByType(nil, s.RestConfigFile, "yaml")
	if err != nil {
		logger.Error("InitConfigByType Err ",err.Error())
		return err
	}

	if s.Config == nil {
		s.Config = new(ServerConfig)
	}
	baseCfg := &s.Config.BaseCfg
	baseCfg.Address, baseCfg.Port, baseCfg.ServerId, err = restConfig.RestService()
	if err != nil {
		logger.Error("RestService Err ", err.Error())
		return err
	}
	logger.Debugf("server add:%s port:%d id:%s", baseCfg.Address, baseCfg.Port, baseCfg.ServerId)

	tlsCfg := s.Config.TLS
	tlsOpts, err := restConfig.TLSOpts()
	if err != nil {
		logger.Error(err.Error())
		return err
	}
	tlsCfg.Enabled = tlsOpts.Enabled
	tlsCfg.CertFile = tlsOpts.CertFile
	tlsCfg.KeyFile = tlsOpts.KeyFile
	tlsCfg.CaCert = tlsOpts.CaCert

	db := &s.Config.DB
	dbCfg, err := restConfig.DBConfig()
	if err != nil {
		logger.Error(err.Error())
		return err
	}
	db.Type = dbCfg.Type
	db.Datasource = dbCfg.Datasource
	db.TLS.Enabled = dbCfg.TLS.Enabled
	db.TLS.CertFile = dbCfg.TLS.CertFile
	db.TLS.KeyFile = dbCfg.TLS.KeyFile
	db.TLS.CaCert = dbCfg.TLS.CaCert
	return nil
}

func (s *SrvHttp) initDB() error {
	logger.Debug("Initializing DB")

	if s.db != nil && s.db.IsInitialized() {
		return nil
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// After obtaining a lock, check again to see if DB got initialized by another process
	if s.db != nil && s.db.IsInitialized() {
		return nil
	}

	db := &s.Config.DB
	var err error

	ds := db.Datasource
	ds = dbutil.MaskDBCred(ds)
	logger.Debugf("Initializing '%s' database at '%s'", db.Type, ds)


	switch db.Type {
	case "mysql":
		s.db, err = dbutil.NewUserRegistryMySQL(db.Datasource, db.TLS.Enabled, db.TLS.CaCert, db.TLS.KeyFile, db.TLS.CertFile)
		if err != nil {
			return fmt.Errorf("Failed to create user registry for MySQL %s", err.Error())
		}
	default:
		return fmt.Errorf("Invalid db.type in config file: '%s'; must be  'tidb', or 'mysql'", db.Type)
	}

	s.db.IsDBInitialized = true
	logger.Infof("Initialized %s database at %s", db.Type, ds)

	return nil
}

func (s *SrvHttp) init() error {
	err := s.initConfig()
	if err != nil {
		logger.Errorf("initConfig init err %s\n", err.Error())
		return err
	}

	err = s.initDB()
	if err != nil {
		logger.Errorf("initConfig init err %s\n", err.Error())
		return err
	}

	err = s.InitTokenSrv(true)
	if err != nil {
		logger.Errorf("InitTokenSrv init err %s\n", err.Error())
		return err
	}


	return nil
}

func (s *SrvHttp) addRoute() {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	api := router.Group("/")
	apiauth := router.Group("/auth") //注册　登录　忘记密码　修改密码
	apicontact :=  router.Group("/contact") //通讯录
	apisafe := router.Group("/safe") //验证器
	apilive := router.Group("/live") //生息规则
	apihelp := router.Group("/help") //帮助中心
	apisoft := router.Group("/soft") //软件升级

	//add token middleware
	api.Use(s.TokenConf.Handle_NoAuth)
	{
		api.POST("/echo", s.POST_Echo)
	}

	apiauth.Use(s.TokenConf.Handle_NoAuth)
	{
		apiauth.POST("/user/register", s.POST_Register)
		apiauth.POST("/user/login", s.POST_Login)
		apiauth.POST("/user/forgetpwd", s.POST_ForgetPwd)
		apiauth.POST("/user/modifypwd", s.POST_ModifyPwd)
	}

	apicontact.Use(s.TokenConf.Handle_NoAuth)
	{
		apicontact.POST("/contact/list/add", s.POST_ContactAdd)
		apicontact.POST("/contact/list/del", s.POST_ContactDel)
		apicontact.POST("/contact/list/update", s.POST_ContactUpdate)
		apicontact.POST("/contact/list/getlist", s.POST_ContactGetList)
	}

	apisafe.Use(s.TokenConf.Handle_NoAuth) //google验证器　validator
	{
		apisafe.POST("/validator/randprikey", s.POST_RandPriKey) //随机生成私钥
		apisafe.POST("/validator/check", s.POST_Check) //验证code
	}

	apilive.Use(s.TokenConf.Handle_NoAuth)//生息规则
	{
		apilive.POST("/live/get/rules", s.POST_GetLiveRules) //生息规则
		apilive.POST("/live/set/rules", s.POST_SetLiveRules)
	}

	apihelp.Use(s.TokenConf.Handle_NoAuth)//帮助中心服务
	{
		apihelp.POST("/help/get/wallet", s.POST_GetWallet) //获取什么是钱包数据
		apihelp.POST("/help/set/wallet", s.POST_SetWallet) //设置什么是钱包数据
	}

	apisoft.Use(s.TokenConf.Handle_NoAuth)//软件版本升级
	{
		apisoft.POST("/soft/get/ver", s.POST_GetSoftVer) //获取最新软件版本
		apisoft.POST("/soft/set/ver", s.POST_SetSoftVer) //设置最新软件版本
	}

	s.Router = router
}

func (s *SrvHttp) checkAndEnableProfiling() error {
	pport := os.Getenv(ServerProfilePort)
	if pport != "" {
		iport, err := strconv.Atoi(pport)
		if err != nil || iport < 0 {
			logger.Errorf("Profile port specified by the %s environment variable is not a valid port, not enabling profiling",
				ServerProfilePort)
		} else {
			addr := net.JoinHostPort(s.Config.BaseCfg.Address, pport)
			listener, err1 := net.Listen("tcp", addr)
			logger.Infof("Profiling enabled; listening for profile requests on port %s", pport)
			if err1 != nil {
				return err1
			}
			go func() {
				r := mux.NewRouter()
				r.HandleFunc("/debug/pprof/", pprof.Index)
				r.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
				r.HandleFunc("/debug/pprof/profile", pprof.Profile)
				r.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
				r.HandleFunc("/debug/pprof/trace", pprof.Trace)

				logger.Debugf("Profiling enabled; waiting for profile requests on port %s", pport)
				http.Serve(listener, nil)
				logger.Errorf("Stopped serving for profiling requests on port %s: %s", pport, err)
			}()


			go func(port int) {
				sport := strconv.Itoa(iport+1)
				opt := agent.Options{Addr:strings.Join([]string{"0.0.0.0", sport},":"), ShutdownCleanup:false}
				if err := agent.Listen(opt); err != nil {
					logger.Fatal(err)
				}
			}(iport)
		}
	}
	return nil
}

// Starting listening and serving
func (s *SrvHttp) listenAndServe() (err error) {
	var listener net.Listener
	var exitErr error = nil
	c := s.Config

	addr := net.JoinHostPort(c.BaseCfg.Address, strconv.Itoa(c.BaseCfg.Port))
	var addrStr string

	if c.TLS.Enabled {
		logger.Debug("TLS is enabled")
		addrStr = fmt.Sprintf("https://%s", addr)

		pool := x509.NewCertPool()
		caCert, err := ioutil.ReadFile(c.TLS.CaCert)
		if err != nil {
			logger.Errorf("%s", err.Error())
			return err
		}
		pool.AppendCertsFromPEM(caCert)

		cert, err := tls.LoadX509KeyPair(c.TLS.CertFile, c.TLS.KeyFile)
		if err != nil {
			logger.Errorf("%s", err.Error())
			return err
		}
		config := &tls.Config{
			ClientCAs:  pool,
			ClientAuth: tls.RequireAndVerifyClientCert,

			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS10,
			MaxVersion:   tls.VersionTLS12,
		}

		listener, err = tls.Listen("tcp", addr, config)
		if err != nil {
			return fmt.Errorf("TLS listen failed for %s: %s", addrStr, err)
		}

	} else {
		addrStr = fmt.Sprintf("http://%s", addr)
		listener, err = net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("TCP listen failed for %s: %s", addrStr, err)
		}
	}

	s.listener = listener
	logger.Infof("Listening on %s", addrStr)

	err = s.checkAndEnableProfiling()
	if err != nil {
		s.closeListener()
		return fmt.Errorf("TCP listen for profiling failed: %s", err)
	}

	// Start serving requests, either blocking or non-blocking
	err = s.srvInit()
	if err != nil {
		s.closeListener()
		return fmt.Errorf("TCP listen for profiling failed: %s", err)
	}

	if s.BlockingStart {
		exitErr = s.serve()
		if exitErr != nil {
			logger.Errorf("Server has stopped serving: %s", exitErr.Error())
		}
		s.closeListener()
	} else {
		go func(){
			exitErr = s.serve()
			if exitErr != nil {
				logger.Errorf("Server has stopped serving: %s", exitErr.Error())
			}
			s.closeListener()
		}()
	}

	<-s.wait
	return nil
}

// closeListener closes the listening endpoint
func (s *SrvHttp) closeListener() error {
	port := s.Config.BaseCfg.Port
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.Server.Close()
	if s.listener == nil {
		msg := fmt.Sprintf("Stop: listener was already closed on port %d", port)
		logger.Errorf("%s", msg)
		return fmt.Errorf(msg)
	} else {
		err := s.listener.Close()
		s.listener = nil
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				logger.Debugf("Stop: successfully closed listener on port %d", port)
				return nil
			} else {
				logger.Errorf("Stop: failed to close listener on port %d: %s", port, err.Error())
				return err
			}
		}
	}
	logger.Debugf("Stop: successfully closed listener on port %d", port)
	return nil
}

func (s *SrvHttp) srvInit() error {
	listener := s.listener
	if listener == nil {
		return nil
	}

	s.wait = make(chan bool)
	s.signal = make(chan os.Signal)
	signal.Notify(s.signal, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2)

	s.Server = &http.Server{
		Handler:        s.Router,
		ReadTimeout:    1000 * time.Second,
		WriteTimeout:   1000 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	go func(server *http.Server, wait chan bool) {
		for sig := range s.signal {
			switch sig {
			case syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
				signal.Stop(s.signal)

				ctx, cancel := context.WithTimeout(context.Background(), 20 * time.Second)
				defer cancel()

				if err := server.Shutdown(ctx); err != nil {
					logger.Errorf("Server Shutdown:", err)
				}
				logger.Errorf("Server exiting.............................")

				//server.Close()
				if wait != nil {
					wait <- true
				}

				logger.Errorf("revice signal %v", sig)
			default:
				logger.Errorf("revice other signal %v", sig)
			}
		}
	}(s.Server, s.wait)

	return nil
}

func (s *SrvHttp) serve() (error) {
	s.serveError = s.Server.Serve(s.listener)
	return s.serveError
}

