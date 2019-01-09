package until

import (
	"bytes"
	"errors"
	"strings"
	"github.com/spf13/viper"
	"log"
	"ihub/logging"
	"fmt"
)

const (
	cmdRoot   = "ihub"
	DefaultServerAddr = "0.0.0.0"
	DefaultServerPort = 8090
	DefaultServerID   = "1"

	logModule0 = "main"
	logModule1 = "until"
	logModule2 = "server"
	logModule3 = "dbutil"

)

type ServiceType struct {
	Addr string
	Port int
	Id   string
}

type ServerTLSConfig struct {
	Enabled  bool
	CertFile string
	KeyFile  string
	CaCert   string
}

type ConfigDB struct {
	Type       string
	Datasource string
	TLS        ServerTLSConfig
}

type ServiceConfig struct {
	Service    ServiceType
	TLSOpts    ServerTLSConfig
	DB         ConfigDB
}

type Config struct {
	restSecConfig       *ServiceConfig
	restSecConfigCached bool
	configViper         *viper.Viper
}

var GlobalLoglevel logging.Level

func setLogLevel(myViper *viper.Viper) (logging.Level) {
	loggingLevelString := myViper.GetString("logging.level")
	logLevel := logging.INFO
	if loggingLevelString != "" {
		var err error
		logLevel, err = logging.LogLevel(loggingLevelString)
		if err != nil {
			panic(err)
		}
	}

	logging.SetLevel(logModule0, logLevel)
	logging.SetLevel(logModule1, logLevel)
	logging.SetLevel(logModule2, logLevel)
	logging.SetLevel(logModule3, logLevel)
	return logLevel
}

func InitConfigByType(configBytes []byte, configFile string, configType string) (*Config, error) {
	myViper := viper.New()
	myViper.SetEnvPrefix(cmdRoot)
	myViper.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	myViper.SetEnvKeyReplacer(replacer)

	if configType == "" {
		return nil, errors.New("empty config type")
	}

	if len(configBytes) > 0 {
		buf := bytes.NewBuffer(configBytes)
		log.Printf("buf Len is %d, Cap is %d: %s\n", buf.Len(), buf.Cap(), buf)
		myViper.SetConfigType(configType)
		myViper.ReadConfig(buf)
	} else {
		if configFile != "" {
			myViper.SetConfigFile(configFile)
			err := myViper.ReadInConfig()

			if err == nil {
				log.Printf("Using config file: %s\n", myViper.ConfigFileUsed())
			} else {
			    return nil, errors.New( "loading config file failed")
			}
		}
	}

	GlobalLoglevel = setLogLevel(myViper)
	return &Config{configViper: myViper}, nil
}

func (c *Config) cacheResSecConfiguration() error {
	c.restSecConfig = new(ServiceConfig)

	err := c.configViper.UnmarshalKey("service", &c.restSecConfig.Service)
	log.Printf("Service are: %+v\n", c.restSecConfig.Service)
	if err != nil {
		return err
	}

	err = c.configViper.UnmarshalKey("tls", &c.restSecConfig.TLSOpts)
	log.Printf("TLSOpts are: %+v\n", c.restSecConfig.TLSOpts)
	if err != nil {
		return err
	}

	err = c.configViper.UnmarshalKey("db", &c.restSecConfig.DB)
	log.Printf("DB are: %+v\n", c.restSecConfig.DB)
	if err != nil {
		return err
	}

	c.restSecConfigCached = true
	return err
}

func (c *Config) RestSecConfig() (*ServiceConfig, error) {
	if c.restSecConfigCached {
		return c.restSecConfig, nil
	}

	if err := c.cacheResSecConfiguration(); err != nil {
		return nil, errors.New( "network configuration load failed")
	}
	return c.restSecConfig, nil
}

func (c *Config) RestService() (string, int, string, error) {
	config, err := c.RestSecConfig()
	if err != nil {
		return "", 0, "", err
	}

	if config.Service.Addr == "" {
		config.Service.Addr = DefaultServerAddr
	}

	if config.Service.Port < 0 {
		config.Service.Port = DefaultServerPort
	}

	if config.Service.Id == "" {
		config.Service.Id = DefaultServerID
	}
	return config.Service.Addr, config.Service.Port, config.Service.Id, nil
}

func (c *Config) TLSOpts() (*ServerTLSConfig, error) {
	config, err := c.RestSecConfig()
	if  err != nil {
		return nil, err
	}

	if config.TLSOpts.Enabled == true {
		if config.TLSOpts.CaCert == "" ||
			config.TLSOpts.KeyFile == "" ||
			config.TLSOpts.CertFile == "" {
			return nil, fmt.Errorf("%s", "cacert, keyfile, certfile is nil." )
		}
	}

	return &config.TLSOpts, nil
}


func (c *Config) DBConfig() (*ConfigDB, error) {
	config, err := c.RestSecConfig()
	if err != nil {
		return nil, err
	}

	if config.DB.Type != "mysql" {
		config.DB.Type = "mysql"
	}

	if config.DB.Datasource == "" {
		config.DB.Datasource = "root:123456@tcp(0.0.0.0:3305)/joors?parseTime=true"
	}

	if config.DB.TLS.Enabled == true {
		if config.TLSOpts.CaCert == "" ||
			config.TLSOpts.KeyFile == "" ||
			config.TLSOpts.CertFile == "" {
			return nil, fmt.Errorf("%s", "cacert, keyfile, certfile is nil." )
		}
	}

	return &config.DB, nil
}
