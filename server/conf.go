package server

type ServerBaseConfig  struct {
	Port int
	Address string
	ServerId string
}

type ServerTLSConfig struct {
	Enabled  bool
	CertFile string
	KeyFile  string
	CaCert string
}

type CAConfigDB struct {
	Type       string
	Datasource string
	TLS        ServerTLSConfig
}

type ServerConfig struct {
	BaseCfg ServerBaseConfig
	Debug bool
	TLS ServerTLSConfig
	DB  CAConfigDB
}

