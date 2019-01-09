package dbutil

import (
	"github.com/jmoiron/sqlx"
	"regexp"
	"github.com/go-sql-driver/mysql"
	"strings"
	"ihub/logging"
	"errors"
	"fmt"
	"io/ioutil"
	"crypto/tls"
	"crypto/x509"
	"time"
	"encoding/pem"
)

const (
	logModule = "dbutil"
)

var logger = logging.NewLogger(logModule)

var (
	dbURLRegex = regexp.MustCompile("(Datasource:\\s*)?(\\S+):(\\S+)@|(Datasource:.*\\s)?(user=\\S+).*\\s(password=\\S+)|(Datasource:.*\\s)?(password=\\S+).*\\s(user=\\S+)")
)

type DB struct {
	*sqlx.DB
	IsDBInitialized bool
}

func getDBName(datasource string) string {
	var dbName string
	datasource = strings.ToLower(datasource)

	re := regexp.MustCompile(`(?:\/([^\/?]+))|(?:dbname=([^\s]+))`)
	getName := re.FindStringSubmatch(datasource)
	if getName != nil {
		dbName = getName[1]
		if dbName == "" {
			dbName = getName[2]
		}
	}

	return dbName
}

func (db *DB) IsInitialized() bool {
	return db.IsDBInitialized
}

func MaskDBCred(str string) string {
	matches := dbURLRegex.FindStringSubmatch(str)
	// If there is a match, there should be three entries: 1 for
	// the match and 9 for submatches (see dbURLRegex regular expression)
	if len(matches) == 10 {
		matchIdxs := dbURLRegex.FindStringSubmatchIndex(str)
		substr := str[matchIdxs[0]:matchIdxs[1]]
		for idx := 1; idx < len(matches); idx++ {
			if matches[idx] != "" {
				if strings.Index(matches[idx], "user=") == 0 {
					substr = strings.Replace(substr, matches[idx], "user=****", 1)
				} else if strings.Index(matches[idx], "password=") == 0 {
					substr = strings.Replace(substr, matches[idx], "password=****", 1)
				} else {
					substr = strings.Replace(substr, matches[idx], "****", 1)
				}
			}
		}
		str = str[:matchIdxs[0]] + substr + str[matchIdxs[1]:len(str)]
	}
	return str
}

func createMySQLDatabase(dbName string, db *sqlx.DB) error {
	logger.Debugf("Creating MySQL Database (%s) if it does not exist...", dbName)

	_, err := db.Exec("CREATE DATABASE IF NOT EXISTS " + dbName)
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to execute create database query %s", err.Error()))
	}

	return nil
}

func createMySQLTables(dbName string, db *sqlx.DB) error {
	logger.Debug("Creating users table if it doesn't exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS users (id VARCHAR(255) NOT NULL, uname VARCHAR(128), pwd VARCHAR(128), token  VARCHAR(256), time INTEGER, PRIMARY KEY (id)) DEFAULT CHARSET=utf8 COLLATE utf8_bin"); err != nil {
		return errors.New(fmt.Sprintf("Error creating users table %s", err.Error()))
	}

	logger.Debug("Creating liverules table if it doesn't exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS liverules (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, rules VARCHAR(1024))"); err != nil {
		return errors.New(fmt.Sprintf("Error creating liverules table %s", err.Error()))
	}

	logger.Debug("Creating help table if it doesn't exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS help (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, name VARCHAR(1024), content VARCHAR(2048))"); err != nil {
		return errors.New(fmt.Sprintf("Error creating help table %s", err.Error()))
	}

	logger.Debug("Creating soft table if it doesn't exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS soft (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, os VARCHAR(30), ver VARCHAR(30), downurl VARCHAR(1024))"); err != nil {
		return errors.New(fmt.Sprintf("Error creating soft table %s", err.Error()))
	}

	logger.Debug("Creating contacts table if it doesn't exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS contacts (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, name VARCHAR(30), cphone VARCHAR(11), wallet_addr VARCHAR(42), remarks varchar(600))"); err != nil {
		return errors.New(fmt.Sprintf("Error creating contacts table %s", err.Error()))
	}

	logger.Debug("Creating users_contacts_rel table if it doesn't exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS users_contacts_rel (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, user_id int, contact_id int)"); err != nil {
		return errors.New(fmt.Sprintf("Error creating users_contacts_rel table %s", err.Error()))
	}

	return nil
}

func NewUserRegistryMySQL(datasource string, enabled bool, cacert string, key string, cert string) (*DB, error) {
	logger.Debugf("Using MySQL database, connecting to database...")

	dbName := getDBName(datasource)
	logger.Debugf("Database Name: %s", dbName)

	re := regexp.MustCompile(`\/([0-9,a-z,A-Z$_]+)`)
	connStr := re.ReplaceAllString(datasource, "/")

	if enabled {
		tlsConfig, err := GetClientTLSConfig(cacert, key, cert)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Failed to get client TLS for MySQL %s", err.Error()))
		}

		mysql.RegisterTLSConfig("custom", tlsConfig)
	}

	logger.Debugf("Connecting to MySQL server, using connection string: %s", MaskDBCred(connStr))
	db, err := sqlx.Open("mysql", connStr)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to open MySQL database %s", err.Error()))
	}

	err = db.Ping()
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to connect to MySQL database %s", err.Error()))
	}

	err = createMySQLDatabase(dbName, db)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to create MySQL database %s", err.Error()))
	}

	logger.Debugf("Connecting to database '%s', using connection string: '%s'", dbName, MaskDBCred(datasource))
	db, err = sqlx.Open("mysql", datasource)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to open database (%s) in MySQL server %s", dbName, err.Error()))
	}

	err = createMySQLTables(dbName, db)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to create MySQL tables %s", err.Error()))
	}

	return &DB{db, false}, nil
}

func GetX509CertificateFromPEM(cert []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(cert)
	if block == nil {
		return nil, errors.New("Failed to PEM decode certificate")
	}
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error parsing certificate %s", err.Error()))
	}
	return x509Cert, nil
}

func checkCertDates(certFile string) error {
	logger.Debug("Check client TLS certificate for valid dates")
	certPEM, err := ioutil.ReadFile(certFile)
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to read file '%s' %s", certFile, err.Error()))
	}

	cert, err := GetX509CertificateFromPEM(certPEM)
	if err != nil {
		return err
	}

	notAfter := cert.NotAfter
	currentTime := time.Now().UTC()

	if currentTime.After(notAfter) {
		return errors.New("Certificate provided has expired")
	}

	notBefore := cert.NotBefore
	if currentTime.Before(notBefore) {
		return errors.New("Certificate provided not valid until later date")
	}

	return nil
}

func GetClientTLSConfig(cacert string, key string, cert string) (*tls.Config, error) {
	var certs []tls.Certificate

	if cert != "" {
		err := checkCertDates(cert)
		if err != nil {
			return nil, err
		}

		clientCert, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, err
		}

		certs = append(certs, clientCert)
	} else {
		logger.Debug("Client TLS certificate and/or key file not provided")
	}
	rootCAPool := x509.NewCertPool()
	if len(cacert) == 0 {
		return nil, errors.New("No trusted root certificates for TLS were provided")
	}

	caCert, err := ioutil.ReadFile(cacert)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to read '%s' %s", cacert, err.Error()))
	}
	ok := rootCAPool.AppendCertsFromPEM(caCert)
	if !ok {
		return nil, errors.New(fmt.Sprintf("Failed to process certificate from file %s %s", cacert, err.Error()))
	}

	config := &tls.Config{
		Certificates: certs,
		RootCAs:      rootCAPool,
	}

	return config, nil
}