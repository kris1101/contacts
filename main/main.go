package main

import (
	"log"
	"os"
	"flag"
	"path"
	"strings"
	"path/filepath"
	"ihub/server"
	"ihub/logging"
	until "ihub/until"
)

const (
	logModule = "main"
)

var logger = logging.NewLogger(logModule)


func getCurrentDirectory() (string, error) {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return "", err
	}
	return strings.Replace(dir, "\\", "/", -1), nil
}


func main() {
	until.Rlimit_init()
	blocking := flag.Bool("blocking", true, "start rest server blocking")
	flag.Parse()

	homeDir, err := getCurrentDirectory()
	_ = homeDir
	if err != nil {
		log.Printf("getCurrentDirectory %s\n", err.Error())
		return
	}

	server := server.NewServer(
		"/home/golang/gopath/src/ihub/main",
		*blocking,
		path.Join("/home/golang/gopath/src/ihub/main", "config/ihub.yaml"),
	)

	err = server.Start()
	if err != nil {
		logger.Errorf("start failture  %s\n", err.Error())
		return
	}
}

/*
./ithub -blocking=true
./ithub -blocking=false

GODEBUG="gctrace=1" ./ithub
GODEBUG="schedtrace=1000" ./ithub
GODEBUG="schedtrace=1000,scheddetail=1" ./ithub
*/