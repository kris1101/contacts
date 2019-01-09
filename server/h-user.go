package server

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"encoding/json"
	. "ihub/protocol"
	"regexp"
)

var (
	imageRegExp  = regexp.MustCompile("^[a-z0-9A-Z]+(([._-][a-z0-9A-Z]+)+)?$")
)

func (server *SrvHttp) POST_Register(c *gin.Context) {
	var err error = nil
	response := "success"
	logger.Info("Chaincode request received")

	reqBody, err := ioutil.ReadAll(c.Request.Body)
	defer c.Request.Body.Close()
	if err != nil {
		response = fmt.Sprintf("failed to read http body error: %s", err.Error())
		logger.Error(response)
		ResponseLogicError(c, response)
		return
	}
	var register ReqRegister
	err = json.Unmarshal(reqBody, &register)
	if err != nil {
		response = fmt.Sprintf("unmarshal body error: %s", err.Error())
		logger.Error(response)
		ResponseLogicError(c, response)
		return
	}

	logger.Println("=================>",register)

	if err != nil {
		ResponseLogicError(c, response)
	} else {
		ResponseLogicSucc(c, response)
	}
}

func (server *SrvHttp) POST_Login(c *gin.Context) {
	var err error = nil
	response := "success"
	logger.Info("Chaincode request received")

	reqBody, err := ioutil.ReadAll(c.Request.Body)
	defer c.Request.Body.Close()
	if err != nil {
		response = fmt.Sprintf("failed to read http body error: %s", err.Error())
		logger.Error(response)
		ResponseLogicError(c, response)
		return
	}
	_ = reqBody

	if err != nil {
		ResponseLogicError(c, response)
	} else {
		ResponseLogicSucc(c, response)
	}
}

func (server *SrvHttp) POST_ForgetPwd(c *gin.Context) {
	var err error = nil
	response := "success"
	logger.Info("Chaincode request received")

	reqBody, err := ioutil.ReadAll(c.Request.Body)
	defer c.Request.Body.Close()
	if err != nil {
		response = fmt.Sprintf("failed to read http body error: %s", err.Error())
		logger.Error(response)
		ResponseLogicError(c, response)
		return
	}
	_ = reqBody

	if err != nil {
		ResponseLogicError(c, response)
	} else {
		ResponseLogicSucc(c, response)
	}
}

func (server *SrvHttp) POST_ModifyPwd(c *gin.Context) {
	var err error = nil
	response := "success"
	logger.Info("Chaincode request received")

	reqBody, err := ioutil.ReadAll(c.Request.Body)
	defer c.Request.Body.Close()
	if err != nil {
		response = fmt.Sprintf("failed to read http body error: %s", err.Error())
		logger.Error(response)
		ResponseLogicError(c, response)
		return
	}
	_ = reqBody

	if err != nil {
		ResponseLogicError(c, response)
	} else {
		ResponseLogicSucc(c, response)
	}
}