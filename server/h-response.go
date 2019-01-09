package server

import (
	"github.com/gin-gonic/gin"
	. "ihub/protocol"
	"net/http"
)

func ResponseLogicSucc(c *gin.Context, message string) {
	c.Header("Content-Type", "application/json")
	c.JSON(http.StatusOK, NewSuccessResponse(message))
}

func ResponseLogicError(c *gin.Context, message string) {
	c.Header("Content-Type", "application/json")
	c.JSON(http.StatusInternalServerError, NewErrorResponse(message))
}


func ResponseLogicSuccessAndWarn(c *gin.Context, message string, warning string) {
	c.Header("Content-Type", "application/json")
	c.JSON(http.StatusInternalServerError, NewSuccessAndWarnResponse(message, warning))
}
