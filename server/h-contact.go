package server

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	//"strings"
	//"strconv"
	"encoding/json"
)

type Contact struct {
	Id int
	Name string
	Cphone string
	Wallet_addr string
	Remarks string
}

func (server *SrvHttp) POST_ContactAdd(c *gin.Context) {
	var err error = nil
	response := "success"

	reqBody, err := ioutil.ReadAll(c.Request.Body)
	defer c.Request.Body.Close()
	if err != nil {
		response = fmt.Sprintf("failed to read http body error: %s", err.Error())
		logger.Error(response)
		ResponseLogicError(c, response)
		return
	}

	var contact Contact
	c_map := make(map[string]interface{}, 0)

	if err := json.Unmarshal(reqBody, &c_map); err != nil {
		logger.Error(err)
		return
	}
	user_id := c_map["user_id"]
	//delete(c_map, "user_id")
	//jsonstr, _ := json.Marshal(c_map)
	if err := json.Unmarshal(reqBody, &contact); err != nil {
		logger.Error(err)
		return
	}
	_conn, err := server.db.Begin()
	if err != nil {
		logger.Error(err)
		return
	}

	rs, err := _conn.Exec("insert into contacts(name, cphone, wallet_addr, remarks) SELECT ?,?,?,? FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM contacts WHERE name=? AND cphone=? AND wallet_addr=? AND remarks=?)",
	                       contact.Name, contact.Cphone, contact.Wallet_addr, contact.Remarks, contact.Name, contact.Cphone, contact.Wallet_addr, contact.Remarks)
	if err != nil {
		response = fmt.Sprintf("failed to insert contacts error: %s", err.Error())
		logger.Error(response)
		ResponseLogicError(c, response)
		return
	}

	contact_id, err := rs.LastInsertId()
	if err != nil {
		logger.Error(err)
		return
	}
	if contact_id == 0 {
		rc, err := server.db.Query("select id from contacts WHERE name=? AND cphone=? AND wallet_addr=? AND remarks=?", contact.Name, contact.Cphone, contact.Wallet_addr, contact.Remarks)
            defer rc.Close()
		if err != nil {
			logger.Error(err)
			return
		}
		//var id int
		for rc.Next() {
			rc.Scan(&contact_id)
		}
	}

	rw, err := _conn.Exec("insert into users_contacts_rel values(0, ?,?)", user_id, contact_id)
	if err != nil {
		logger.Error(err)
		ResponseLogicError(c, response)
		return
	}
	_ = rw

	if err != nil {
		_conn.Rollback()
		ResponseLogicError(c, response)
	} else {
		_conn.Commit()
		ResponseLogicSucc(c, response)
	}
}

func (server *SrvHttp) POST_ContactDel(c *gin.Context) {
	var err error = nil
	response := "success"

	reqBody, err := ioutil.ReadAll(c.Request.Body)
	defer c.Request.Body.Close()
	if err != nil {
		response = fmt.Sprintf("failed to read http body error: %s", err.Error())
		logger.Error(response)
		ResponseLogicError(c, response)
		return
	}

	c_map := make(map[string]interface{}, 0)
	if err := json.Unmarshal(reqBody, &c_map); err != nil {
		logger.Error(err)
		return
	}
	var _id, user_id string
	// if _id, ok := c_map["contact_id"]; ok {
	// }
	_id = c_map["contact_id"].(string)
	if _id == "" {
		response = fmt.Sprintf("contact id err!")
		ResponseLogicSucc(c, response)
		return
	}

	user_id = c_map["user_id"].(string)
	if user_id == "" {
		response = fmt.Sprintf("user id err!")
		ResponseLogicSucc(c, response)
		return
	}

	_conn, err := server.db.Begin()
	rs, err := _conn.Exec("delete from contacts where id=?", _id)
	if err != nil {
		response = fmt.Sprintf("failed to delete contacts error: %s", err.Error())
		logger.Error(response)
		ResponseLogicError(c, response)
		return
	}
	_ = rs

	rc, err := _conn.Exec("delete from users_contacts_rel where user_id=? and contact_id=?", user_id, _id)
	if err != nil {
		response = fmt.Sprintf("failed to delete users_contacts_rel error: %s", err.Error())
		logger.Error(response)
		ResponseLogicError(c, response)
		return
	}
	_ = rc

	if err != nil {
		_conn.Rollback()
		ResponseLogicError(c, response)
	} else {
		_conn.Commit()
		ResponseLogicSucc(c, response)
	}
}


func (server *SrvHttp) POST_ContactUpdate(c *gin.Context) {
	var err error = nil
	response := "success"

	reqBody, err := ioutil.ReadAll(c.Request.Body)
	defer c.Request.Body.Close()
	if err != nil {
		response = fmt.Sprintf("failed to read http body error: %s", err.Error())
		logger.Error(response)
		ResponseLogicError(c, response)
		return
	}

	var contact Contact
	c_map := make(map[string]interface{}, 0)
	if err := json.Unmarshal(reqBody, &c_map); err != nil {
		logger.Error(err)
		return
	}

	if err := json.Unmarshal(reqBody, &contact); err != nil {
		logger.Error(err)
		return
	}

	_id := c_map["contact_id"].(string)
	if _id == "" {
		response = fmt.Sprintf("contact id err!")
		ResponseLogicSucc(c, response)
		return
	}

	rows, err := server.db.Query("SELECT * FROM contacts where id = ?", _id)
	defer rows.Close()
	if err != nil {
		logger.Info(err)
		return
	}

	for rows.Next() {
		rows.Scan(&contact.Id, &contact.Name, &contact.Cphone, &contact.Wallet_addr, &contact.Remarks)
	}

	_name := contact.Name
	_cphone := contact.Cphone
	_wallet_addr := contact.Wallet_addr
	_remarks := contact.Remarks

	if err := json.Unmarshal(reqBody, &contact); err != nil {
		logger.Error(err)
		return
	}

      if contact.Name != "" {
		_name = contact.Name
	}
	if contact.Cphone != "" {
		_cphone = contact.Cphone
	}
	if contact.Wallet_addr != "" {
		_wallet_addr = contact.Wallet_addr
	}
	if contact.Remarks != "" {
		_remarks = contact.Remarks
	}

	_conn, err := server.db.Begin()
	rs, err := _conn.Exec("update contacts set name=?, cphone=?, wallet_addr=?, remarks=? where id=?", _name, _cphone, _wallet_addr, _remarks, _id)
	if err != nil {
		response = fmt.Sprintf("failed to update contacts error: %s", err.Error())
		logger.Error(response)
		ResponseLogicError(c, response)
		return
	}
	_ = rs

	if err != nil {
		_conn.Rollback()
		ResponseLogicError(c, response)
	} else {
		_conn.Commit()
		ResponseLogicSucc(c, response)
	}
}

func (server *SrvHttp) POST_ContactGetList(c *gin.Context) {
	var err error = nil
	response := "success"

	reqBody, err := ioutil.ReadAll(c.Request.Body)
	defer c.Request.Body.Close()
	if err != nil {
		response = fmt.Sprintf("failed to read http body error: %s", err.Error())
		logger.Error(response)
		ResponseLogicError(c, response)
		return
	}

	// user_id, err := strconv.Atoi(strings.Split(string(reqBody), "=")[1])
	// if err != nil {
	// 	response = fmt.Sprintf("params error: %s", err.Error())
	// 	logger.Error(response)
	// 	ResponseLogicError(c, response)
	// 	return
	// }

	c_map := make(map[string]interface{}, 0)
	if err := json.Unmarshal(reqBody, &c_map); err != nil {
		logger.Error(err)
		return
	}

	user_id := c_map["user_id"].(string)
	if user_id == "" {
		response = fmt.Sprintf("user id err!")
		ResponseLogicSucc(c, response)
		return
	}

	rows, err := server.db.Query("SELECT contact_id FROM users_contacts_rel where user_id = ? group by contact_id", user_id)
	defer rows.Close()
	if err != nil {
		logger.Info(err)
		return
	}

	contacts := make([]Contact, 0)
	c_maps := make([]map[string]interface{}, 0)

	for rows.Next() {
		var id int
		rows.Scan(&id)
		contact_rows, err := server.db.Query("SELECT * FROM contacts where id = ?", id)
		defer contact_rows.Close()
		for contact_rows.Next() {
			var contact Contact
			contact_rows.Scan(&contact.Id, &contact.Name, &contact.Cphone, &contact.Wallet_addr, &contact.Remarks)
			contacts = append(contacts, contact)
		}

		if err != nil {
			logger.Info(err)
			return
		}

	}

	if(contacts !=nil){
		c_map := make(map[string]interface{}, 0)
		for i:=0; i<len(contacts); i++{
			c_map["id"] = contacts[i].Id
			c_map["name"] = contacts[i].Name
			c_map["cphone"] = contacts[i].Cphone
			c_map["remarks"] = contacts[i].Remarks
			c_maps = append(c_maps, c_map)
		}
		json_contracts, _ := json.Marshal(contacts)
		response = string(json_contracts)
	}

	if err != nil {
		ResponseLogicError(c, response)
	} else {
		ResponseLogicSucc(c, response)
	}
}