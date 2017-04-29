package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/gorilla/websocket"
	"golang.org/x/net/xsrftoken"
	"gopkg.in/gin-gonic/gin.v1"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"text/template"
	"time"
)

const (
	STATIC_PATH      = "/static"
	COOKIE_KEY       = "INTERVIEW_SID"
	TOKEN_SECRET_KEY = "mVCmYgA6b097gcwN"
)

var (
	SESSION_TIME_TO_LIVE = time.Hour * 24
	ErrorInternalServer  = errors.New("Internal server error - see server logs")
)

type WebAppConfig struct {
	Listen               string          `json:"listen"`
	ProjectHost          string          `json:"projectHost"`
	ProjectPath          string          `json:"projectPath"`
	SSLCert              string          `json:"sslCert"`
	SSLKey               string          `json:"sslKey"`
	UsersGroup           string          `json:"usersGroup"`
	InspectorsGroup      string          `json:"inspectorsGroup"`
	CallRecordRoot       string          `json:"callRecordRoot"`
	PeerConnectionConfig json.RawMessage `json:"peerConnectionConfig"`
}

type WebAPIError struct {
	Err string `json:"err"`
}

type WebAPIMsgType struct {
	MsgType string `json:"msgType"`
}

type UserData struct {
	UserId           string `json:"userId"`
	Role             string `json:"role"`
	Online           bool   `json:"online"`
	NoReplySeconds   int    `json:"-"`
	SelectedUserName string `json:"-"`
}

type WebApp struct {
	config           WebAppConfig
	pOrm             *DBORM
	pRouter          *gin.Engine
	usersOnline      map[*websocket.Conn]UserData
	usersOnlineMutex sync.RWMutex
}

func (a *WebApp) getCommonData(c *gin.Context) gin.H {
	H := gin.H{
		"projectPath": a.config.ProjectPath,
	}
	return H
}

func (a *WebApp) panicHandler(c *gin.Context) {
	if e := recover(); e != nil {
		var err error = e.(error)
		log.Printf("[GO FATAL ERROR]: %s\n%s", err.Error(), debug.Stack())
		c.JSON(http.StatusInternalServerError, &WebAPIError{Err: ErrorInternalServer.Error()})
	}
}

var wsupgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

type WebAPIClientReq struct {
	WebAPIError
	WebAPIMsgType
	To               string                 `json:"to"`
	From             string                 `json:"from"`
	Text             string                 `json:"text,omitempty"`
	Reason           string                 `json:"reason,omitempty"`
	SelectedUserName string                 `json:"selectedUserName,omitempty"`
	CallUUID         string                 `json:"callUUID,omitempty"`
	Candidate        map[string]interface{} `json:"candidate,omitempty"`
	Sdp              map[string]interface{} `json:"sdp,omitempty"`
}

func (a *WebApp) wsHandler(c *gin.Context) {
	conn, err := wsupgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		panic(errors.New("Failed to set websocket upgrade: " + err.Error()))
	}
	defer func() {
		conn.Close()
	}()
	var userData UserData
	if userId, ok := c.Get("UserId"); ok {
		userData.UserId = userId.(string)
	} else {
		panic(errors.New("websocket without UserId"))
	}
	if role, ok := c.Get("Role"); ok {
		userData.Role = role.(string)
	}
	userData.Online = true

	a.usersOnlineMutex.Lock()
	a.usersOnline[conn] = userData
	a.usersOnlineMutex.Unlock()

	defer func() {
		a.usersOnlineMutex.Lock()
		delete(a.usersOnline, conn)
		a.usersOnlineMutex.Unlock()
	}()

	a.sendUserData(conn)
	a.sendBroadCastUserOnline(conn)
	defer func() {
		a.sendBroadCastUserOffline(conn)
	}()
	a.sendAllUsers(conn)

	go func() {
		for userData.Online {
			time.Sleep(time.Second * 30)
			if userData.Online {
				userData.NoReplySeconds = userData.NoReplySeconds + 30
				if userData.NoReplySeconds >= 90 {
					log.Printf("%s: ping timeout\n", userData.UserId)
					conn.Close()
					break
				}
			}
		}
	}()

	for {
		var req WebAPIClientReq
		err := conn.ReadJSON(&req)
		if err != nil {
			log.Printf("%s: %s\n", userData.UserId, err.Error())
			break
		}
		//log.Printf("RECEIVE: %+v\n", req)
		req.From = userData.UserId
		var historyEntry CallHistory

		if req.MsgType == "ping" {
			userData.NoReplySeconds = 0
			a.sendPong(conn)
		} else if req.MsgType == "selectUserName" {
			userData.SelectedUserName = req.SelectedUserName
			a.usersOnlineMutex.Lock()
			a.usersOnline[conn] = userData
			a.usersOnlineMutex.Unlock()
			a.sendTextMessages(conn, nil)
			a.sendCallHistory(conn, nil)
		} else if req.MsgType == "call" {
			if err := a.pOrm.Conn.Where("call_uuid = ?", req.CallUUID).First(&historyEntry).Error; err == nil {
				historyEntry.CallFrom = getUserName(req.From)
				historyEntry.CallTo = getUserName(req.To)
			} else {
				historyEntry = CallHistory{
					CallUUID: req.CallUUID,
					CallFrom: getUserName(req.From),
					CallTo:   getUserName(req.To),
				}
			}
			a.pOrm.Conn.Save(&historyEntry)
		} else if req.MsgType == "callAccept" {
			if err := a.pOrm.Conn.Where("call_uuid = ?", req.CallUUID).First(&historyEntry).Error; err == nil {
				historyEntry.StartTime = time.Now()
				a.pOrm.Conn.Save(&historyEntry)
			}
		} else if req.MsgType == "callReject" {
			if err := a.pOrm.Conn.Where("call_uuid = ?", req.CallUUID).First(&historyEntry).Error; err == nil {
				if historyEntry.RejectReason == "" {
					historyEntry.EndTime = time.Now()
					historyEntry.RejectReason = req.Reason
					a.pOrm.Conn.Save(&historyEntry)
					if err := a.pOrm.Conn.Preload("CallRecordL").Where("call_uuid = ?", req.CallUUID).First(&historyEntry).Error; err == nil {
						a.sendCallHistory(conn, &historyEntry)
					}
				}
			}
		} else if req.MsgType == "textMessage" {
			textMessage := TextMessage{
				MessageFrom: getUserName(userData.UserId),
				MessageTo:   req.To,
				Text:        req.Text,
				MessageTime: time.Now(),
			}
			if err := a.pOrm.Conn.Save(&textMessage).Error; err == nil {
				a.sendTextMessages(conn, &textMessage)
				a.usersOnlineMutex.RLock()
				for connTo, userDataTo := range a.usersOnline {
					if getUserName(userDataTo.UserId) == req.To {
						a.sendTextMessages(connTo, &textMessage)
					}
				}
				a.usersOnlineMutex.RUnlock()
			}
		}
		if req.To != "" {
			a.usersOnlineMutex.RLock()
			for connTo, userDataTo := range a.usersOnline {
				if userDataTo.UserId == req.To {
					connTo.WriteJSON(req)
					//log.Printf("SEND: %+v\n", req)
					if historyEntry.CallUUID != "" {
						a.sendCallHistory(connTo, &historyEntry)
					}
					break
				}
			}
			a.usersOnlineMutex.RUnlock()
		}
	}
	userData.Online = false
}

//----------------------------------------------------------------------

func (a *WebApp) WebAPIGetAvatar(c *gin.Context) {
	defer a.panicHandler(c)

	if rawBytes, err := getUserAvatar(c.Query("userName")); err == nil {
		c.Data(http.StatusOK, "image/jpeg", rawBytes)
		return
	}
	c.File("./static/images/nophoto.png")
	return
}

//----------------------------------------------------------------------

type WebAPIOwnUserDataRes struct {
	WebAPIError
	WebAPIMsgType
	UserData
	PeerConnectionConfig json.RawMessage `json:"peerConnectionConfig"`
}

func (a *WebApp) sendUserData(conn *websocket.Conn) error {
	var res WebAPIOwnUserDataRes
	a.usersOnlineMutex.RLock()
	res.UserData = a.usersOnline[conn]
	a.usersOnlineMutex.RUnlock()
	res.MsgType = "ownUserData"
	res.PeerConnectionConfig = a.config.PeerConnectionConfig
	conn.WriteJSON(res)
	return nil
}

//---------------------------------------------------------------------

type WebAPIUserStatusChangeRes struct {
	WebAPIError
	WebAPIMsgType
	AllUsers         bool       `json:"allUsers"`
	ChangedUserDatas []UserData `json:"changedUserDatas"`
}

func (a *WebApp) sendAllUsers(conn *websocket.Conn) error {
	a.usersOnlineMutex.RLock()
	defer a.usersOnlineMutex.RUnlock()

	var res WebAPIUserStatusChangeRes
	res.MsgType = "userStatusChange"
	res.AllUsers = true
	res.ChangedUserDatas = make([]UserData, 0)
	var role string = a.usersOnline[conn].Role
	var userName string = getUserName(a.usersOnline[conn].UserId)

	var accounts []Account
	if role == "inspector" {
		accounts, _ = a.pOrm.GetAllAccounts()
	} else {
		accounts, _ = a.pOrm.GetAllInspectorAccounts()
	}
	for _, account := range accounts {
		var curUserData UserData
		curUserData.UserId = account.LastUserId
		curUserData.Role = account.LastRole
		if account.UserName != userName {
			res.ChangedUserDatas = append(res.ChangedUserDatas, curUserData)
		}
	}

	for curConn, curUserData := range a.usersOnline {
		if curConn != conn {
			if (role != "agent") || (curUserData.Role != "agent") {
				var find bool
				for i, curUserData0 := range res.ChangedUserDatas {
					if (!curUserData0.Online) && (getUserName(curUserData0.UserId) == getUserName(curUserData.UserId)) {
						res.ChangedUserDatas[i] = curUserData
						find = true
					}
				}
				if !find {
					res.ChangedUserDatas = append(res.ChangedUserDatas, curUserData)
				}
			}
		}
	}

	if len(res.ChangedUserDatas) > 0 {
		conn.WriteJSON(res)
	}
	return nil
}

func (a *WebApp) sendBroadCastUserOnline(conn *websocket.Conn) error {
	a.usersOnlineMutex.RLock()
	defer a.usersOnlineMutex.RUnlock()

	var res WebAPIUserStatusChangeRes
	res.MsgType = "userStatusChange"
	var userData UserData = a.usersOnline[conn]
	userData.Online = true
	res.ChangedUserDatas = []UserData{userData}
	var role string = a.usersOnline[conn].Role

	for curConn, curUserData := range a.usersOnline {
		if curConn != conn {
			if (role != "agent") || (curUserData.Role != "agent") {
				curConn.WriteJSON(res)
			}
		}
	}
	return nil
}

func (a *WebApp) sendBroadCastUserOffline(conn *websocket.Conn) error {
	a.usersOnlineMutex.RLock()
	defer a.usersOnlineMutex.RUnlock()

	var res WebAPIUserStatusChangeRes
	res.MsgType = "userStatusChange"
	var userData UserData = a.usersOnline[conn]
	userData.Online = false
	res.ChangedUserDatas = []UserData{userData}
	var role string = a.usersOnline[conn].Role

	for curConn, curUserData := range a.usersOnline {
		if curConn != conn {
			if (role != "agent") || (curUserData.Role != "agent") {
				curConn.WriteJSON(res)
			}
		}
	}
	return nil
}

//---------------------------------------------------------------------

type WebAPICallHistoryRes struct {
	WebAPIError
	WebAPIMsgType
	AllHistory     bool          `json:"allHistory"`
	HistoryEntries []CallHistory `json:"historyEntries"`
}

func (a *WebApp) sendCallHistory(conn *websocket.Conn, historyEntry *CallHistory) error {
	a.usersOnlineMutex.RLock()
	defer a.usersOnlineMutex.RUnlock()

	var res WebAPICallHistoryRes
	res.MsgType = "callHistory"
	if historyEntry == nil {
		if err := a.pOrm.Conn.Preload("CallRecordL").Where("((call_from = ? AND call_to = ?) OR (call_to = ? AND call_from = ?)) AND updated_at > ?",
			getUserName(a.usersOnline[conn].UserId),
			a.usersOnline[conn].SelectedUserName,
			getUserName(a.usersOnline[conn].UserId),
			a.usersOnline[conn].SelectedUserName,
			time.Now().Add(-(time.Hour * 24 * 7))).Find(&res.HistoryEntries).Error; err == nil {
			res.AllHistory = true
			conn.WriteJSON(res)
		} else {
			panic(err)
		}
	} else {
		if (historyEntry.CallFrom == a.usersOnline[conn].SelectedUserName) ||
			(historyEntry.CallTo == a.usersOnline[conn].SelectedUserName) {
			res.HistoryEntries = append(res.HistoryEntries, *historyEntry)
			conn.WriteJSON(res)
		}
	}
	return nil
}

//---------------------------------------------------------------------

type WebAPIMessageRes struct {
	WebAPIError
	WebAPIMsgType
	AllMessages    bool          `json:"allMessages"`
	MessageEntries []TextMessage `json:"messageEntries"`
}

func (a *WebApp) sendTextMessages(conn *websocket.Conn, messageEntry *TextMessage) error {
	a.usersOnlineMutex.RLock()
	defer a.usersOnlineMutex.RUnlock()

	var res WebAPIMessageRes
	res.MsgType = "textMessages"
	if messageEntry == nil {
		if err := a.pOrm.Conn.Where("((message_from = ? AND message_to = ?) OR (message_to = ? AND message_from = ?)) AND updated_at > ?",
			getUserName(a.usersOnline[conn].UserId),
			a.usersOnline[conn].SelectedUserName,
			getUserName(a.usersOnline[conn].UserId),
			a.usersOnline[conn].SelectedUserName,
			time.Now().Add(-(time.Hour * 24 * 7))).Find(&res.MessageEntries).Error; err == nil {
			res.AllMessages = true
			conn.WriteJSON(res)
		} else {
			panic(err)
		}
	} else {
		if (messageEntry.MessageFrom == a.usersOnline[conn].SelectedUserName) ||
			(messageEntry.MessageTo == a.usersOnline[conn].SelectedUserName) {
			res.MessageEntries = append(res.MessageEntries, *messageEntry)
			conn.WriteJSON(res)
		}
	}
	return nil
}

//---------------------------------------------------------------------

func (a *WebApp) WebAPIDownloadVideo(c *gin.Context) {
	defer a.panicHandler(c)

	if role, ok := c.Get("Role"); ok {
		if role.(string) != "inspector" {
			panic(errors.New("Only inspectors allowed download video"))
		}
	}
	userId, ok := c.Get("UserId")
	if !ok {
		panic(errors.New("Context without userId"))
	}

	recordUUID := c.Query("recordUUID")
	if recordUUID == "" {
		c.String(http.StatusForbidden, "")
		return
	}
	var callRecord CallRecord
	if err := a.pOrm.Conn.Where("record_uuid = ?", recordUUID).First(&callRecord).Error; err == nil {
		var historyEntry CallHistory
		if err := a.pOrm.Conn.Where("id = ?", callRecord.ID).First(&historyEntry).Error; err == nil {
			if (historyEntry.CallFrom == getUserName(userId.(string))) || (historyEntry.CallTo == getUserName(userId.(string))) {
				c.Header("Content-Type", "video/webm")
				c.File(a.config.CallRecordRoot + "/" + callRecord.FileName)
				return
			} else {
				c.String(http.StatusForbidden, "")
			}
		} else {
			panic(err)
		}
	} else {
		c.String(http.StatusForbidden, "")
	}
}

//---------------------------------------------------------------------

type WebAPIUploadVideoRes struct {
	WebAPIError
}

func (a *WebApp) WebAPIUploadVideo(c *gin.Context) {
	defer a.panicHandler(c)

	var res WebAPIUploadVideoRes
	if role, ok := c.Get("Role"); ok {
		if role.(string) != "inspector" {
			panic(errors.New("Only inspectors allowed upload video"))
		}
	}
	callUUID := c.Query("callUUID")
	var historyEntry CallHistory
	if err := a.pOrm.Conn.Where("call_uuid = ?", callUUID).Preload("CallRecordL").First(&historyEntry).Error; err == nil {
		var dateDir string = time.Now().Format(time.RFC3339)[:10]
		_ = os.Mkdir(a.config.CallRecordRoot+"/"+dateDir, 0750)
		var recordUUID string = genRandomString(8) + "-" + genRandomString(4) + "-" + genRandomString(4) + "-" +
			genRandomString(12)
		var fileName = dateDir + "/" + recordUUID + ".webm"
		historyEntry.CallRecordL = append(historyEntry.CallRecordL, CallRecord{RecordUUID: recordUUID, FileName: fileName})
		f, err := os.OpenFile(a.config.CallRecordRoot+"/"+fileName, os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
			panic(err)
		}
		a.pOrm.Conn.Save(&historyEntry)
		defer f.Close()
		io.Copy(f, c.Request.Body)
		c.JSON(http.StatusOK, &res)
	} else {
		panic(err)
	}
}

//---------------------------------------------------------------------

type WebAPIPingRes struct {
	WebAPIError
	WebAPIMsgType
}

func (a *WebApp) sendPong(conn *websocket.Conn) error {
	var res WebAPIPingRes
	res.MsgType = "pong"
	conn.WriteJSON(res)
	return nil
}

//---------------------------------------------------------------------

func (a *WebApp) authRequired(c *gin.Context) {
	c.Header("WWW-Authenticate", `Basic realm="Restricted"`)
	c.AbortWithStatus(401)
}

func (a *WebApp) AccounterHandler(c *gin.Context) {
	var SID string
	var session Session

	cookie, err := c.Request.Cookie(COOKIE_KEY)
	var role string
	if err != nil {
		s := strings.SplitN(c.Request.Header.Get("Authorization"), " ", 2)
		if len(s) != 2 {
			a.authRequired(c)
			return
		}
		b, err := base64.StdEncoding.DecodeString(s[1])
		if err != nil {
			a.authRequired(c)
			return
		}
		pair := strings.SplitN(string(b), ":", 2)
		if len(pair) != 2 {
			a.authRequired(c)
			return
		}
		if err := authUser(pair[0], pair[1]); err != nil {
			log.Printf("User %s: Invalid credentials, %s\n", pair[0], err.Error())
			a.authRequired(c)
			return
		}
		if role = getUserRole(pair[0]); role == "" {
			log.Printf("User %s: Can't lookup role\n", pair[0])
			a.authRequired(c)
			return
		}

		SID = xsrftoken.Generate(TOKEN_SECRET_KEY, pair[0], "webapp")

		session.SID = SID
		session.UserId = pair[0] + "/" + genRandomString(8)
		a.pOrm.Conn.Save(&session)

		expiration := time.Now().Add(24 * time.Hour)
		cookie := http.Cookie{Path: a.config.ProjectPath, Name: COOKIE_KEY, Value: SID, Expires: expiration}
		http.SetCookie(c.Writer, &cookie)
	} else {
		SID = cookie.Value
		err := a.pOrm.Conn.Where("s_id = ?", SID).First(&session).Error
		if err == nil {
			if role = getUserRole(getUserName(session.UserId)); role == "" {
				log.Printf("User %s: Can't lookup role\n", getUserName(session.UserId))
				a.pOrm.Conn.Delete(&session)
			}
		}
		if err != nil {
			cookieToDel := http.Cookie{Path: a.config.ProjectPath, Name: COOKIE_KEY, Value: "deleted", Expires: time.Unix(24, 0)}
			http.SetCookie(c.Writer, &cookieToDel)
			c.Redirect(http.StatusFound, a.config.ProjectPath+"/")
			return
		}
		a.pOrm.Conn.Save(&session)
	}
	c.Set("UserId", session.UserId)
	a.pOrm.UpdateAccount(getUserName(session.UserId), session.UserId, role)
	c.Set("Role", role)
	c.Next()
}

func Accounter(a *WebApp) gin.HandlerFunc {
	return a.AccounterHandler
}

func (a *WebApp) TemplateRender(c *gin.Context, templateFileName string, data interface{}) ([]byte, error) {

	tname := filepath.Base(templateFileName)
	t, err := template.New(tname).ParseFiles(templateFileName)
	if err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)
	if err = t.ExecuteTemplate(buf, tname, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Render base template
func (a *WebApp) renderRoutes(c *gin.Context) {
	if d, err := a.TemplateRender(c, "./templates/main.tmpl", a.getCommonData(c)); err == nil {
		c.Data(http.StatusOK, "text/html", d)
	} else {
		log.Printf("[WebApp::renderMain] %s\n", err.Error())
		c.String(http.StatusInternalServerError, "text/plain", "")
	}
}

func (a *WebApp) renderTemplates(c *gin.Context) {
	var name = c.Request.RequestURI[(len(a.config.ProjectPath) + 1):]
	name = name[:len(name)-5]

	if d, err := a.TemplateRender(c, "./templates/"+name+".tmpl", a.getCommonData(c)); err == nil {
		c.Data(http.StatusOK, "text/html", d)
	} else {
		log.Printf("[WebApp::renderTemplates] %s\n", err.Error())
		c.String(http.StatusInternalServerError, "text/plain", "")
	}
}

func (a *WebApp) InitAndServe(config *WebAppConfig, pOrm *DBORM) error {

	a.config = *config
	a.pOrm = pOrm
	a.usersOnline = make(map[*websocket.Conn]UserData)

	a.pRouter = gin.Default()
	a.pRouter.Use(Accounter(a))

	// Static content
	a.pRouter.Static(a.config.ProjectPath+STATIC_PATH, "./static")

	// Render routes
	a.pRouter.GET(a.config.ProjectPath+"/", a.renderRoutes)

	// Render all templates
	a.pRouter.GET(a.config.ProjectPath+"/app-main.html", a.renderTemplates)

	a.pRouter.GET(a.config.ProjectPath+"/api/ws", a.wsHandler)
	a.pRouter.GET(a.config.ProjectPath+"/api/getAvatar", a.WebAPIGetAvatar)
	a.pRouter.PUT(a.config.ProjectPath+"/api/uploadVideo", a.WebAPIUploadVideo)
	a.pRouter.GET(a.config.ProjectPath+"/api/downloadVideo", a.WebAPIDownloadVideo)

	go func() {
		expiredTime := time.Now().Add(-(SESSION_TIME_TO_LIVE))
		if err := a.pOrm.Conn.Where("updated_at < ? AND deleted_at is NULL", expiredTime).Delete(Session{}).Error; err != nil {
			log.Printf("Error deleting sessions: %s\n", err.Error)
		}
		time.Sleep(time.Second * 60)
	}()

	log.Printf("Listening TLS on %s\n", a.config.Listen)
	if err := a.pRouter.RunTLS(a.config.Listen, a.config.SSLCert, a.config.SSLKey); err != nil {
		panic(err)
	}

	return nil
}
