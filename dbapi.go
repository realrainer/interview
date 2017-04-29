package main

import (
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"log"
	"time"
)

// ----- MODEL -----

type Model struct {
	ID        uint64     `gorm:"primary_key" json:"-"`
	CreatedAt time.Time  `json:"-"`
	UpdatedAt time.Time  `json:"-"`
	DeletedAt *time.Time `sql:"index" json:"-"`
}

// ----- TABLES ----

type Account struct {
	Model
	UserName   string `sql:"size:255;index"`
	LastUserId string `sql:"size:255"`
	LastRole   string `sql:"size:32"`
}

type Session struct {
	Model
	UserId string `sql:"size:255;index"`
	SID    string `sql:"size:42;index"`
}

type CallHistory struct {
	Model
	CallUUID     string       `sql:"size:64;index" json:"callUUID"`
	CallFrom     string       `sql:"size:255;index" json:"callFrom"`
	CallTo       string       `sql:"size:255;index" json:"callTo"`
	StartTime    time.Time    `json:"startTime"`
	EndTime      time.Time    `json:"endTime"`
	RejectReason string       `sql:"size:255" json:"rejectReason"`
	CallRecordL  []CallRecord `gorm:"ForeignKey:CallHistoryID" json:"callRecordL"`
}

type CallRecord struct {
	Model
	RecordUUID    string       `sql:"size:64;index" json:"recordUUID"`
	CallHistoryL  *CallHistory `json:"-"`
	CallHistoryID uint64       `json:"-"`
	FileName      string       `sql:"size:64;index" json:"-"`
}

type TextMessage struct {
	Model
	MessageTime time.Time `json:"messageTime"`
	MessageFrom string    `sql:"size:255;index" json:"messageFrom"`
	MessageTo   string    `sql:"size:255;index" json:"messageTo"`
	Text        string    `json:"text"`
}

type DBORM struct {
	Conn *gorm.DB
}

func (pOrm *DBORM) UpdateAccount(userName string, lastUserId string, lastRole string) error {
	var account Account
	if err := pOrm.Conn.Where("user_name = ?", userName).First(&account).Error; err != nil {
		account.UserName = userName
	}
	account.LastUserId = lastUserId
	account.LastRole = lastRole
	return pOrm.Conn.Save(&account).Error
}

func (pOrm *DBORM) GetAllAccounts() ([]Account, error) {
	var accounts []Account
	err := pOrm.Conn.Find(&accounts).Error
	return accounts, err
}
func (pOrm *DBORM) GetAllInspectorAccounts() ([]Account, error) {
	var accounts []Account
	err := pOrm.Conn.Where("last_role = 'inspector'").Find(&accounts).Error
	return accounts, err
}

func NewDBORM(MYSQL_URI string) (*DBORM, error) {

	conn, err := gorm.Open("mysql", MYSQL_URI)
	if err != nil {
		return nil, err
	}
	conn.SingularTable(true)
	log.Println("Start migrate tables")
	conn.AutoMigrate(Session{}, CallHistory{}, CallRecord{}, Account{}, TextMessage{})

	return &DBORM{Conn: conn}, nil
}
