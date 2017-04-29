package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"time"
)

type Config struct {
	MySQLURI     string       `json:"mysql"`
	WebAppCfg    WebAppConfig `json:"webapp"`
	LDAPCfg      LDAPConfig   `json:"ldap"`
	UsersBackend string       `json:"usersBackend"`
	File         struct {
		UsersFile string `json:"usersFile"`
	} `json:"file"`
}

type Users struct {
	UserName   string `json:"userName"`
	Password   string `json:"password"`
	Role       string `json:"role"`
	AvatarFile string `json:"avatarFile"`
}

type UserInGroupCacheEntry struct {
	role        string
	success     bool
	lastUpdated time.Time
}

var (
	osMutex    sync.Mutex
	cache      map[string]interface{}
	config     Config
	ldapClient LDAPClient
)

func getUsersFromFile() (users []Users, rerr error) {
	rerr = nil
	if rawUsers, err := ioutil.ReadFile(config.File.UsersFile); err != nil {
		rerr = errors.New("Can't open file: " + config.File.UsersFile)
	} else {
		if err := json.Unmarshal(rawUsers, &users); err != nil {
			rerr = errors.New("Error read file: " + config.File.UsersFile + ": " + err.Error())
		}
	}
	return
}

func getUserRole(userName string) (role string) {
	osMutex.Lock()
	defer osMutex.Unlock()

	var cacheKey string = "main.getUserRole(" + userName + ")"
	var cacheValue UserInGroupCacheEntry
	if cacheEntry, ok := cache[cacheKey]; ok {
		cacheValue = cacheEntry.(UserInGroupCacheEntry)
		if cacheValue.lastUpdated.After(time.Now().Add(-(time.Second * 60))) {
			role = cacheValue.role
			return
		}
	}
	defer func() {
		cacheValue.role = role
		cacheValue.lastUpdated = time.Now()
		cache[cacheKey] = cacheValue
	}()

	role = ""
	if config.UsersBackend == "ldap" {
		if inUsers, err := ldapClient.InGroup(userName, config.LDAPCfg.UsersGroupDn); err != nil {
			panic(err)
		} else {
			if inUsers {
				role = "agent"
				if inInspectors, err := ldapClient.InGroup(userName, config.LDAPCfg.InspectorsGroupDn); err != nil {
					panic(err)
				} else {
					if inInspectors {
						role = "inspector"
					}
				}
			}
		}
	} else if config.UsersBackend == "file" {
		if users, err := getUsersFromFile(); err == nil {
			for _, user := range users {
				if user.UserName == userName {
					role = user.Role
					return
				}
			}
		} else {
			panic(err)
		}
	} else {
		panic(errors.New("Unknown users backend " + config.UsersBackend))
	}
	return
}

func authUser(userName string, password string) error {
	if config.UsersBackend == "ldap" {
		return ldapClient.Auth(userName, password)
	} else if config.UsersBackend == "file" {
		if users, err := getUsersFromFile(); err == nil {
			for _, user := range users {
				if (user.UserName == userName) && (user.Password == password) {
					return nil
				}
			}
			return errors.New("Can't find user " + userName)
		} else {
			return err
		}
	} else {
		return errors.New("Unknown users backend " + config.UsersBackend)
	}
}

func getUserAvatar(userName string) ([]byte, error) {
	if config.UsersBackend == "ldap" {
		if h, err := ldapClient.NewLdapHandler(); err == nil {
			defer h.Close()
			photoString, err := ldapClient.GetOneAttribute(h, "uid="+userName, "jpegPhoto")
			return []byte(photoString), err
		} else {
			return []byte(""), err
		}
	} else if config.UsersBackend == "file" {
		if users, err := getUsersFromFile(); err == nil {
			for _, user := range users {
				if user.UserName == userName {
					if rawBytes, err := ioutil.ReadFile(user.AvatarFile); err == nil {
						return rawBytes, nil
					} else {
						return []byte(""), err
					}
				}
			}
			return []byte(""), errors.New("Can't find user " + userName)
		} else {
			return []byte(""), err
		}
	} else {
		return []byte(""), errors.New("Unknown users backend " + config.UsersBackend)
	}
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			log.Fatalf("Fatal error: %v\n%s", r, debug.Stack())
			os.Exit(1)
		}
	}()

	if (len(os.Args)) < 2 {
		fmt.Println("USAGE: " + os.Args[0] + " <config file>")
		panic("No config file")
	}

	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		panic(err.Error())
	}
	err = os.Chdir(dir)
	if err != nil {
		panic(err.Error())
	}

	cache = make(map[string]interface{})

	rawConfig, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		panic("Can't open config file")
	}

	err = json.Unmarshal(rawConfig, &config)
	if err != nil {
		panic("Error read config: " + err.Error())
	}

	var pOrm *DBORM
	pOrm, err = NewDBORM(config.MySQLURI)
	if err != nil {
		panic(err)
	}

	ldapClient.SetConfig(config.LDAPCfg)

	var webApp WebApp
	go webApp.InitAndServe(&config.WebAppCfg, pOrm)

	lock := make(chan bool)
	<-lock

	return
}
