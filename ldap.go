package main

import (
	"errors"
	"github.com/mqu/openldap"
	"strings"
	"sync"
)

type LDAPConfig struct {
	URI               string `json:"uri"`
	Base              string `json:"base"`
	UsersGroupDn      string `json:"usersGroupDn"`
	InspectorsGroupDn string `json:"inspectorsGroupDn"`
}

type LDAPClient struct {
	ldapConfig  LDAPConfig
	initialized bool
	mutex       sync.Mutex
}

func (ldapClient *LDAPClient) SetConfig(ldapConfig LDAPConfig) error {
	if ldapConfig.URI == "" {
		return errors.New("LDAP URI is not defined")
	}
	ldapClient.ldapConfig = ldapConfig
	ldapClient.initialized = true

	return nil
}

func (ldapClient *LDAPClient) NewLdapHandler() (*openldap.Ldap, error) {
	if !ldapClient.initialized {
		return nil, errors.New("LDAPClient not initialized")
	}
	pLdap, err := openldap.Initialize(ldapClient.ldapConfig.URI)
	if err != nil {
		return nil, err
	}
	pLdap.SetOption(openldap.LDAP_OPT_PROTOCOL_VERSION, openldap.LDAP_VERSION3)
	return pLdap, nil
}

func (ldapClient *LDAPClient) GetOneAttribute(pLdap *openldap.Ldap, filter string, attribute string) (string, error) {

	scope := openldap.LDAP_SCOPE_SUBTREE
	attributes := []string{attribute}

	ldapClient.mutex.Lock()
	result, err := pLdap.SearchAll(ldapClient.ldapConfig.Base, scope, filter, attributes)
	ldapClient.mutex.Unlock()

	if err != nil {
		return "", err
	}

	for _, entry := range result.Entries() {
		if attribute == "dn" {
			return entry.Dn(), nil
		}
		for _, attr := range entry.Attributes() {
			if attr.Name() == attribute {
				return strings.Join(attr.Values(), ", "), nil
			}
		}
	}

	return "", errors.New("Attribute " + attribute + " not found for filter " + filter)
}

func (ldapClient *LDAPClient) InGroup(uid string, group string) (bool, error) {

	pLdap, err := ldapClient.NewLdapHandler()
	if err != nil {
		return false, err
	}
	defer pLdap.Close()

	dn, err := ldapClient.GetOneAttribute(pLdap, "uid="+uid, "dn")
	if err != nil {
		return false, err
	}

	scope := openldap.LDAP_SCOPE_SUBTREE
	attributes := []string{"member", "uniqueMember"}

	ldapClient.mutex.Lock()
	result, err := pLdap.SearchAll(group, scope, "(objectClass=*)", attributes)
	ldapClient.mutex.Unlock()

	if err != nil {
		return false, err
	}

	for _, entry := range result.Entries() {
		for _, attr := range entry.Attributes() {
			if (attr.Name() == "member") || (attr.Name() == "uniqueMember") {
				for _, value := range attr.Values() {
					if value == dn {
						return true, nil
					}
				}
			}
		}
	}
	return false, nil
}

func (ldapClient *LDAPClient) Auth(userName string, password string) error {
	ldapHandler, err := ldapClient.NewLdapHandler()
	if err != nil {
		return err
	}
	if dn, err := ldapClient.GetOneAttribute(ldapHandler, "uid="+userName, "dn"); err == nil {
		ldapClient.mutex.Lock()
		err := ldapHandler.Bind(dn, password)
		ldapClient.mutex.Unlock()
		if err == nil {
			ldapHandler.Close()
		}
		return err
	} else {
		return err
	}
}
