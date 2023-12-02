package ldap

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap"
)

type LdapClient struct {
	BaseDN             string
	Realm              string
	Host               string
	ServerName         string
	Conn               *ldap.Conn
	Port               int
	UseSSL             bool
	SkipTLS            bool
	ClientCertificates []tls.Certificate
}

func (lc *LdapClient) connectTLS() error {
	config := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         lc.ServerName,
	}
	if lc.ClientCertificates != nil && len(lc.ClientCertificates) > 0 {
		config.Certificates = lc.ClientCertificates
	}
	l, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", lc.Host, lc.Port), config)
	if err != nil {
		return err
	}
	lc.Conn = l
	return nil
}

func (lc *LdapClient) connect() error {
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", lc.Host, lc.Port))
	if err != nil {
		return err
	}

	// Reconnect with TLS
	if !lc.SkipTLS {
		err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return err
		}
	}
	lc.Conn = l
	return nil
}

func (lc *LdapClient) Connect() error {
	if lc.Conn != nil {
		return nil
	}
	if lc.UseSSL {
		return lc.connectTLS()
	}
	return lc.connect()
}

// Close closes the ldap backend connection.
func (lc *LdapClient) Close() {
	if lc.Conn == nil {
		return
	}
	lc.Conn.Close()
	lc.Conn = nil
}

func (lc *LdapClient) bind(username, password string, prefix string) error {
	splitted := strings.Split(prefix, ".")
	tentativeUser := fmt.Sprintf("%s\\%s", prefix, username)
	switch password {
	case "":
		if len(splitted) == 1 {
			if err := lc.Conn.UnauthenticatedBind(tentativeUser); err != nil {
				return lc.Conn.UnauthenticatedBind(username)
			}
			return nil
		}
		if err := lc.Conn.UnauthenticatedBind(tentativeUser); err != nil {
			return lc.bind(username, password, strings.Join(splitted[:len(splitted)-1], "."))
		}
	default:
		if len(splitted) == 1 {
			return lc.Conn.Bind(tentativeUser, password)
		}
		if err := lc.Conn.Bind(tentativeUser, password); err != nil {
			return lc.bind(username, password, strings.Join(splitted[:len(splitted)-1], "."))
		}
	}
	return nil
}

// Authenticate authenticates the user against the ldap backend.
func (lc *LdapClient) Authenticate(username, password string) error {
	if err := lc.Connect(); err != nil {
		return err
	}

	if err := lc.bind(username, password, lc.Realm); err != nil {
		return err
	}

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		lc.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(sAMAccountName=%s)", username),
		[]string{"dn"},
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return err
	}

	if len(sr.Entries) < 1 {
		return fmt.Errorf("user does not exist")
	}

	if len(sr.Entries) > 1 {
		return fmt.Errorf("too many entries returned")
	}

	return lc.Conn.Bind(sr.Entries[0].DN, password)
}

func (lc *LdapClient) Search(filter string, attributes []string) (*ldap.SearchResult, error) {
	return lc.Conn.Search(ldap.NewSearchRequest(
		lc.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, attributes, nil,
	))
}
