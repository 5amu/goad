package ldap

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/5amu/goad/pkg/utils"
	"github.com/go-ldap/ldap/v3"
)

type LdapClient struct {
	BaseDN     string
	Realm      string
	Host       string
	ServerName string
	Conn       *ldap.Conn
	Port       int
	UseSSL     bool
	SkipTLS    bool
}

func NewLdapClient(host string, port int, realm string, ssl bool, skiptls bool) *LdapClient {
	return &LdapClient{
		Host:    host,
		Port:    port,
		Realm:   realm,
		BaseDN:  fmt.Sprintf("dc=%s", strings.Join(strings.Split(realm, "."), ",dc=")),
		SkipTLS: skiptls,
		UseSSL:  ssl,
	}
}

// Close closes the ldap backend connection.
func (lc *LdapClient) Close() {
	if lc.Conn == nil {
		return
	}
	lc.Conn.Close()
	lc.Conn = nil
}

func (c *LdapClient) Connect() error {
	if c.Conn != nil {
		return nil
	}

	conn, err := utils.GetConnection(c.Host, c.Port)
	if err != nil {
		return nil
	}
	c.Conn = ldap.NewConn(conn, c.UseSSL)
	c.Conn.Start()

	if !c.SkipTLS {
		return c.Conn.StartTLS(&tls.Config{
			InsecureSkipVerify: true,
			ServerName:         c.Host,
		})
	}
	return nil
}

// Authenticate authenticates the user against the ldap backend.
func (c *LdapClient) Authenticate(username, password string) error {
	if c.Conn == nil {
		if err := c.Connect(); err != nil {
			return err
		}
	}

	if err := c.Conn.NTLMBind(c.Realm, username, password); err == nil {
		return nil
	}

	switch password {
	case "":
		if err := c.Conn.UnauthenticatedBind(username); err != nil {
			return err
		}
	default:
		if err := c.Conn.Bind(username, password); err != nil {
			return err
		}
	}
	return nil
}

func (lc *LdapClient) AuthenticateNTLM(username, hash string) error {
	if lc.Conn == nil {
		if err := lc.Connect(); err != nil {
			return err
		}
	}
	return lc.Conn.NTLMBindWithHash(lc.Realm, username, hash)
}

func (lc *LdapClient) Search(filter string, attributes ...string) (*ldap.SearchResult, error) {
	return lc.Conn.Search(ldap.NewSearchRequest(
		lc.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, attributes, nil,
	))
}
