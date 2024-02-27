package optldap

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/5amu/goad/pkg/utils"
	"github.com/go-ldap/ldap/v3"
)

type connectOpts struct {
	Host   string
	Port   int
	UseSSL bool
}

func connect(host string, port int, useSsl bool) (*ldap.Conn, error) {
	conn, err := utils.GetConnection(host, port)
	if err != nil {
		return nil, err
	}

	startConn := func(c net.Conn, ssl bool) *ldap.Conn {
		client := ldap.NewConn(c, ssl)
		client.Start()
		return client
	}

	if useSsl {
		return startConn(conn, useSsl), nil
	}

	ch := make(chan *ldap.Conn)
	go func() {
		client := startConn(conn, useSsl)
		if err := client.StartTLS(&tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		}); err != nil {
			client.Close()
		} else {
			ch <- client
		}
	}()

	var ret *ldap.Conn
	select {
	case ret = <-ch:
	case <-time.After(2 * time.Second):
		ret = startConn(conn, useSsl)
	}
	return ret, nil
}

func authenticate(c *ldap.Conn, realm, username, password string) error {
	if c == nil {
		return fmt.Errorf("not connected")
	}

	if err := c.NTLMBind(realm, username, password); err == nil {
		return nil
	}

	switch password {
	case "":
		if err := c.UnauthenticatedBind(username); err != nil {
			return err
		}
	default:
		if err := c.Bind(username, password); err != nil {
			return err
		}
	}
	return nil
}
