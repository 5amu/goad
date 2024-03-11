package optldap

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/5amu/goad/pkg/proxyconn"
	"github.com/go-ldap/ldap/v3"
)

func connect(host string, port int, useSsl bool) (*ldap.Conn, error) {
	startConn := func(ssl bool) *ldap.Conn {
		conn, err := proxyconn.GetConnection(host, port)
		if err != nil {
			fmt.Println(err)
			return nil
		}
		if ssl {
			conn = tls.Client(conn, &tls.Config{
				InsecureSkipVerify: true,
			})
		}

		client := ldap.NewConn(conn, ssl)
		client.Start()
		return client
	}

	if useSsl {
		return startConn(useSsl), nil
	}

	ch := make(chan *ldap.Conn)
	go func() {
		client := startConn(useSsl)
		if err := client.StartTLS(&tls.Config{
			InsecureSkipVerify: true,
		}); err != nil {
			client.Close()
		} else {
			ch <- client
		}
	}()

	var ret *ldap.Conn
	select {
	case ret = <-ch:
	case <-time.After(time.Second):
		ret = startConn(useSsl)
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
