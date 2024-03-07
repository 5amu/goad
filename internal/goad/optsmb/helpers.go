package optsmb

import (
	"context"
	"os"
	"strings"

	"github.com/5amu/goad/pkg/proxyconn"
	"github.com/hirochachacha/go-smb2"
)

const DefaultPort = 445

type Client struct {
	Host    string
	Port    int
	Domain  string
	session *smb2.Session
}

func NewClient(host string, port int, domain string) *Client {
	return &Client{
		Host:   host,
		Port:   port,
		Domain: domain,
	}
}

func (c *Client) authenticate(username, password, hash string) error {
	conn, err := proxyconn.GetConnection(c.Host, c.Port)
	if err != nil {
		return err
	}

	var initiator smb2.NTLMInitiator
	if password != "" {
		initiator = smb2.NTLMInitiator{
			User:     username,
			Password: password,
			Domain:   c.Domain,
		}
	} else {
		initiator = smb2.NTLMInitiator{
			User:   username,
			Hash:   []byte(hash),
			Domain: c.Domain,
		}
	}

	d := &smb2.Dialer{
		Initiator: &initiator,
	}

	session, err := d.DialContext(context.TODO(), conn)
	if err != nil {
		return err
	}

	c.session = session
	return nil
}

func (c *Client) Authenticate(username, password string) error {
	return c.authenticate(username, password, "")
}

func (c *Client) AuthenticateWithHash(username, hash string) error {
	return c.authenticate(username, "", hash)
}

type Share struct {
	Name     string
	Readable bool
	Writable bool
}

func (c *Client) ListSharenames() ([]string, error) {
	return c.session.ListSharenames()
}

func (c *Client) ListShares() ([]Share, error) {
	sh, err := c.session.ListSharenames()
	if err != nil {
		return nil, err
	}

	var res []Share
	for _, sname := range sh {
		if strings.EqualFold(sname, "IPC$") {
			res = append(res, Share{
				Name:     sname,
				Readable: true,
				Writable: false,
			})
			continue
		}
		var readable bool = false
		var writable bool = false

		fs, err := c.session.Mount(sname)
		if err != nil {
			res = append(res, Share{
				Name:     sname,
				Readable: readable,
				Writable: writable,
			})
			continue
		}
		readable = true

		err = fs.WriteFile("goadtest.txt", []byte("test"), 0444)
		writable = !os.IsPermission(err)
		if writable {
			// cleanup
			_ = fs.Remove("goadtest.txt")
		}

		_ = fs.Umount()

		res = append(res, Share{
			Name:     sname,
			Readable: readable,
			Writable: writable,
		})
	}
	return res, nil
}

func (c *Client) AdminShareWritable() bool {
	fs, err := c.session.Mount("ADMIN$")
	if err != nil {
		return false
	}
	defer func() {
		_ = fs.Umount()
	}()

	err = fs.WriteFile("goadtest.txt", []byte("test"), 0444)
	if !os.IsPermission(err) {
		// cleanup
		_ = fs.Remove("goadtest.txt")
	}
	return !os.IsPermission(err)
}
