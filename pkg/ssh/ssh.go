package ssh

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/5amu/goad/pkg/utils"
	zgrab "github.com/zmap/zgrab2/lib/ssh"
	"golang.org/x/crypto/ssh"
)

type Client struct {
	conn *ssh.Client
}

func connect(user string, signer ssh.AuthMethod, host string, port int) (*Client, error) {
	conn, err := utils.GetConnection(host, port)
	if err != nil {
		return nil, err
	}
	c, ch, req, err := ssh.NewClientConn(conn, fmt.Sprintf("%s:%d", host, port), &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{signer},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	return &Client{
		conn: ssh.NewClient(c, ch, req),
	}, err
}

func ConnectWithPassword(user, pass string, host string, port int) (*Client, error) {
	return connect(user, ssh.Password(pass), host, port)
}

func ConnectWithKey(user, keyPath string, host string, port int) (*Client, error) {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}
	return connect(user, ssh.PublicKeys(signer), host, port)
}

func (c *Client) Run(cmd string, stdout, stderr io.Writer) error {
	session, err := c.conn.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	session.Stdout = stdout
	session.Stderr = stderr
	if err := session.Run(cmd); err != nil {
		switch err.(type) {
		// ExitMissingError is returned when a command does not
		// return an exit code. This means that it could have timed
		// out, or whatever shenanigan the network can do.
		case *ssh.ExitMissingError:
			return fmt.Errorf("command didn't execute: %v", err)

		// ExitError will be returned if a command returned a non 0
		// code after being executed, for our means, we don't care
		// and we want to treat it as a correct behavior.
		case *ssh.ExitError:
			break

		// Any other error would be an I/O error, so we want to return
		// the error to the caller.
		default:
			return err
		}
	}
	return nil
}

func (c *Client) Shell() error {
	session, err := c.conn.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}
	if err := session.RequestPty("xterm-256color", 80, 40, modes); err != nil {
		return err
	}

	//set input and output
	session.Stdout = os.Stdout
	session.Stdin = os.Stdin
	session.Stderr = os.Stderr

	if err := session.Shell(); err != nil {
		return err
	}
	return session.Wait()
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func GrabBanner(host string, port int) (string, error) {
	data := new(zgrab.HandshakeLog)

	sshConfig := zgrab.MakeSSHConfig()
	sshConfig.Timeout = 10 * time.Second
	sshConfig.ConnLog = data
	sshConfig.DontAuthenticate = true
	sshConfig.BannerCallback = func(banner string) error {
		data.Banner = strings.TrimSpace(banner)
		return nil
	}

	conn, err := utils.GetConnection(host, port)
	if err != nil {
		return "", err
	}
	c, ch, req, err := zgrab.NewClientConn(conn, fmt.Sprintf("%s:%d", host, port), sshConfig)
	if err != nil {
		return "", err
	}

	client := zgrab.NewClient(c, ch, req)
	defer client.Close()
	return data.ServerID.SoftwareVersion, nil
}
