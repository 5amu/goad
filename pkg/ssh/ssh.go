package ssh

import (
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

type Client struct {
	conn *ssh.Client
}

func connect(user string, signer ssh.AuthMethod, fullHost string) (*Client, error) {
	client, err := ssh.Dial("tcp",
		fullHost,
		&ssh.ClientConfig{
			User:            user,
			Auth:            []ssh.AuthMethod{signer},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         3 * time.Second,
		},
	)
	return &Client{
		conn: client,
	}, err
}

func ConnectWithPassword(user, pass string, host string, port int) (*Client, error) {
	return connect(user, ssh.Password(pass), fmt.Sprintf("%s:%d", host, port))
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
	return connect(user, ssh.PublicKeys(signer), fmt.Sprintf("%s:%d", host, port))
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