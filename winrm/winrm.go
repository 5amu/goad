package winrm

import (
	"context"
	"os"

	"github.com/masterzen/winrm"
)

type WinrmClient struct {
	Endpoint *winrm.Endpoint
	Client   *winrm.Client
}

func NewWinrmClient(host string, port int, ssl bool) *WinrmClient {
	return &WinrmClient{
		Endpoint: winrm.NewEndpoint(host, port, ssl, true, nil, nil, nil, 0),
	}
}

func (c *WinrmClient) Authenticate(username, password string) error {
	params := winrm.DefaultParameters
	params.TransportDecorator = func() winrm.Transporter { return &winrm.ClientNTLM{} }
	client, err := winrm.NewClientWithParameters(c.Endpoint, username, password, params)
	c.Client = client
	return err
}

func (c *WinrmClient) OpenShell(shell string) error {
	var cmd string
	switch shell {
	case "cmd":
		cmd = "cmd.exe"
	default:
		cmd = "powershell.exe"
	}
	_, err := c.Client.RunWithContextWithInput(context.TODO(), cmd, os.Stdout, os.Stderr, os.Stdin)
	return err
}

func (c *WinrmClient) Run(cmd string) error {
	_, err := c.Client.RunWithContext(context.TODO(), cmd, os.Stdout, os.Stderr)
	return err
}
