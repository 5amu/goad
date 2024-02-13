package goad

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/5amu/goad/internal/printer"
	"github.com/5amu/goad/internal/utils"
	"github.com/masterzen/winrm"
)

type WinrmOptions struct {
	Targets struct {
		TARGETS []string `description:"Provide target IP/FQDN/FILE"`
	} `positional-args:"yes"`

	Connection struct {
		Port     int    `long:"port" default:"5985"`
		SSL      bool   `long:"ssl" description:"Encrypt Winrm connection"`
		Username string `short:"u" description:"Provide username (or FILE)"`
		Password string `short:"p" description:"Provide password (or FILE)"`
		Domain   string `short:"d" long:"domain" description:"Provide domain"`
	} `group:"Connection Options" description:"Connection Options"`

	Mode struct {
		Exec  string `short:"x" description:"Execute command on target host"`
		Shell bool   `long:"shell" description:"Spawn a powershell shell"`
	} `group:"Execution Mode"`

	targets     []string
	credentials []utils.Credential
	cmd         string
}

func (o *WinrmOptions) Run() error {
	for _, t := range o.Targets.TARGETS {
		o.targets = append(o.targets, sliceFromString(t)...)
	}

	o.credentials = utils.NewCredentialsClusterBomb(
		sliceFromString(o.Connection.Username),
		sliceFromString(o.Connection.Password),
	)

	var f func(string) error
	if o.Mode.Exec != "" {
		o.cmd = o.Mode.Exec
		f = o.exec
	} else if o.Mode.Shell {
		f = o.openShell
	} else {
		return fmt.Errorf("nothing to do")
	}

	var wg sync.WaitGroup
	for _, target := range o.targets {
		wg.Add(1)
		go func(t string) {
			if err := f(t); err != nil {
				fmt.Println(err)
			}
			wg.Done()
		}(target)
	}
	wg.Wait()
	return nil
}

func (o *WinrmOptions) exec(target string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var client *winrm.Client
	prt := printer.NewPrinter("WINRM", target, "", o.Connection.Port)
	for _, cred := range o.credentials {
		var err error
		params := winrm.DefaultParameters
		params.TransportDecorator = func() winrm.Transporter { return &winrm.ClientNTLM{} }
		client, err = winrm.NewClientWithParameters(
			winrm.NewEndpoint(target, o.Connection.Port, o.Connection.SSL, true, nil, nil, nil, 0),
			cred.Username,
			cred.Password,
			params,
		)
		if err != nil {
			prt.PrintFailure(cred.StringWithDomain(o.Connection.Domain))
			continue
		} else {
			prt.PrintSuccess(cred.StringWithDomain(o.Connection.Domain))
			break
		}
	}

	var stdoutBuff, stderrBuff bytes.Buffer
	_, err := client.RunWithContext(ctx, o.cmd, &stdoutBuff, &stderrBuff)
	if err != nil {
		return err
	}
	out := stdoutBuff.String() + stderrBuff.String()
	splitted := strings.Split(out, "\n")
	for _, s := range splitted {
		prt.Print(s)
	}
	return nil
}

func (o *WinrmOptions) openShell(target string) error {
	if len(o.credentials) != 1 {
		return fmt.Errorf("provide 1 set of credentials")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, cred := range o.credentials {
		params := winrm.DefaultParameters
		params.TransportDecorator = func() winrm.Transporter { return &winrm.ClientNTLM{} }
		client, err := winrm.NewClientWithParameters(
			winrm.NewEndpoint(target, o.Connection.Port, o.Connection.SSL, true, nil, nil, nil, 0),
			cred.Username,
			cred.Password,
			params,
		)
		if err != nil {
			continue
		}

		_, err = client.RunWithContextWithInput(ctx, "powershell.exe", os.Stdout, os.Stderr, os.Stdin)
		return err
	}
	return nil
}
