package goad

import (
	"bytes"
	"fmt"
	"strings"
	"sync"

	"github.com/5amu/goad/internal/printer"
	"github.com/5amu/goad/internal/utils"
	"github.com/5amu/goad/pkg/ssh"
)

type SshOptions struct {
	Targets struct {
		TARGETS []string `description:"Provide target IP/FQDN/FILE"`
	} `positional-args:"yes"`

	Connection struct {
		Username string `short:"u" description:"Provide username (or FILE)"`
		Password string `short:"p" description:"Provide password (or FILE)"`
		PrivKey  string `short:"k" long:"private-key" description:"Provide a path to a ssh private key without password"`
		Port     int    `long:"port" default:"22" description:"Port to contact"`
	} `group:"Connection Options" description:"Connection Options"`

	Mode struct {
		Exec  string `long:"exec" description:"Execute command on target host"`
		Shell bool   `long:"shell" description:"Spawn a shell"`
	} `group:"Execution Mode"`

	targets     []string
	credentials []utils.Credential
	cmd         string
}

func (o *SshOptions) Run() error {
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
		f = o.shell
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

func (o *SshOptions) exec(target string) error {
	banner, err := ssh.GrabBanner(fmt.Sprintf("%s:%d", target, o.Connection.Port))
	if err != nil {
		return err
	}
	prt := printer.NewPrinter("SSH", target, banner, o.Connection.Port)

	var c *ssh.Client
	for _, cred := range o.credentials {
		var err error
		if o.Connection.PrivKey != "" {
			c, err = ssh.ConnectWithKey(
				cred.Username,
				o.Connection.PrivKey,
				target,
				o.Connection.Port,
			)
		} else {
			c, err = ssh.ConnectWithPassword(
				o.Connection.Username,
				o.Connection.Password,
				target,
				o.Connection.Port,
			)
		}
		if err != nil {
			prt.PrintFailure(cred.String())
			continue
		} else {
			prt.PrintSuccess(cred.String())
			break
		}
	}

	var stdoutBuff, stderrBuff bytes.Buffer
	if err := c.Run(o.cmd, &stdoutBuff, &stderrBuff); err != nil {
		prt.PrintFailure(err.Error())
	}

	out := stdoutBuff.String() + stderrBuff.String()
	splitted := strings.Split(out, "\n")
	for _, s := range splitted {
		prt.Print(s)
	}
	return nil
}

func (o *SshOptions) shell(target string) error {
	if len(o.credentials) != 1 {
		return fmt.Errorf("provide 1 set of credentials")
	}

	var err error
	var c *ssh.Client
	if o.Connection.Password != "" {
		c, err = ssh.ConnectWithPassword(
			o.Connection.Username,
			o.Connection.Password,
			target,
			o.Connection.Port,
		)
	} else if o.Connection.PrivKey != "" {
		c, err = ssh.ConnectWithKey(
			o.Connection.Username,
			o.Connection.PrivKey,
			target,
			o.Connection.Port,
		)
	}
	if err != nil {
		return err
	}
	return c.Shell()
}
