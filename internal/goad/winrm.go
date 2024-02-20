package goad

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"

	"github.com/5amu/goad/internal/printer"
	"github.com/5amu/goad/internal/utils"
	"github.com/5amu/goad/pkg/smb"
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
	} `group:"Connection Options" description:"Connection Options"`

	Mode struct {
		Exec  string `short:"x" description:"Execute command on target host"`
		Shell bool   `long:"shell" description:"Spawn a powershell shell"`
	} `group:"Execution Mode"`

	targets        []string
	target2SMBInfo map[string]*smb.SMBInfo
	credentials    []utils.Credential
	printMutex     sync.Mutex
	cmd            string
}

func (o *WinrmOptions) getFunction() func(string) {
	if o.Mode.Exec != "" {
		o.cmd = o.Mode.Exec
		return o.exec
	}
	if o.Mode.Shell {
		return o.openShell
	}
	return nil
}

func (o *WinrmOptions) Run() error {
	o.targets = utils.ExtractTargets(o.Targets.TARGETS)
	o.target2SMBInfo = gatherSMBInfoToMap(&o.printMutex, o.targets, o.Connection.Port)
	var f func(string) = o.getFunction()
	if f == nil {
		return nil
	}

	o.credentials = utils.NewCredentialsClusterBomb(
		utils.ExtractLinesFromFileOrString(o.Connection.Username),
		utils.ExtractLinesFromFileOrString(o.Connection.Password),
	)

	var wg sync.WaitGroup
	for _, target := range o.targets {
		wg.Add(1)
		go func(t string) {
			f(t)
			wg.Done()
		}(target)
	}
	wg.Wait()
	return nil
}

func (o *WinrmOptions) exec(target string) {
	prt := printer.NewPrinter("WINRM", target, o.target2SMBInfo[target].NetBIOSName, o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	var client *winrm.Client
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
			prt.StoreFailure(cred.String())
			continue
		} else {
			prt.StoreSuccess(cred.String())
			break
		}
	}

	var stdoutBuff, stderrBuff bytes.Buffer
	_, err := client.RunWithContext(context.Background(), o.cmd, &stdoutBuff, &stderrBuff)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}
	out := stdoutBuff.String() + stderrBuff.String()
	splitted := strings.Split(out, "\n")
	for _, s := range splitted[:len(splitted)-1] {
		prt.Store(s)
	}
}

func (o *WinrmOptions) openShell(target string) {
	prt := printer.NewPrinter("WINRM", target, o.target2SMBInfo[target].NetBIOSName, o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	if len(o.credentials) != 1 {
		prt.StoreFailure("provide 1 set of credentials")
		return
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
		if err != nil {
			prt.StoreFailure(err.Error())
			return
		}
	}
}
