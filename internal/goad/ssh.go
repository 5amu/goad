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

	targets       []string
	target2Banner map[string]string
	printMutex    sync.Mutex
	credentials   []utils.Credential
	cmd           string
}

func gatherSSHBanner2Map(mutex *sync.Mutex, targets []string, port int) map[string]string {
	res := make(map[string]string)
	var mapMutex sync.Mutex

	mutex.Lock()
	defer mutex.Unlock()

	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(p string) {
			s, err := ssh.GrabBanner(fmt.Sprintf("%s:%d", p, port))
			prt := printer.NewPrinter("SSH", p, s, port)
			if err == nil {
				mapMutex.Lock()
				res[p] = s
				mapMutex.Unlock()
				prt.PrintInfo(s)
			}
			wg.Done()
		}(t)
	}
	wg.Wait()
	return res
}

func (o *SshOptions) Run() error {
	o.targets = utils.ExtractTargets(o.Targets.TARGETS)
	o.credentials = utils.NewCredentialsClusterBomb(
		utils.ExtractLinesFromFileOrString(o.Connection.Username),
		utils.ExtractLinesFromFileOrString(o.Connection.Password),
	)

	o.target2Banner = gatherSSHBanner2Map(&o.printMutex, o.targets, o.Connection.Port)

	var f func(string)
	if o.Mode.Exec != "" {
		o.cmd = o.Mode.Exec
		f = o.exec
	} else if o.Mode.Shell {
		f = o.shell
	} else {
		return nil
	}

	var wg sync.WaitGroup
	for _, target := range o.targets {
		wg.Add(1)
		go func(t string) {
			o.printMutex.Lock()
			f(t)
			o.printMutex.Unlock()
			wg.Done()
		}(target)
	}
	wg.Wait()
	return nil
}

func (o *SshOptions) authenticate(target string) (*ssh.Client, error) {
	prt := printer.NewPrinter("SSH", target, o.target2Banner[target], o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

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
			prt.StoreFailure(cred.String())
			continue
		}
		prt.StoreSuccess(cred.String())
		return c, nil
	}
	return nil, fmt.Errorf("no valid credential provided")
}

func (o *SshOptions) exec(target string) {
	prt := printer.NewPrinter("SSH", target, o.target2Banner[target], o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	c, err := o.authenticate(target)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	var stdoutBuff, stderrBuff bytes.Buffer
	if err := c.Run(o.cmd, &stdoutBuff, &stderrBuff); err != nil {
		prt.StoreFailure(err.Error())
	}

	out := stdoutBuff.String() + stderrBuff.String()
	splitted := strings.Split(out, "\n")
	for _, s := range splitted[:len(splitted)-1] {
		prt.Store(s)
	}
}

func (o *SshOptions) shell(target string) {
	prt := printer.NewPrinter("SSH", target, o.target2Banner[target], o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	if len(o.credentials) != 1 {
		prt.StoreFailure("provide 1 set of credentials")
		return
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
		prt.StoreFailure(err.Error())
		return
	}
	err = c.Shell()
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}
}
