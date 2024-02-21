package goad

import (
	"sync"

	"github.com/5amu/goad/internal/utils"
	"github.com/5amu/goad/pkg/smb"
)

type SmbOptions struct {
	Targets struct {
		TARGETS []string `description:"Provide target IP/FQDN/FILE"`
	} `positional-args:"yes"`

	Connection struct {
		Username string `short:"u" description:"Provide username (or FILE)"`
		Password string `short:"p" description:"Provide password (or FILE)"`
		NTLM     string `short:"H" long:"hashes" description:"authenticate with NTLM hash"`
		Domain   string `short:"d" long:"domain" description:"Provide domain"`
	} `group:"Connection Options" description:"Connection Options"`

	credentials    []utils.Credential
	target2SMBInfo map[string]*smb.SMBInfo
	printMutex     sync.Mutex
	targets        []string
}

func (o *SmbOptions) Run() error {
	o.targets = utils.ExtractTargets(o.Targets.TARGETS)
	o.target2SMBInfo = utils.GatherSMBInfoToMap(&o.printMutex, o.targets, 445)
	var f func(string) //= o.getFunction()
	if f == nil {
		return nil
	}

	o.credentials = utils.NewCredentialsDispacher(
		o.Connection.Username,
		o.Connection.Password,
		o.Connection.NTLM,
		utils.Clusterbomb,
	)

	var wg sync.WaitGroup
	for _, t := range o.targets {
		wg.Add(1)
		go func(g string) {
			o.printMutex.Lock()
			f(g)
			o.printMutex.Unlock()
			wg.Done()
		}(t)
	}
	wg.Wait()
	return nil
}
