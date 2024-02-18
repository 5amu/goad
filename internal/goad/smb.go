package goad

import (
	"sync"

	"github.com/5amu/goad/internal/printer"
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

func getSMBInfo(host string) *smb.SMBInfo {
	data, err := smb.GatherSMBInfo(host)
	if err != nil {
		return data
	}
	prt := printer.NewPrinter("SMB", host, data.NetBIOSName, 445)
	prt.PrintInfo(data.String())
	return data
}

func gatherSMBInfoToMap(mutex *sync.Mutex, targets []string, port int) map[string]*smb.SMBInfo {
	ret := make(map[string]*smb.SMBInfo)
	var wg sync.WaitGroup

	mutex.Lock()
	defer mutex.Unlock()

	var mapMutex sync.Mutex
	for _, t := range targets {
		wg.Add(1)
		go func(s string) {
			v := getSMBInfo(s)
			if v != nil {
				mapMutex.Lock()
				ret[s] = v
				mapMutex.Unlock()
			}
			wg.Done()
		}(t)
	}
	wg.Wait()
	return ret
}

func (o *SmbOptions) Run() error {
	o.targets = utils.ExtractTargets(o.Targets.TARGETS)
	o.target2SMBInfo = gatherSMBInfoToMap(&o.printMutex, o.targets, 445)
	var f func(string) //= o.getFunction()
	if f == nil {
		return nil
	}

	if o.Connection.NTLM != "" {
		o.credentials = utils.NewCredentialsNTLM(
			utils.ExtractLinesFromFileOrString(o.Connection.Username),
			o.Connection.NTLM,
		)
	} else {
		o.credentials = utils.NewCredentialsClusterBomb(
			utils.ExtractLinesFromFileOrString(o.Connection.Username),
			utils.ExtractLinesFromFileOrString(o.Connection.Password),
		)
	}

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
