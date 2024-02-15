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

	credentials []utils.Credential
	targets     []string
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

func (o *SmbOptions) Run() error {
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

	o.targets = utils.ExtractTargets(o.Targets.TARGETS)

	var wg sync.WaitGroup
	for _, t := range o.targets {
		wg.Add(1)
		go func(g string) {
			getSMBInfo(g)
			wg.Done()
		}(t)
	}
	wg.Wait()
	return nil
}
