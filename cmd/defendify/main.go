package main

import (
	"fmt"
	"os"

	"github.com/5amu/goad/internal/defendify"
	"github.com/5amu/goad/ldap"
	"github.com/jessevdk/go-flags"
)

type Options struct {
	Targets struct {
		TARGET string `description:"Provide target IP/FQDN of a Domain Controller"`
	} `positional-args:"yes"`
	Username string `short:"u" description:"Provide a username"`
	Password string `short:"p" description:"Provide a password"`
	NTLM     string `short:"H" long:"hashes" description:"authenticate with NTLM hash"`
	Domain   string `short:"d" long:"domain" description:"Provide domain"`
	Outfile  string `short:"o" default:"report.xlsx" description:"Provide output file"`
	Port     int    `long:"port" default:"389" description:"Ldap port to contact"`
	SSL      bool   `short:"s" long:"ssl" description:"Use ssl to interact with ldap"`
	UseTLS   bool   `long:"tls" description:"Upgrade the ldap connection"`
}

func (o *Options) authenticate(lclient *ldap.LdapClient) error {
	if o.NTLM != "" {
		return lclient.AuthenticateNTLM(o.Username, o.NTLM)
	}
	return lclient.Authenticate(o.Username, o.Password)
}

func main() {
	p := flags.NewNamedParser("Defendify", flags.Default)

	var opts Options
	p.AddGroup("Application Options", "", &opts)

	if _, err := p.Parse(); err != nil {
		os.Exit(1)
	}

	lclient := ldap.NewLdapClient(opts.Targets.TARGET, opts.Port, opts.Domain, opts.SSL, !opts.UseTLS)
	defer lclient.Close()

	if err := opts.authenticate(lclient); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if err := defendify.NewEngine(lclient, opts.Outfile).Run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
