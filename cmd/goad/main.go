package main

import (
	"fmt"
	"os"

	"github.com/5amu/goad/internal/runner"
	"github.com/jessevdk/go-flags"
)

type MainOptions struct {
	LDAP bool `long:"ldap" command:"ldap" description:"own stuff using LDAP"`
	SMB  bool `long:"smb" command:"smb" description:"own stuff using SMB"`
}

func main() {
	p := flags.NewNamedParser("GoAD", flags.Default)
	var mainOpts MainOptions
	p.AddGroup("Application Options", "", &mainOpts)

	if len(os.Args) < 2 {
		p.WriteHelp(os.Stdout)
		os.Exit(1)
	}

	if _, err := p.ParseArgs(os.Args[0:2]); err != nil {
		os.Exit(1)
	}

	if mainOpts.LDAP {
		if err := runner.ExecuteLdapSubcommand(os.Args[2:]); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}
}
