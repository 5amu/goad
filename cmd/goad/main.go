package main

import (
	"fmt"
	"os"

	"github.com/5amu/goad/internal/runner"
	"github.com/jessevdk/go-flags"
)

type MainOptions struct {
	FTP   struct{}           `command:"ftp" description:"own stuff using SMB"`
	LDAP  runner.LdapOptions `command:"ldap" description:"own stuff using LDAP"`
	MSSQL struct{}           `command:"mssql" description:"own stuff using MSSQL"`
	RDP   struct{}           `command:"smb" description:"own stuff using RDP"`
	SMB   struct{}           `command:"smb" description:"own stuff using SMB"`
	SSH   struct{}           `command:"ssh" description:"own stuff using SSH"`
	VNC   struct{}           `command:"vnc" description:"own stuff using VNC"`
	WINRM struct{}           `command:"winrm" description:"own stuff using WINRM"`
	WMI   struct{}           `command:"wmi" description:"own stuff using WMI"`
}

func main() {
	p := flags.NewNamedParser("GoAD", flags.Default)
	var opts MainOptions
	p.AddGroup("Application Options", "", &opts)

	if _, err := p.Parse(); err != nil {
		os.Exit(1)
	}

	if p.Command.Find("ftp") == p.Active {
		//if err := opts.SMB.Run(); err != nil {
		//	fmt.Println(err)
		//}
	} else if p.Command.Find("ldap") == p.Active {
		if err := opts.LDAP.Run(); err != nil {
			fmt.Println(err)
		}
	} else if p.Command.Find("mssql") == p.Active {
		//if err := opts.SMB.Run(); err != nil {
		//	fmt.Println(err)
		//}
	} else if p.Command.Find("rdp") == p.Active {
		//if err := opts.SMB.Run(); err != nil {
		//	fmt.Println(err)
		//}
	} else if p.Command.Find("smb") == p.Active {
		//if err := opts.SMB.Run(); err != nil {
		//	fmt.Println(err)
		//}
	} else if p.Command.Find("ssh") == p.Active {
		//if err := opts.SMB.Run(); err != nil {
		//	fmt.Println(err)
		//}
	} else if p.Command.Find("vnc") == p.Active {
		//if err := opts.SMB.Run(); err != nil {
		//	fmt.Println(err)
		//}
	} else if p.Command.Find("winrm") == p.Active {
		//if err := opts.SMB.Run(); err != nil {
		//	fmt.Println(err)
		//}
	} else if p.Command.Find("wmi") == p.Active {
		//if err := opts.SMB.Run(); err != nil {
		//	fmt.Println(err)
		//}
	}
}
