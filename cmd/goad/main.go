package main

import (
	"fmt"
	"os"

	"github.com/5amu/go-flags"
	"github.com/5amu/goad/internal/goad"
)

type MainOptions struct {
	FTP   goad.FtpOptions   `command:"ftp" description:"own stuff using SMB"`
	LDAP  goad.LdapOptions  `command:"ldap" description:"own stuff using LDAP"`
	KRB5  goad.Krb5Options  `command:"krb5" description:"own stuff using Kerberos"`
	MSSQL goad.MssqlOptions `command:"mssql" description:"own stuff using MSSQL"`
	RDP   goad.RdpOptions   `command:"rdp" description:"own stuff using RDP"`
	SMB   goad.SmbOptions   `command:"smb" description:"own stuff using SMB"`
	SSH   goad.SshOptions   `command:"ssh" description:"own stuff using SSH"`
	VNC   goad.VncOptions   `command:"vnc" description:"own stuff using VNC"`
	WINRM goad.WinrmOptions `command:"winrm" description:"own stuff using WINRM"`
	WMI   goad.WmiOptions   `command:"wmi" description:"own stuff using WMI"`
}

func main() {
	p := flags.NewNamedParser("GoAD", flags.Default)

	var opts MainOptions
	_, err := p.AddGroup("Application Options", "", &opts)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if _, err := p.Parse(); err != nil {
		os.Exit(1)
	}

	fmt.Println()
	defer fmt.Println()

	if p.Command.Find("ftp") == p.Active {
		if err := opts.FTP.Run(); err != nil {
			fmt.Println(err)
		}
	} else if p.Command.Find("ldap") == p.Active {
		if err := opts.LDAP.Run(); err != nil {
			fmt.Println(err)
		}
	} else if p.Command.Find("krb5") == p.Active {
		if err := opts.KRB5.Run(); err != nil {
			fmt.Println(err)
		}
	} else if p.Command.Find("mssql") == p.Active {
		if err := opts.MSSQL.Run(); err != nil {
			fmt.Println(err)
		}
	} else if p.Command.Find("rdp") == p.Active {
		if err := opts.RDP.Run(); err != nil {
			fmt.Println(err)
		}
	} else if p.Command.Find("smb") == p.Active {
		if err := opts.SMB.Run(); err != nil {
			fmt.Println(err)
		}
	} else if p.Command.Find("ssh") == p.Active {
		if err := opts.SSH.Run(); err != nil {
			fmt.Println(err)
		}
	} else if p.Command.Find("vnc") == p.Active {
		if err := opts.VNC.Run(); err != nil {
			fmt.Println(err)
		}
	} else if p.Command.Find("winrm") == p.Active {
		if err := opts.WINRM.Run(); err != nil {
			fmt.Println(err)
		}
	} else if p.Command.Find("wmi") == p.Active {
		if err := opts.WMI.Run(); err != nil {
			fmt.Println(err)
		}
	}
}
