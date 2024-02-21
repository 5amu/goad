package goad

import (
	"fmt"
	"strings"
	"sync"

	"github.com/5amu/goad/internal/printer"
	"github.com/5amu/goad/internal/utils"
	"github.com/5amu/goad/pkg/smb"
	"github.com/fatih/color"
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

	Shares bool `long:"shares" description:"list open shares"`

	credentials    []utils.Credential
	target2SMBInfo map[string]*smb.SMBInfo
	printMutex     sync.Mutex
	targets        []string
}

func (o *SmbOptions) getFunction() func(string) {
	if o.Shares {
		return o.enumShares
	}
	return o.testCredentials
}

func (o *SmbOptions) Run() error {
	o.targets = utils.ExtractTargets(o.Targets.TARGETS)
	o.target2SMBInfo = utils.GatherSMBInfoToMap(&o.printMutex, o.targets, 445)
	var f func(string) = o.getFunction()

	o.credentials = utils.NewCredentialsDispacher(
		o.Connection.Username,
		o.Connection.Password,
		o.Connection.NTLM,
		utils.Clusterbomb,
	)

	var wg sync.WaitGroup
	for t := range o.target2SMBInfo {
		wg.Add(1)
		go func(g string) {
			f(g)
			wg.Done()
		}(t)
	}
	wg.Wait()
	return nil
}

func (o *SmbOptions) testCredentials(target string) {
	client := smb.NewClient(target, 445, o.Connection.Domain)

	prt := printer.NewPrinter("SMB", client.Host, o.target2SMBInfo[client.Host].NetBIOSName, 445)
	defer prt.PrintStored(&o.printMutex)

	var valid bool = false
	for _, creds := range o.credentials {
		if creds.Hash != "" {
			if err := client.AuthenticateWithHash(creds.Username, creds.Hash); err != nil {
				prt.StoreFailure(creds.StringWithDomain(o.Connection.Domain))
			} else {
				valid = true
				if client.AdminShareWritable() {
					prt.StoreSuccess(creds.StringWithDomain(o.Connection.Domain) + color.YellowString(" (Pwn3d!)"))
				} else {
					prt.StoreSuccess(creds.StringWithDomain(o.Connection.Domain))
				}
			}
		} else {
			if err := client.Authenticate(creds.Username, creds.Password); err != nil {
				prt.StoreFailure(creds.StringWithDomain(o.Connection.Domain))
			} else {
				valid = true
				if client.AdminShareWritable() {
					prt.StoreSuccess(creds.StringWithDomain(o.Connection.Domain) + color.YellowString(" (Pwn3d!)"))
				} else {
					prt.StoreSuccess(creds.StringWithDomain(o.Connection.Domain))
				}
			}
		}
	}
	if !valid {
		prt.StoreFailure("no valid authentication")
	}
}

func (o *SmbOptions) authenticate(client *smb.Client) (utils.Credential, error) {
	prt := printer.NewPrinter("SMB", client.Host, o.target2SMBInfo[client.Host].NetBIOSName, 445)
	defer prt.PrintStored(&o.printMutex)

	for _, creds := range o.credentials {
		if creds.Hash != "" {
			if err := client.AuthenticateWithHash(creds.Username, creds.Hash); err != nil {
				prt.StoreFailure(creds.StringWithDomain(o.Connection.Domain))
			} else {
				if client.AdminShareWritable() {
					prt.StoreSuccess(creds.StringWithDomain(o.Connection.Domain) + color.YellowString(" (Pwn3d!)"))
				} else {
					prt.StoreSuccess(creds.StringWithDomain(o.Connection.Domain))
				}
				return creds, nil
			}
		} else {
			if err := client.Authenticate(creds.Username, creds.Password); err != nil {
				prt.StoreFailure(creds.StringWithDomain(o.Connection.Domain))
			} else {
				if client.AdminShareWritable() {
					prt.StoreSuccess(creds.StringWithDomain(o.Connection.Domain) + color.YellowString(" (Pwn3d!)"))
				} else {
					prt.StoreSuccess(creds.StringWithDomain(o.Connection.Domain))
				}
				return creds, nil
			}
		}
	}
	return utils.Credential{}, fmt.Errorf("no valid authentication")
}

func shareToSlice(s smb.Share) []string {
	var out []string
	out = append(out, s.Name)

	var builder strings.Builder
	if s.Readable {
		builder.WriteString("READ")
	}
	if s.Writable {
		builder.WriteString(",WRITE")
	}
	return append(out, builder.String())
}

func (o *SmbOptions) enumShares(target string) {
	prt := printer.NewPrinter("SMB", target, o.target2SMBInfo[target].NetBIOSName, 445)
	defer prt.PrintStored(&o.printMutex)

	client := smb.NewClient(target, 445, o.Connection.Domain)

	if _, err := o.authenticate(client); err != nil {
		prt.StoreFailure(err.Error())
	}

	sh, err := client.ListShares()
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	prt.StoreSuccess("Listing shares: ")
	for _, s := range sh {
		prt.Store(shareToSlice(s)...)
	}
}
