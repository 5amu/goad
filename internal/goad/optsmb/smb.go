package optsmb

import (
	"fmt"
	"os"
	"slices"
	"sync"

	"github.com/5amu/goad/internal/printer"
	"github.com/5amu/goad/internal/utils"
	"github.com/5amu/goad/pkg/proxyconn"
	"github.com/5amu/goad/pkg/smb"
	"github.com/fatih/color"
)

type Options struct {
	Targets struct {
		TARGETS []string `description:"Provide target IP/FQDN/FILE"`
	} `positional-args:"yes"`

	Connection struct {
		Username string `short:"u" description:"Provide username (or FILE)"`
		Password string `short:"p" description:"Provide password (or FILE)"`
		NTLM     string `short:"H" long:"hashes" description:"authenticate with NTLM hash"`
		Domain   string `short:"d" long:"domain" description:"provide domain"`
		Port     int    `long:"port" default:"445" description:"Provide SMB port"`
	} `group:"Connection Options" description:"Connection Options"`

	Shares bool `long:"shares" description:"list open shares"`

	credentials    []utils.Credential
	target2SMBInfo map[string]*smb.SMBFingerprint
	printMutex     sync.Mutex
	targets        []string
}

func (o *Options) getFunction() func(string) {
	if o.Shares {
		return o.enumShares
	}
	return o.testCredentials
}

func (o *Options) Run() {
	o.targets = utils.ExtractTargets(o.Targets.TARGETS)
	o.target2SMBInfo = GatherSMBInfoToMap(o.targets, o.Connection.Port)
	var f func(string) = o.getFunction()

	o.credentials = utils.NewCredentialsDispacher(
		o.Connection.Username,
		o.Connection.Password,
		o.Connection.NTLM,
		utils.Clusterbomb,
	)

	if !slices.Contains(os.Args, "-u") {
		return
	}

	var wg sync.WaitGroup
	for t := range o.target2SMBInfo {
		wg.Add(1)
		go func(g string) {
			f(g)
			wg.Done()
		}(t)
	}
	wg.Wait()
}

func (o *Options) testCredentials(target string) {
	prt := printer.NewPrinter("SMB", target, o.target2SMBInfo[target].NetBIOSComputerName, 445)
	defer prt.PrintStored(&o.printMutex)

	var domain string = o.Connection.Domain
	if o.Connection.Domain == "" {
		domain = o.target2SMBInfo[target].DNSDomainName
	}

	client := NewClient(target, DefaultPort, domain)

	var valid bool = false
	for _, creds := range o.credentials {
		if creds.Hash != "" {
			if err := client.AuthenticateWithHash(creds.Username, creds.Hash); err != nil {
				prt.StoreFailure(creds.StringWithDomain(domain))
			} else {
				valid = true
				if client.AdminShareWritable() {
					prt.StoreSuccess(creds.StringWithDomain(domain) + color.YellowString(" (Pwn3d!)"))
				} else {
					prt.StoreSuccess(creds.StringWithDomain(domain))
				}
			}
		} else {
			if err := client.Authenticate(creds.Username, creds.Password); err != nil {
				prt.StoreFailure(creds.StringWithDomain(domain))
			} else {
				valid = true
				if client.AdminShareWritable() {
					prt.StoreSuccess(creds.StringWithDomain(domain) + color.YellowString(" (Pwn3d!)"))
				} else {
					prt.StoreSuccess(creds.StringWithDomain(domain))
				}
			}
		}
	}
	if !valid {
		prt.StoreFailure("no valid authentication")
	}
}

func (o *Options) authenticate(host string, port int) (*smb.Session, utils.Credential, error) {
	prt := printer.NewPrinter("SMB", host, o.target2SMBInfo[host].NetBIOSComputerName, 445)
	defer prt.PrintStored(&o.printMutex)

	var domain string = o.Connection.Domain
	if o.Connection.Domain == "" {
		domain = o.target2SMBInfo[host].DNSDomainName
	}

	for _, creds := range o.credentials {
		conn, err := proxyconn.GetConnection(host, port)
		if err != nil {
			return nil, utils.Credential{}, err
		}
		opts := smb.Options{
			Conn:   conn,
			User:   creds.Username,
			Domain: domain,
		}

		if creds.Hash != "" {
			opts.Hash = creds.Hash
		} else {
			opts.User = creds.Username
		}

		s, err := smb.NewSession(opts)
		if err == nil {
			prt.StoreSuccess(creds.StringWithDomain(domain))
			if AdminShareWritable(s) {
				prt.StoreSuccess(creds.StringWithDomain(domain) + color.YellowString(" (Pwn3d!)"))
			} else {
				prt.StoreSuccess(creds.StringWithDomain(domain))
			}
			return s, creds, nil
		}
	}
	return nil, utils.Credential{}, fmt.Errorf("no valid authentication")
}

/*
func shareToSlice(s Share) []string {
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
*/

func (o *Options) enumShares(target string) {
	prt := printer.NewPrinter("SMB", target, o.target2SMBInfo[target].NetBIOSComputerName, 445)
	defer prt.PrintStored(&o.printMutex)

	/*var domain string = o.Connection.Domain
	if o.Connection.Domain == "" {
		domain = o.target2SMBInfo[target].DNSDomainName
	}
	client := NewClient(target, 445, domain)

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
	*/
}
