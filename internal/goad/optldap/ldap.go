package optldap

import (
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/5amu/goad/internal/printer"
	"github.com/5amu/goad/internal/utils"
	"github.com/5amu/goad/pkg/smb"
	"github.com/go-ldap/ldap/v3"
)

type Options struct {
	Targets struct {
		TARGETS []string `description:"Provide target IP/FQDN/FILE"`
	} `positional-args:"yes"`

	Connection struct {
		Username    string `short:"u" description:"Provide username (or FILE)"`
		Password    string `short:"p" description:"Provide password (or FILE)"`
		NullSession bool   `long:"null-session" description:"Authenticate with null credentials"`
		NTLM        string `short:"H" long:"hashes" description:"Authenticate with NTLM hash"`
		Domain      string `short:"d" long:"domain" description:"Provide domain"`
		Port        int    `long:"port" default:"389" description:"Ldap port to contact"`
		SSL         bool   `short:"s" long:"ssl" description:"Use ssl to interact with ldap"`
	} `group:"Connection Options" description:"Connection Options"`

	Hashes struct {
		AsrepRoast string `long:"asreproast" description:"Grab AS_REP ticket(s) parsed to be cracked with hashcat"`
		Kerberoast string `long:"kerberoast" description:"Grab TGS ticket(s) parsed to be cracked with hashcat"`
	} `group:"Hash Retrieval Options" description:"Hash Retrieval Options"`

	// CRUD
	// Create / Read / Update / Delete

	// Create
	Create struct {
	} `group:"Create Options" description:"Create Options"`

	// Read
	Read struct {
		CustomFilter         string `short:"f" long:"filter" description:"Bring your own filter"`
		CustomAttributes     string `short:"a" long:"attributes" description:"Ask your attributes (comma separated)"`
		TrustedForDelegation bool   `long:"trusted-for-delegation" description:"Get the list of users and computers with flag TRUSTED_FOR_DELEGATION"`
		PasswordNotRequired  bool   `long:"password-not-required" description:"Get the list of users with flag PASSWD_NOTREQD"`
		PasswordNeverExpires bool   `long:"password-never-expires" description:"Get the list of accounts with flag DONT_EXPIRE_PASSWD"`
		AdminCount           bool   `long:"admin-count" description:"Get objets that had the value adminCount=1"`
		Users                bool   `long:"users" description:"Enumerate enabled domain users"`
		User                 string `long:"user" description:"Find data about a single user"`
		Computers            bool   `long:"computers" description:"Enumerate computers in the domain"`
		ActiveUsers          bool   `long:"active-users" description:"Enumerate active enabled domain users"`
		Groups               bool   `long:"groups" description:"Enumerate domain groups"`
		DCList               bool   `long:"dc-list" description:"Enumerate Domain Controllers"`
		GetSID               bool   `long:"get-sid" description:"Get domain sid"`
		GMSA                 bool   `long:"gmsa" description:"Enumerate GMSA passwords"`
		Not                  bool   `long:"not" description:"Negate next filter"`
	} `group:"Read Options" description:"Read Options"`

	// Update
	Update struct {
	} `group:"Update Options" description:"Update Options"`

	// Delete
	Delete struct {
	} `group:"Delete Options" description:"Delete Options"`

	/*
		BH struct {
			Bloodhound           string   `long:"bloodhound" description:"Run bloodhound collector (v4.2) and save in output file (zip)"`
			BloodhoundNameserver string   `short:"n" long:"nameserver" description:"Provide a nameserver for bloodhound collector"`
			Collection           []string `short:"c" long:"collection" default:"Default" description:"Which information to collect. Supported: Group, LocalAdmin, Session, Trusts, Default, DCOnly, DCOM, RDP, PSRemote, LoggedOn, Container, ObjectProps, ACL, All"`
		} `group:"Run Bloodhound Collector v4.2" description:"Run Bloodhound Collector v4.2"`
	*/

	target2SMBInfo map[string]*smb.SMBInfo
	filters        []string
	filter         string
	attributes     []string
	printMutex     sync.Mutex
	credentials    []utils.Credential
}

type ExecutionFunction int

const (
	Undefined ExecutionFunction = iota
	Enumeration
	Kerberoast
	Asreproast
)

func (o *Options) parallelExecution(runner func(string)) {
	if len(o.filters) == 1 {
		o.filter = o.filters[0]
	} else {
		o.filter = JoinFilters(o.filters...)
	}
	var wg sync.WaitGroup
	for target := range o.target2SMBInfo {
		wg.Add(1)
		go func(t string) {
			if IsLDAP(t, o.Connection.Port) {
				runner(t)
			}
			wg.Done()
		}(target)
	}
	wg.Wait()
}

func (o *Options) Run() {
	o.target2SMBInfo = utils.GatherSMBInfoToMap(
		utils.ExtractTargets(o.Targets.TARGETS),
		o.Connection.Port,
	)

	if !o.Connection.NullSession {
		o.credentials = utils.NewCredentialsDispacher(
			o.Connection.Username,
			o.Connection.Password,
			o.Connection.NTLM,
			utils.Clusterbomb,
		)
	}

	switch o.parseH() {
	case Asreproast:
		o.parallelExecution(o.asreproast)
		return
	case Kerberoast:
		o.parallelExecution(o.kerberoast)
		return
	}

	if o.parseR(os.Args[2:]) == Enumeration {
		o.parallelExecution(o.read)
		return
	}

	o.parallelExecution(func(s string) {
		_, _, _ = o.authenticate(s)
	})
	return
}

func (o *Options) authenticate(target string) (*ldap.Conn, utils.Credential, error) {
	if !o.Connection.NullSession && len(o.credentials) == 0 {
		return nil, utils.Credential{}, fmt.Errorf("no credentials provided")
	}

	lconn, err := connect(target, o.Connection.Port, o.Connection.SSL)
	if err != nil {
		return nil, utils.Credential{}, err
	}

	prt := printer.NewPrinter("LDAP", target, o.target2SMBInfo[target].NetBIOSName, o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	var domain string = o.Connection.Domain
	if domain == "" {
		domain = o.target2SMBInfo[target].Domain
	}

	if o.Connection.NullSession {
		if err := lconn.UnauthenticatedBind(""); err != nil {
			prt.StoreFailure("null session not allowed")
			return nil, utils.Credential{}, fmt.Errorf("no valid authentication")
		}
		c := utils.Credential{Username: o.Connection.Username, Password: o.Connection.Password}
		prt.StoreSuccess(c.StringWithDomain(domain))
		return lconn, c, nil
	}

	for _, creds := range o.credentials {
		if creds.Hash != "" {
			if err := lconn.NTLMBindWithHash(domain, creds.Username, creds.Hash); err != nil {
				prt.StoreFailure(creds.StringWithDomain(domain))
			} else {
				prt.StoreSuccess(creds.StringWithDomain(domain))
				return lconn, creds, nil
			}
		} else {
			if err := authenticate(lconn, domain, creds.Username, creds.Password); err != nil {
				prt.StoreFailure(creds.StringWithDomain(domain))
			} else {
				prt.StoreSuccess(creds.StringWithDomain(domain))
				return lconn, creds, nil
			}
		}
	}
	return nil, utils.Credential{}, fmt.Errorf("no valid authentication")
}

func (o *Options) parseR(args []string) ExecutionFunction {
	if o.Read.GetSID {
		o.filters = []string{UACFilter(SERVER_TRUST_ACCOUNT)}
		o.attributes = []string{ObjectSid}
		return Enumeration
	}

	if o.Read.GMSA {
		o.filters = []string{FilterGMSA}
		o.attributes = []string{SAMAccountName, ManagedPassword}
		return Enumeration
	}

	tmp := strings.Split(o.Read.CustomAttributes, ",")
	for _, a := range tmp {
		switch strings.ToLower(a) {
		case strings.ToLower(SAMAccountName), "name":
			o.attributes = append(o.attributes, SAMAccountName)
		case strings.ToLower(ServicePrincipalName), "spn":
			o.attributes = append(o.attributes, ServicePrincipalName)
		case strings.ToLower(ObjectSid):
			o.attributes = append(o.attributes, ObjectSid)
		case strings.ToLower(AdminCount):
			o.attributes = append(o.attributes, AdminCount)
		case strings.ToLower(DistinguishedName), "dn":
			o.attributes = append(o.attributes, DistinguishedName)
		case strings.ToLower(OperatingSystem):
			o.attributes = append(o.attributes, OperatingSystem)
		case strings.ToLower(OperatingSystemServicePack):
			o.attributes = append(o.attributes, OperatingSystemServicePack)
		case strings.ToLower(OperatingSystemVersion):
			o.attributes = append(o.attributes, OperatingSystemVersion)
		case strings.ToLower(PasswordLastSet):
			o.attributes = append(o.attributes, PasswordLastSet)
		case strings.ToLower(LastLogon):
			o.attributes = append(o.attributes, LastLogon)
		case strings.ToLower(MemberOf):
			o.attributes = append(o.attributes, MemberOf)
		case strings.ToLower(Description):
			o.attributes = append(o.attributes, Description)
		case strings.ToLower(ManagedPassword):
			o.attributes = append(o.attributes, ManagedPassword)
		case "":
			o.attributes = []string{SAMAccountName, Description}
		default:
			o.attributes = append(o.attributes, a)
		}
	}

	var nextNegated bool = false

	for _, a := range args {
		attr, _ := strings.CutPrefix(a, "--")
		attr, _ = strings.CutPrefix(attr, "-")

		for _, f := range reflect.VisibleFields(reflect.TypeOf(o.Read)) {
			var filters []string
			switch attr {
			case f.Tag.Get("long"), f.Tag.Get("short"):
				switch f.Name {
				case "TrustedForDelegation":
					filters = []string{UACFilter(TRUSTED_FOR_DELEGATION)}
				case "User":
					filters = []string{FilterIsUser, NewFilter(SAMAccountName, o.Read.User)}
				case "Users":
					filters = []string{FilterIsUser}
				case "PasswordNotRequired":
					filters = []string{UACFilter(PASSWD_NOTREQD)}
				case "PasswordNeverExpires":
					filters = []string{UACFilter(DONT_EXPIRE_PASSWORD)}
				case "ActiveUsers":
					filters = []string{FilterIsUser, NegativeFilter(UACFilter(ACCOUNTDISABLE))}
				case "CustomFilter":
					filters = []string{o.Read.CustomFilter}
				case "AdminCount":
					filters = []string{FilterIsAdmin}
				case "Groups":
					filters = []string{FilterIsGroup}
				case "DCList":
					filters = []string{NegativeFilter(UACFilter(ACCOUNTDISABLE)), UACFilter(SERVER_TRUST_ACCOUNT)}
				case "Computers":
					filters = []string{FilterIsComputer}
				case "Not":
					nextNegated = true
				default:
					continue
				}
			}
			if len(filters) != 0 {
				if nextNegated {
					if len(filters) == 1 {
						o.filters = append(o.filters, NegativeFilter(filters[0]))
					} else {
						o.filters = append(o.filters, NegativeFilter(JoinFilters(filters...)))
					}
					nextNegated = false
				} else {
					o.filters = append(o.filters, filters...)
				}
			}
		}
	}
	if len(o.filters) > 0 {
		slices.Sort(o.filters)
		o.filters = slices.Compact[[]string, string](o.filters)
		return Enumeration
	}
	return Undefined
}

func (o *Options) parseH() ExecutionFunction {
	if o.Hashes.AsrepRoast != "" {
		o.filter = JoinFilters(
			FilterIsUser,
			UACFilter(DONT_REQ_PREAUTH),
		)
		return Asreproast
	}
	if o.Hashes.Kerberoast != "" {
		o.filter = JoinFilters(
			FilterIsUser,
			NegativeFilter(UACFilter(ACCOUNTDISABLE)),
		)
		return Kerberoast
	}
	return Undefined
}
