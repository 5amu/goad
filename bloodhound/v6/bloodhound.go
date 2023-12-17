package bloodhound

import "github.com/5amu/goad/pkg/ldap"

type Collection int

var (
	Default     Collection = 1
	All         Collection = 2
	Group       Collection = 3
	LocalAdmin  Collection = 4
	Session     Collection = 5
	Trusts      Collection = 6
	DCOnly      Collection = 7
	DCOM        Collection = 8
	RDP         Collection = 9
	PSRemote    Collection = 10
	LoggedOn    Collection = 11
	Container   Collection = 12
	ObjectProps Collection = 13
	ACL         Collection = 14
)

func BloodhoundCollector(ldapClient *ldap.LdapClient, outfile string, collection ...Collection) error {

	return nil
}
