package defendify

import (
	"fmt"

	"github.com/5amu/goad/ldap"
)

type Engine struct {
	client  *ldap.LdapClient
	outfile string
}

func NewEngine(lclient *ldap.LdapClient, outfile string) *Engine {
	return &Engine{
		client:  lclient,
		outfile: outfile,
	}
}

func (e *Engine) Run() error {
	f, _ := e.checkOutdatedDC()

	fmt.Printf("Name:\n\t%s\nDescription:\n\t%s\nRemediation:\n\t%s\nResults:\n", f.Name, f.Description, f.Remediation)
	for _, o := range f.Objects {
		fmt.Printf("\tDN:%s\n\tOS: %s\n\tVersion: %s\n\tServicePack: %s\n", o.DN, o.OperatingSystem, o.OperatingSystemVersion, o.OperatingSystemServicePack)
	}
	fmt.Println("References: ")
	for _, r := range f.References {
		fmt.Printf("\t%s\n", r)
	}

	return nil
}

func (e *Engine) checkOutdatedDC() (*Finding, error) {
	f := InitFinding(DCNotUpdated)
	err := e.client.FindObjectsWithCallback(
		ldap.JoinFilters(ldap.FilterIsComputer, ldap.UACFilter(ldap.SERVER_TRUST_ACCOUNT)),
		func(m []map[string]string) error {
			for _, e := range m {
				f.Objects = append(f.Objects, &ADObject{
					DN:                         e[ldap.DistinguishedName],
					SAMAccountName:             e[ldap.SAMAccountName],
					OperatingSystem:            e[ldap.OperatingSystem],
					OperatingSystemServicePack: e[ldap.OperatingSystemServicePack],
					OperatingSystemVersion:     e[ldap.OperatingSystemVersion],
				})
			}
			return nil
		},
		ldap.SAMAccountName,
		ldap.OperatingSystem,
		ldap.OperatingSystemServicePack,
		ldap.OperatingSystemVersion,
	)
	if err != nil {
		return nil, err
	}
	if len(f.Objects) == 0 {
		return nil, nil
	}
	return f, nil
}
