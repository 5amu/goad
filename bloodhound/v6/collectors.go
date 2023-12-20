package bloodhound

import "github.com/5amu/goad/ldap"

type GroupCollector struct {
	data Groups
}

func (c *GroupCollector) Collect(lclient *ldap.LdapClient) error {
	return nil
}

func (c *GroupCollector) Export(outdir string) error {
	return nil
}
