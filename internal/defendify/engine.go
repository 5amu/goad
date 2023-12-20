package defendify

import "github.com/5amu/goad/ldap"

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
	return nil
}
