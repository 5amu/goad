package ldap

import "github.com/go-ldap/ldap/v3/gssapi"

func (lc *LdapClient) AuthenticateKerberos(spn string) error {
	if lc.Conn == nil {
		if err := lc.Connect(); err != nil {
			return err
		}
	}

	krb5client, err := gssapi.NewSSPIClient()
	if err != nil {
		return err
	}
	return lc.Conn.GSSAPIBind(krb5client, spn, "")
}
