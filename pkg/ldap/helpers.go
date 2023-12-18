package ldap

import (
	"fmt"
	"strings"
)

/*
   LDAP makes you search using an OID
   http://oid-info.com/get/1.2.840.113556.1.4.803
   The one for the userAccountControl in MS Active Directory is
   1.2.840.113556.1.4.803 (LDAP_MATCHING_RULE_BIT_AND)
   And we can look at the enabled flags using a query like (!(userAccountControl:1.2.840.113556.1.4.803:=2))
   https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
*/

const (
	FilterScript                       = "(userAccountControl:1.2.840.113556.1.4.803:=1)"        // SCRIPT (1)
	FilterDisabledUser                 = "(userAccountControl:1.2.840.113556.1.4.803:=2)"        // ACCOUNTDISABLE (2)
	FilterHomeDirRequired              = "(userAccountControl:1.2.840.113556.1.4.803:=8)"        // HOMEDIR_REQUIRED (8)
	FilterLockout                      = "(userAccountControl:1.2.840.113556.1.4.803:=16)"       // LOCKOUT (16)
	FilterPasswordNotRequired          = "(userAccountControl:1.2.840.113556.1.4.803:=32)"       // PASSWD_NOTREQD (32)
	FilterPasswordCantChange           = "(userAccountControl:1.2.840.113556.1.4.803:=64)"       // PASSWD_CANT_CHANGE (64)
	FilterEncryptedTextPasswordAllowed = "(userAccountControl:1.2.840.113556.1.4.803:=128)"      // ENCRYPTED_TEXT_PWD_ALLOWED (128)
	FilterTempDuplicateAccount         = "(userAccountControl:1.2.840.113556.1.4.803:=256)"      // TEMP_DUPLICATE_ACCOUNT (256)
	FilterNormalAccount                = "(userAccountControl:1.2.840.113556.1.4.803:=512)"      // NORMAL_ACCOUNT (512)
	FilterInterdomainTrustAccount      = "(userAccountControl:1.2.840.113556.1.4.803:=2048)"     // INTERDOMAIN_TRUST_ACCOUNT (2048)
	FilterWorkstationTrustAccount      = "(userAccountControl:1.2.840.113556.1.4.803:=4096)"     // WORKSTATION_TRUST_ACCOUNT (4096)
	FilterServerTrustAccount           = "(userAccountControl:1.2.840.113556.1.4.803:=8192)"     // SERVER_TRUST_ACCOUNT (8192)
	FilterDontExpirePassword           = "(userAccountControl:1.2.840.113556.1.4.803:=65536)"    // DONT_EXPIRE_PASSWORD (65536)
	FilterMNSLogonAccount              = "(userAccountControl:1.2.840.113556.1.4.803:=131072)"   // MNS_LOGON_ACCOUNT (131072)
	FilterSmartcardRequired            = "(userAccountControl:1.2.840.113556.1.4.803:=262144)"   // SMARTCARD_REQUIRED (262144)
	FilterTrustedForDelegation         = "(userAccountControl:1.2.840.113556.1.4.803:=524288)"   // TRUSTED_FOR_DELEGATION (524288)
	FilterNotDelegated                 = "(userAccountControl:1.2.840.113556.1.4.803:=1048576)"  // NOT_DELEGATED (1048576)
	FilterUseDesKeyOnly                = "(userAccountControl:1.2.840.113556.1.4.803:=2097152)"  // USE_DES_KEY_ONLY (2097152)
	FilterDontRequirePreauth           = "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"  // DONT_REQ_PREAUTH (4194304)
	FilterPasswordExpired              = "(userAccountControl:1.2.840.113556.1.4.803:=8388608)"  // PASSWORD_EXPIRED (8388608)
	FilterTrustedToAuthForDelegation   = "(userAccountControl:1.2.840.113556.1.4.803:=16777216)" // TRUSTED_TO_AUTH_FOR_DELEGATION (16777216)
	FilterPartialSecretsAccount        = "(userAccountControl:1.2.840.113556.1.4.803:=67108864)" // PARTIAL_SECRETS_ACCOUNT (67108864)
)

const (
	FilterIsUser     = "(objectCategory=person)"
	FilterIsGroup    = "(objectCategory=group)"
	FilterIsComputer = "(objectCategory=computer)"
	FilterIsAdmin    = "(adminCount=1)"
)

const (
	AttributeSAMAccountName       = "sAMAccountName"
	AttributeServicePrincipalName = "servicePrincipalName"
	AttributeObjectSid            = "objectSid"
	AttributeAdminCount           = "adminCount"
)

func JoinFilters(filters ...string) string {
	var builder strings.Builder
	builder.WriteString("(&")
	for _, s := range filters {
		builder.WriteString(s)
	}
	builder.WriteString(")")
	return builder.String()
}

func NegativeFilter(filter string) string {
	return fmt.Sprintf("(!%s)", filter)
}

func NewFilter(attribute string, equalsTo string) string {
	return fmt.Sprintf("(%s=%s)", attribute, equalsTo)
}

func (lc *LdapClient) FindObject(user string, attributes ...string) (map[string]string, error) {
	filter := NewFilter(AttributeSAMAccountName, user)
	res, err := lc.Search(filter, attributes...)
	if err != nil {
		return nil, err
	}

	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("no object found in search")
	} else if len(res.Entries) > 1 {
		return nil, fmt.Errorf("too many objects found in search")
	}

	out := make(map[string]string)
	e := res.Entries[0]
	out["dn"] = e.DN
	for _, a := range attributes {
		out[a] = e.GetAttributeValue(a)
	}
	return out, nil
}

func (lc *LdapClient) FindObjects(filter string, attributes ...string) ([]map[string]string, error) {
	res, err := lc.Search(filter, attributes...)
	if err != nil {
		return nil, err
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("no user found in search")
	}

	var out []map[string]string
	for _, r := range res.Entries {
		app := make(map[string]string)
		for _, a := range attributes {
			app[a] = r.GetAttributeValue(a)
		}
		app["dn"] = r.DN
		out = append(out, app)
	}
	return out, nil
}

func (lc *LdapClient) FindObjectsWithCallback(filter string, callback func([]map[string]string) error, attributes ...string) error {
	users, err := lc.FindObjects(filter, attributes...)
	if err != nil {
		return err
	}
	return callback(users)
}

func (lc *LdapClient) GetDomainSID() (string, error) {
	r, err := lc.Search(FilterServerTrustAccount, AttributeObjectSid)
	if err != nil {
		return "", err
	}

	for _, entry := range r.Entries {
		return DecodeSID([]byte(entry.GetAttributeValue("objectSid"))).String(), nil
	}
	return "", fmt.Errorf("impossible to get domain SID")
}
