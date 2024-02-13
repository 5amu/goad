package ldap

import (
	"fmt"
	"strconv"
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

type UserAccountControl int

var (
	SCRIPT                         UserAccountControl = 1
	ACCOUNTDISABLE                 UserAccountControl = 2
	HOMEDIR_REQUIRED               UserAccountControl = 8
	LOCKOUT                        UserAccountControl = 16
	PASSWD_NOTREQD                 UserAccountControl = 32
	PASSWD_CANT_CHANGE             UserAccountControl = 64
	ENCRYPTED_TEXT_PWD_ALLOWED     UserAccountControl = 128
	TEMP_DUPLICATE_ACCOUNT         UserAccountControl = 256
	NORMAL_ACCOUNT                 UserAccountControl = 512
	INTERDOMAIN_TRUST_ACCOUNT      UserAccountControl = 2048
	WORKSTATION_TRUST_ACCOUNT      UserAccountControl = 4096
	SERVER_TRUST_ACCOUNT           UserAccountControl = 8192
	DONT_EXPIRE_PASSWORD           UserAccountControl = 65536
	MNS_LOGON_ACCOUNT              UserAccountControl = 131072
	SMARTCARD_REQUIRED             UserAccountControl = 262144
	TRUSTED_FOR_DELEGATION         UserAccountControl = 524288
	NOT_DELEGATED                  UserAccountControl = 1048576
	USE_DES_KEY_ONLY               UserAccountControl = 2097152
	DONT_REQ_PREAUTH               UserAccountControl = 4194304
	PASSWORD_EXPIRED               UserAccountControl = 8388608
	TRUSTED_TO_AUTH_FOR_DELEGATION UserAccountControl = 16777216
	PARTIAL_SECRETS_ACCOUNT        UserAccountControl = 67108864
)

func UserAccountControlParsing(value string) ([]UserAccountControl, error) {
	var possible []UserAccountControl = []UserAccountControl{
		SCRIPT, ACCOUNTDISABLE, HOMEDIR_REQUIRED, LOCKOUT, PASSWD_NOTREQD,
		PASSWD_CANT_CHANGE, ENCRYPTED_TEXT_PWD_ALLOWED, TEMP_DUPLICATE_ACCOUNT,
		NORMAL_ACCOUNT, INTERDOMAIN_TRUST_ACCOUNT, WORKSTATION_TRUST_ACCOUNT,
		SERVER_TRUST_ACCOUNT, DONT_EXPIRE_PASSWORD, MNS_LOGON_ACCOUNT,
		SMARTCARD_REQUIRED, TRUSTED_FOR_DELEGATION, NOT_DELEGATED,
		USE_DES_KEY_ONLY, DONT_REQ_PREAUTH, PASSWORD_EXPIRED,
		TRUSTED_TO_AUTH_FOR_DELEGATION, PARTIAL_SECRETS_ACCOUNT,
	}

	i, err := strconv.Atoi(value)
	if err != nil {
		return nil, err
	}

	var out []UserAccountControl
	for i > 0 {
		for j := len(possible) - 1; j > 0; j = j - 1 {
			tentative := i - int(possible[j])
			if tentative >= 0 {
				out = append(out, UserAccountControl(possible[j]))
				if tentative == 0 {
					return out, nil
				}
				i = tentative
				break
			}
		}
	}
	return out, nil
}

const (
	FilterIsUser     = "(objectCategory=person)"
	FilterIsGroup    = "(objectCategory=group)"
	FilterIsComputer = "(objectCategory=computer)"
	FilterIsAdmin    = "(adminCount=1)"
)

const (
	SAMAccountName             = "sAMAccountName"
	ServicePrincipalName       = "servicePrincipalName"
	ObjectSid                  = "objectSid"
	AdminCount                 = "adminCount"
	UAC                        = "userAccountControl:1.2.840.113556.1.4.803:"
	DistinguishedName          = "distinguishedName"
	OperatingSystem            = "operatingSystem"
	OperatingSystemServicePack = "operatingSystemServicePack"
	OperatingSystemVersion     = "operatingSystemVersion"
	PasswordLastSet            = "pwdLastSet"
	LastLogon                  = "lastLogon"
	MemberOf                   = "memberOf"
	Description                = "description"
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

func UACFilter(prop UserAccountControl) string {
	return NewFilter(UAC, strconv.Itoa(int(prop)))
}

func (lc *LdapClient) FindObject(user string, attributes ...string) (map[string]string, error) {
	filter := NewFilter(SAMAccountName, user)
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
		app[DistinguishedName] = r.DN
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
	r, err := lc.Search(UACFilter(SERVER_TRUST_ACCOUNT), ObjectSid)
	if err != nil {
		return "", err
	}

	for _, entry := range r.Entries {
		return DecodeSID(entry.GetAttributeValue(ObjectSid)), nil
	}
	return "", fmt.Errorf("impossible to get domain SID")
}
