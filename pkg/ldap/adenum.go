package ldap

import (
	"encoding/hex"
	"fmt"

	"github.com/5amu/goad/pkg/mstypes"
	"github.com/go-ldap/ldap/v3"
	"golang.org/x/crypto/md4"
)

type ADObject struct {
	DistinguishedName    string
	SAMAccountName       string
	PWDLastSet           string
	LastLogon            string
	Description          string
	MemberOf             []string
	ServicePrincipalName []string
}

func (c *LdapClient) FindADObjects(filter string) ([]ADObject, error) {
	sr := ldap.NewSearchRequest(
		c.BaseDN, ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{
			DistinguishedName,
			SAMAccountName,
			PasswordLastSet,
			LastLogon,
			MemberOf,
			ServicePrincipalName,
			Description,
		},
		nil,
	)

	res, err := c.Conn.Search(sr)
	if err != nil {
		return nil, err
	}

	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("no object returned from query")
	}

	var objects []ADObject
	for _, obj := range res.Entries {
		objects = append(objects, ADObject{
			DistinguishedName:    obj.GetAttributeValue(DistinguishedName),
			SAMAccountName:       obj.GetAttributeValue(SAMAccountName),
			PWDLastSet:           DecodeADTimestamp(obj.GetAttributeValue(PasswordLastSet)),
			LastLogon:            DecodeADTimestamp(obj.GetAttributeValue(LastLogon)),
			MemberOf:             obj.GetAttributeValues(MemberOf),
			ServicePrincipalName: obj.GetAttributeValues(ServicePrincipalName),
			Description:          obj.GetAttributeValue(Description),
		})
	}
	return objects, nil
}

func (c *LdapClient) FindADObjectsWithCallback(filter string, callback func(ADObject) error) error {
	objects, err := c.FindADObjects(filter)
	if err != nil {
		return err
	}

	if len(objects) == 0 {
		return fmt.Errorf("no object returned from query")
	}

	for _, obj := range objects {
		if err := callback(obj); err != nil {
			return err
		}
	}
	return nil
}

type GMSA struct {
	SAMAccountName string
	NTLM           string
}

func (c *LdapClient) GetGMSA() ([]GMSA, error) {
	objects, err := c.FindObjects(
		"(objectClass=msDS-GroupManagedServiceAccount)",
		"sAMAccountName",
		"msDS-ManagedPassword",
		"msDS-GroupMSAMembership",
	)
	if err != nil {
		return nil, err
	}

	var gmsa []GMSA
	for _, obj := range objects {
		g := GMSA{}
		name, ok1 := obj[SAMAccountName]
		if ok1 {
			g.SAMAccountName = name
		}
		pass, ok2 := obj["msDS-ManagedPassword"]
		if ok2 {
			mdfour := md4.New()
			blob := mstypes.NewMSDSManagedPasswordBlob([]byte(pass))
			pass := blob.CurrentPassword
			_, _ = mdfour.Write(pass)
			g.NTLM = hex.EncodeToString(mdfour.Sum(nil))
		}
		if ok1 && ok2 {
			gmsa = append(gmsa, g)
		}
	}
	return gmsa, nil
}
