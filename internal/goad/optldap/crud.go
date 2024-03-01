package optldap

import (
	"fmt"

	"github.com/5amu/goad/internal/printer"
	"github.com/5amu/goad/internal/utils"
	"github.com/5amu/goad/pkg/mstypes"
	"github.com/go-ldap/ldap/v3"
)

func (o *Options) read(target string) {
	prt := printer.NewPrinter("LDAP", target, o.target2SMBInfo[target].NetBIOSName, o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	prt.StoreInfo("LDAP Query Filter")
	prt.StoreInfo(o.filter)

	lclient, _, err := o.authenticate(target)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}
	defer lclient.Close()

	if o.filter == "" {
		return
	}

	var domain string = o.Connection.Domain
	if domain == "" {
		domain = o.target2SMBInfo[target].Domain
	}

	err = FindObjectsWithCallback(lclient, domain, o.filter, func(m map[string]interface{}) error {
		var data []string
		for _, a := range o.attributes {
			switch a {
			case LastLogon, PasswordLastSet:
				data = append(data, DecodeADTimestamp(UnpackToString(m[a])))
			case ObjectSid:
				data = append(data, DecodeSID(UnpackToString(m[a])))
			case ManagedPassword:
				d := UnpackToString(m[ManagedPassword])
				blob := mstypes.NewMSDSManagedPasswordBlob([]byte(d))
				data = append(data, mstypes.HashDataNTLM(blob.CurrentPassword))
			default:
				data = append(data, UnpackToString(m[a]))
			}
		}
		prt.Store(data...)
		return nil
	}, o.attributes...)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}
}

func (o *Options) create(target string) {
	prt := printer.NewPrinter("LDAP", target, o.target2SMBInfo[target].NetBIOSName, o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	lclient, _, err := o.authenticate(target)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}
	defer lclient.Close()

	var domain string = o.Connection.Domain
	if domain == "" {
		domain = o.target2SMBInfo[target].Domain
	}

	var req *ldap.AddRequest

	switch o.ucd.UAC {
	case WORKSTATION_TRUST_ACCOUNT:
		req = ldap.NewAddRequest(fmt.Sprintf("CN=%s,CN=Computers,%s", o.ucd.SAMAccountName, toDN(domain)), []ldap.Control{})
		req.Attribute(ObjectClass, []string{"top", "organizationalPerson", "user", "computer"})
	case NORMAL_ACCOUNT:
		req = ldap.NewAddRequest(fmt.Sprintf("CN=Users,%s", toDN(domain)), []ldap.Control{})
		req.Attribute(ObjectClass, []string{"top", "organizationalPerson", "user", "person"})
	default:
		return
	}

	req.Attribute(SAMAccountName, []string{o.ucd.SAMAccountName})
	req.Attribute(InstanceType, []string{fmt.Sprintf("%d", IT_Writable)})
	req.Attribute(UACAttr, []string{fmt.Sprint(o.ucd.UAC)})

	switch o.ucd.UAC {
	case WORKSTATION_TRUST_ACCOUNT:
		o.ucd.DnsHostName = fmt.Sprintf("%s.%s", o.ucd.SAMAccountName, domain)
		o.ucd.SPNs = []string{
			fmt.Sprintf("HOST/%s", o.ucd.SAMAccountName),
			fmt.Sprintf("HOST/%s.%s", o.ucd.SAMAccountName, domain),
			fmt.Sprintf("RestrictedKrbHost/%s", o.ucd.SAMAccountName),
			fmt.Sprintf("RestrictedKrbHost/%s.%s", o.ucd.SAMAccountName, domain),
		}
		o.ucd.UnicodePwd = utils.StringToUTF16(utils.GeneratePassword(12))
	default:
		return
	}

	if err := lclient.Add(req); err != nil {
		prt.StoreFailure(err.Error())
	} else {
		prt.Store(o.ucd.SAMAccountName, o.ucd.UnicodePwd)
	}
}

type DeletionType int

const (
	DelComputer DeletionType = iota
	DelUser
)

func (o *Options) delete(target string) {
	prt := printer.NewPrinter("LDAP", target, o.target2SMBInfo[target].NetBIOSName, o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	lclient, _, err := o.authenticate(target)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}
	defer lclient.Close()

	var domain string = o.Connection.Domain
	if domain == "" {
		domain = o.target2SMBInfo[target].Domain
	}

	var req *ldap.DelRequest
	switch o.deletionType {
	case DelComputer:
		req = ldap.NewDelRequest(fmt.Sprintf("CN=%s,CN=Computers,%s", o.deletionName, toDN(domain)), []ldap.Control{})
	default:
		return
	}

	if err := lclient.Del(req); err != nil {
		prt.StoreFailure(err.Error())
	} else {
		prt.Store(o.deletionName, "successfullty deleted")
	}
}
