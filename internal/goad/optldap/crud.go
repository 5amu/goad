package optldap

import (
	"github.com/5amu/goad/internal/printer"
	"github.com/5amu/goad/pkg/mstypes"
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
