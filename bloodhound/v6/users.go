package bloodhound

type Users struct {
	Meta struct {
		Methods int     `json:"methods"`
		Type    *string `json:"type"`
		Count   int     `json:"count"`
		Version int     `json:"version"`
	} `json:"meta"`
	Data []struct {
		Properties struct {
			Domain                  *string  `json:"domain"`
			Name                    *string  `json:"name"`
			Distinguishedname       *string  `json:"distinguishedname"`
			Domainsid               *string  `json:"domainsid"`
			Description             *string  `json:"description"`
			Whencreated             int      `json:"whencreated"`
			Sensitive               bool     `json:"sensitive"`
			Dontreqpreauth          bool     `json:"dontreqpreauth"`
			Passwordnotreqd         bool     `json:"passwordnotreqd"`
			Unconstraineddelegation bool     `json:"unconstraineddelegation"`
			Pwdneverexpires         bool     `json:"pwdneverexpires"`
			Enabled                 bool     `json:"enabled"`
			Trustedtoauth           bool     `json:"trustedtoauth"`
			Lastlogon               int      `json:"lastlogon"`
			Lastlogontimestamp      int      `json:"lastlogontimestamp"`
			Pwdlastset              int      `json:"pwdlastset"`
			Serviceprincipalnames   []string `json:"serviceprincipalnames"`
			Hasspn                  bool     `json:"hasspn"`
			Admincount              bool     `json:"admincount"`
			Sidhistory              []string `json:"sidhistory"`
		} `json:"Properties,omitempty"`
		AllowedToDelegate []struct {
			ObjectIdentifier *string `json:"ObjectIdentifier"`
			ObjectType       *string `json:"ObjectType"`
		} `json:"AllowedToDelegate"`
		PrimaryGroupSID *string `json:"PrimaryGroupSID"`
		HasSIDHistory   []struct {
			ObjectIdentifier *string `json:"ObjectIdentifier"`
			ObjectType       *string `json:"ObjectType"`
		} `json:"HasSIDHistory"`
		SpnTargets []struct {
			ComputerSID *string `json:"ComputerSID"`
			Port        int     `json:"Port"`
			Service     *string `json:"Service"`
		} `json:"SpnTargets"`
		Aces []struct {
			PrincipalSID  *string `json:"PrincipalSID"`
			PrincipalType *string `json:"PrincipalType"`
			RightName     *string `json:"RightName"`
			IsInherited   bool    `json:"IsInherited"`
		} `json:"Aces"`
		ObjectIdentifier *string `json:"ObjectIdentifier"`
		IsDeleted        bool    `json:"IsDeleted"`
		IsACLProtected   bool    `json:"IsACLProtected"`
	} `json:"data"`
}
