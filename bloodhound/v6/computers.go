package bloodhound

type Computers struct {
	Meta struct {
		Methods int     `json:"methods"`
		Type    *string `json:"type"`
		Count   int     `json:"count"`
		Version int     `json:"version"`
	} `json:"meta"`
	Data []struct {
		PrimaryGroupSID   *string `json:"PrimaryGroupSID"`
		AllowedToDelegate []struct {
			ObjectIdentifier *string `json:"ObjectIdentifier"`
			ObjectType       *string `json:"ObjectType"`
		} `json:"AllowedToDelegate"`
		AllowedToAct []struct {
			ObjectIdentifier *string `json:"ObjectIdentifier"`
			ObjectType       *string `json:"ObjectType"`
		} `json:"AllowedToAct"`
		HasSIDHistory []struct {
			ObjectIdentifier *string `json:"ObjectIdentifier"`
			ObjectType       *string `json:"ObjectType"`
		} `json:"HasSIDHistory"`
		Sessions struct {
			Results []struct {
				UserSID     *string `json:"UserSID"`
				ComputerSID *string `json:"ComputerSID"`
			} `json:"Results"`
			Collected     bool    `json:"Collected"`
			FailureReason *string `json:"FailureReason"`
		} `json:"Sessions"`
		PrivilegedSessions struct {
			Results []struct {
				UserSID     *string `json:"UserSID"`
				ComputerSID *string `json:"ComputerSID"`
			} `json:"Results"`
			Collected     bool    `json:"Collected"`
			FailureReason *string `json:"FailureReason"`
		} `json:"PrivilegedSessions,omitempty"`
		RegistrySessions struct {
			Results []struct {
				UserSID     *string `json:"UserSID"`
				ComputerSID *string `json:"ComputerSID"`
			} `json:"Results"`
			Collected     bool    `json:"Collected"`
			FailureReason *string `json:"FailureReason"`
		} `json:"RegistrySessions,omitempty"`
		LocalGroups []struct {
			Collected     bool    `json:"Collected"`
			FailureReason *string `json:"FailureReason"`
			Results       []struct {
				ObjectIdentifier *string `json:"ObjectIdentifier"`
				ObjectType       *string `json:"ObjectType"`
			} `json:"Results"`
			LocalName        []any   `json:"LocalName"`
			Name             *string `json:"Name"`
			ObjectIdentifier *string `json:"ObjectIdentifier"`
		} `json:"LocalGroups,omitempty"`
		UserRights []struct {
			Collected     bool    `json:"Collected"`
			FailureReason *string `json:"FailureReason"`
			Results       []struct {
				ObjectIdentifier *string `json:"ObjectIdentifier"`
				ObjectType       *string `json:"ObjectType"`
			} `json:"Results"`
			Privilege  *string `json:"Privilege"`
			LocalNames []any   `json:"LocalNames"`
		} `json:"UserRights,omitempty"`
		Status any `json:"Status"`
		Aces   []struct {
			PrincipalSID  *string `json:"PrincipalSID"`
			PrincipalType *string `json:"PrincipalType"`
			RightName     *string `json:"RightName"`
			IsInherited   bool    `json:"IsInherited"`
		} `json:"Aces"`
		ObjectIdentifier *string `json:"ObjectIdentifier"`
		IsDeleted        bool    `json:"IsDeleted"`
		IsACLProtected   bool    `json:"IsACLProtected"`
		Properties       struct {
			Domain                  *string  `json:"domain"`
			Name                    *string  `json:"name"`
			Distinguishedname       *string  `json:"distinguishedname"`
			Domainsid               *string  `json:"domainsid"`
			Haslaps                 bool     `json:"haslaps"`
			Description             *string  `json:"description"`
			Whencreated             int      `json:"whencreated"`
			Enabled                 bool     `json:"enabled"`
			Unconstraineddelegation bool     `json:"unconstraineddelegation"`
			Trustedtoauth           bool     `json:"trustedtoauth"`
			Lastlogon               int      `json:"lastlogon"`
			Lastlogontimestamp      int      `json:"lastlogontimestamp"`
			Pwdlastset              int      `json:"pwdlastset"`
			Serviceprincipalnames   []string `json:"serviceprincipalnames"`
			Operatingsystem         *string  `json:"operatingsystem"`
			Sidhistory              []any    `json:"sidhistory"`
		} `json:"Properties"`
		ContainedBy struct {
			ObjectIdentifier *string `json:"ObjectIdentifier"`
			ObjectType       *string `json:"ObjectType"`
		} `json:"ContainedBy,omitempty"`
		LocalAdmins struct {
			Results []struct {
				UserSID     string `json:"UserSID"`
				ComputerSID string `json:"ComputerSID"`
			} `json:"Results"`
			Collected     bool `json:"Collected"`
			FailureReason any  `json:"FailureReason"`
		} `json:"LocalAdmins,omitempty"`
		RemoteDesktopUsers struct {
			Results []struct {
				UserSID     string `json:"UserSID"`
				ComputerSID string `json:"ComputerSID"`
			} `json:"Results"`
			Collected     bool `json:"Collected"`
			FailureReason any  `json:"FailureReason"`
		} `json:"RemoteDesktopUsers,omitempty"`
		DcomUsers struct {
			Results []struct {
				UserSID     string `json:"UserSID"`
				ComputerSID string `json:"ComputerSID"`
			} `json:"Results"`
			Collected     bool    `json:"Collected"`
			FailureReason *string `json:"FailureReason"`
		} `json:"DcomUsers,omitempty"`
		PSRemoteUsers struct {
			Results []struct {
				UserSID     string `json:"UserSID"`
				ComputerSID string `json:"ComputerSID"`
			} `json:"Results"`
			Collected     bool    `json:"Collected"`
			FailureReason *string `json:"FailureReason"`
		} `json:"PSRemoteUsers,omitempty"`
	} `json:"data"`
}
