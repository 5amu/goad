package bloodhound

type Domains struct {
	Meta struct {
		Methods int     `json:"methods"`
		Type    *string `json:"type"`
		Count   int     `json:"count"`
		Version int     `json:"version"`
	} `json:"meta"`
	Data []struct {
		Properties struct {
			Domain            *string `json:"domain"`
			Name              *string `json:"name"`
			Distinguishedname *string `json:"distinguishedname"`
			Domainsid         *string `json:"domainsid"`
			Collected         bool    `json:"collected"`
			Whencreated       int     `json:"whencreated"`
			Functionallevel   *string `json:"functionallevel"`
		} `json:"Properties"`
		Trusts []struct {
			TargetDomainSid     *string `json:"TargetDomainSid"`
			TargetDomainName    *string `json:"TargetDomainName"`
			IsTransitive        bool    `json:"IsTransitive"`
			SidFilteringEnabled bool    `json:"SidFilteringEnabled"`
			TrustDirection      *string `json:"TrustDirection"`
			TrustType           *string `json:"TrustType"`
		} `json:"Trusts"`
		Links []struct {
			IsEnforced bool    `json:"IsEnforced"`
			GUID       *string `json:"GUID"`
		} `json:"Links"`
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
