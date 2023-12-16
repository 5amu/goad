package bloodhound

type GPOs struct {
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
			Whencreated       int     `json:"whencreated"`
			Gpcpath           *string `json:"gpcpath"`
		} `json:"Properties"`
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
