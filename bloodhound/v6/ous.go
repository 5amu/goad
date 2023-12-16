package bloodhound

type OUs struct {
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
			Description       *string `json:"description"`
			Whencreated       int     `json:"whencreated"`
			Blocksinheritance bool    `json:"blocksinheritance"`
		} `json:"Properties,omitempty"`
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
		ChildObjects     []struct {
			ObjectIdentifier *string `json:"ObjectIdentifier"`
			ObjectType       *string `json:"ObjectType"`
		} `json:"ChildObjects,omitempty"`
	} `json:"data"`
}
