package bloodhound

type Sessions struct {
	Meta struct {
		Methods int     `json:"methods"`
		Type    *string `json:"type"`
		Count   int     `json:"count"`
		Version int     `json:"version"`
	} `json:"meta"`
	Data []struct {
		ComputerSID *string `json:"ComputerSID"`
		UserSID     *string `json:"UserSID"`
		LogonType   int     `json:"LogonType"`
	} `json:"data"`
}
