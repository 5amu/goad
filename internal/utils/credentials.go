package utils

import "fmt"

type Credential struct {
	Username string
	Password string
	Hash     string
}

func NewCredentialsClusterBomb(users []string, passwords []string) (out []Credential) {
	if len(passwords) == 0 {
		passwords = append(passwords, "")
	}
	for _, u := range users {
		for _, p := range passwords {
			out = append(out, Credential{Username: u, Password: p})
		}
	}
	return
}

func NewCredentialsPitchFork(users []string, passwords []string) (out []Credential) {
	for i := 0; i < len(users) && i < len(passwords); i++ {
		out = append(out, Credential{Username: users[i], Password: passwords[i]})
	}
	return
}

func NewCredentialsNTLM(users []string, hash string) (out []Credential) {
	for _, u := range users {
		out = append(out, Credential{Username: u, Hash: hash})
	}
	return
}

func (c *Credential) String() string {
	if c.Hash != "" {
		return fmt.Sprintf("%s:%s", c.Username, c.Hash)
	}
	return fmt.Sprintf("%s:%s", c.Username, c.Password)
}

func (c *Credential) StringWithDomain(domain string) string {
	if c.Hash != "" {
		return fmt.Sprintf("%s\\%s:%s", domain, c.Username, c.Hash)
	}
	return fmt.Sprintf("%s\\%s:%s", domain, c.Username, c.Password)
}

type Strategy int

const (
	Clusterbomb Strategy = iota
	Pitchfork
)

func NewCredentialsDispacher(users, passwords, ntlm string, strategy Strategy) []Credential {
	if ntlm != "" {
		return NewCredentialsNTLM(ExtractLinesFromFileOrString(users), ntlm)
	}
	if strategy == Pitchfork {
		return NewCredentialsPitchFork(ExtractLinesFromFileOrString(users), ExtractLinesFromFileOrString(passwords))
	}
	return NewCredentialsClusterBomb(ExtractLinesFromFileOrString(users), ExtractLinesFromFileOrString(passwords))
}
