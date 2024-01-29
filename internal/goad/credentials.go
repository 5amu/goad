package goad

import "fmt"

type credential struct {
	Username string
	Password string
	Hash     string
}

func NewCredentialsClusterBomb(users []string, passwords []string) (out []credential) {
	if len(passwords) == 0 {
		passwords = append(passwords, "")
	}
	for _, u := range users {
		for _, p := range passwords {
			out = append(out, credential{Username: u, Password: p})
		}
	}
	return
}

func NewCredentialsPitchFork(users []string, passwords []string) (out []credential) {
	for i := 0; i < len(users) && i < len(passwords); i++ {
		out = append(out, credential{Username: users[i], Password: passwords[i]})
	}
	return
}

func NewCredentialsNTLM(users []string, hash string) (out []credential) {
	for _, u := range users {
		out = append(out, credential{Username: u, Hash: hash})
	}
	return
}

func (c *credential) String() string {
	if c.Hash != "" {
		return fmt.Sprintf("%s:%s", c.Username, c.Hash)
	}
	return fmt.Sprintf("%s:%s", c.Username, c.Password)
}
