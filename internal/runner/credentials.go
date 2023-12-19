package runner

import "fmt"

type credential struct {
	Username string
	Password string
	Hash     string
}

func NewCredentialsClusterBomb(users []string, passwords []string) (out []credential) {
	for _, u := range users {
		for _, p := range passwords {
			out = append(out, credential{Username: u, Password: p})
		}
	}
	return
}

func NewCredentialsPitchFork(users []string, passwords []string) (out []credential, err error) {
	if len(users) != len(passwords) {
		return nil, fmt.Errorf("slices lenght mismatch")
	}
	for i := range users {
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
