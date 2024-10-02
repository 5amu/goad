package ntlm

import "crypto/rc4"

type NTLMServer struct {
	TargetName string
	Accounts   map[string]string //map["username"]"password"

	// Session Tracking
	SeqNum             uint32
	NegotiateFlags     uint32
	ExportedSessionKey []byte
	SigningKey         []byte
	Handle             *rc4.Cipher
}
