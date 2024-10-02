package ntlm

import "crypto/md5"

var DefaultSignature = [8]byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0}

const (
	NtLmNegotiate    = 0x00000001
	NtLmChallenge    = 0x00000002
	NtLmAuthenticate = 0x00000003
)

const (
	NTLMSSP_NEGOTIATE_UNICODE = 1 << iota
	NTLM_NEGOTIATE_OEM
	NTLMSSP_REQUEST_TARGET
	_
	NTLMSSP_NEGOTIATE_SIGN
	NTLMSSP_NEGOTIATE_SEAL
	NTLMSSP_NEGOTIATE_DATAGRAM
	NTLMSSP_NEGOTIATE_LM_KEY
	_
	NTLMSSP_NEGOTIATE_NTLM
	_
	NTLMSSP_ANONYMOUS
	NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
	NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
	_
	NTLMSSP_NEGOTIATE_ALWAYS_SIGN
	NTLMSSP_TARGET_TYPE_DOMAIN
	NTLMSSP_TARGET_TYPE_SERVER
	_
	NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
	NTLMSSP_NEGOTIATE_IDENTIFY
	_
	NTLMSSP_REQUEST_NON_NT_SESSION_KEY
	NTLMSSP_NEGOTIATE_TARGET_INFO
	_
	NTLMSSP_NEGOTIATE_VERSION
	_
	_
	_
	NTLMSSP_NEGOTIATE_128
	NTLMSSP_NEGOTIATE_KEY_EXCH
	NTLMSSP_NEGOTIATE_56
)
const DefaultFlags uint32 = NTLMSSP_NEGOTIATE_56 | NTLMSSP_NEGOTIATE_KEY_EXCH | NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_TARGET_INFO | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_VERSION

const (
	WINDOWS_MAJOR_VERSION_5  = 0x05
	WINDOWS_MAJOR_VERSION_6  = 0x06
	WINDOWS_MAJOR_VERSION_10 = 0x0a
)

const (
	WINDOWS_MINOR_VERSION_0 = 0x00
	WINDOWS_MINOR_VERSION_1 = 0x01
	WINDOWS_MINOR_VERSION_2 = 0x02
	WINDOWS_MINOR_VERSION_3 = 0x03
)

const (
	NTLMSSP_REVISION_W2K3 = 0x0f
)

var DefaultVersion = [8]byte{
	0: WINDOWS_MAJOR_VERSION_10,
	1: WINDOWS_MINOR_VERSION_0,
	7: NTLMSSP_REVISION_W2K3,
}

func sealKey(negotiateFlags uint32, randomSessionKey []byte, fromClient bool) []byte {
	if negotiateFlags&NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY != 0 {
		h := md5.New()
		switch {
		case negotiateFlags&NTLMSSP_NEGOTIATE_128 != 0:
			h.Write(randomSessionKey)
		case negotiateFlags&NTLMSSP_NEGOTIATE_56 != 0:
			h.Write(randomSessionKey[:7])
		default:
			h.Write(randomSessionKey[:5])
		}
		if fromClient {
			h.Write([]byte("session key to client-to-server sealing key magic constant\x00"))
		} else {
			h.Write([]byte("session key to server-to-client sealing key magic constant\x00"))
		}
		return h.Sum(nil)
	}

	if negotiateFlags&NTLMSSP_NEGOTIATE_LM_KEY != 0 {
		sealingKey := make([]byte, 8)
		if negotiateFlags&NTLMSSP_NEGOTIATE_56 != 0 {
			copy(sealingKey, randomSessionKey[:7])
			sealingKey[7] = 0xa0
		} else {
			copy(sealingKey, randomSessionKey[:5])
			sealingKey[5] = 0xe5
			sealingKey[6] = 0x38
			sealingKey[7] = 0xb0
		}
		return sealingKey
	}

	return randomSessionKey
}

func signKey(negotiateFlags uint32, randomSessionKey []byte, fromClient bool) []byte {
	if negotiateFlags&NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY != 0 {
		h := md5.New()
		h.Write(randomSessionKey)
		if fromClient {
			h.Write([]byte("session key to client-to-server signing key magic constant\x00"))
		} else {
			h.Write([]byte("session key to server-to-client signing key magic constant\x00"))
		}
		return h.Sum(nil)
	}
	return nil
}
