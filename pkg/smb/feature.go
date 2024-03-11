package smb

import (
	"github.com/5amu/goad/pkg/smb/internal/smb2"
)

// client

const (
	clientCapabilities = smb2.SMB2_GLOBAL_CAP_LARGE_MTU | smb2.SMB2_GLOBAL_CAP_ENCRYPTION
)

var (
	clientHashAlgorithms = []uint16{smb2.SHA512}
	clientCiphers        = []uint16{smb2.AES128GCM, smb2.AES128CCM}
	clientDialects       = []uint16{smb2.SMB311, smb2.SMB302, smb2.SMB300, smb2.SMB210, smb2.SMB202}
)

const (
	clientMaxCreditBalance = 128
)

const (
	clientMaxSymlinkDepth = 8
)
