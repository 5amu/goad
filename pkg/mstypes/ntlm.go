package mstypes

import (
	"encoding/hex"

	"golang.org/x/crypto/md4" //nolint:staticcheck
)

func HashDataNTLM(b []byte) string {
	mdfour := md4.New()
	_, _ = mdfour.Write(b)
	return hex.EncodeToString(mdfour.Sum(nil))
}
