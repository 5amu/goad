package encoder

import (
	"encoding/hex"
	"strings"
)

func UUIDFromString(s string) []byte {
	s = strings.ReplaceAll(s, "-", "")
	b, _ := hex.DecodeString(s)
	r := []byte{b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]}
	return r
}
