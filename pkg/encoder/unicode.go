package encoder

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
)

func StringToUnicode(s string) []byte {
	// https://github.com/Azure/go-ntlmssp/blob/master/unicode.go
	uints := utf16.Encode([]rune(s))
	b := bytes.Buffer{}
	_ = binary.Write(&b, binary.LittleEndian, &uints)
	return b.Bytes()
}

func UnicodeToString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	ws := make([]uint16, len(b)/2)
	for i := range ws {
		ws[i] = binary.LittleEndian.Uint16(b[2*i : 2*i+2])
	}
	if len(ws) > 0 && ws[len(ws)-1] == 0 {
		ws = ws[:len(ws)-1]
	}
	return string(utf16.Decode(ws))
}
