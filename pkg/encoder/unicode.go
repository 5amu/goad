package encoder

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
)

func ToUnicode(s string) []byte {
	// https://github.com/Azure/go-ntlmssp/blob/master/unicode.go
	uints := utf16.Encode([]rune(s))
	b := bytes.Buffer{}
	_ = binary.Write(&b, binary.LittleEndian, &uints)
	return b.Bytes()
}

func BytesToUnicode(b []byte) string {
	buf := bytes.Buffer{}
	_ = binary.Write(&buf, binary.LittleEndian, &b)
	return buf.String()
}
