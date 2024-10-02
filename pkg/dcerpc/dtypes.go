package dcerpc

import "math/rand"

type MsrpcUUID struct {
	UUID         string
	Version      int
	VersionMinor int
	NamedPipe    string
}

type PointerHeader struct {
	ReferentId  uint32
	MaxCount    uint32
	Offset      uint32
	ActualCount uint32
}

type WcharTPtr struct {
	PointerHeader
	UnicodeString []byte
}

func NewWcharTPtr32(str []byte) WcharTPtr {
	return WcharTPtr{
		PointerHeader: PointerHeader{
			ReferentId:  rand.Uint32(),
			MaxCount:    uint32(len(str)),
			Offset:      0,
			ActualCount: uint32(len(str)),
		},
		UnicodeString: AlignBytes32(str),
	}
}

func NewWcharTPtr64(str []byte) WcharTPtr {
	return WcharTPtr{
		PointerHeader: PointerHeader{
			ReferentId:  rand.Uint32(),
			MaxCount:    uint32(len(str)),
			Offset:      0,
			ActualCount: uint32(len(str)),
		},
		UnicodeString: AlignBytes64(str),
	}
}

func NewWcharTPtr(str []byte, x64 bool) WcharTPtr {
	if x64 {
		return NewWcharTPtr64(str)
	}
	return NewWcharTPtr32(str)
}
