package msrpc

import (
	"encoding/binary"

	"github.com/5amu/goad/pkg/encoder"
)

// x32: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/b6090c2b-f44a-47a1-a13b-b82ade0137b2
// x64: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/dca648a5-42d3-432c-9927-2f22e50fa266
const (
	NDR32UUID    = "8a885d04-1ceb-11c9-9fe8-08002b104860"
	NDR32Version = 2
	NDR64UUID    = "71710533-beba-4937-8319-b5dbef9ccc36"
	NDR64Version = 1
)

type BindContextEntry struct {
	ContextID             uint16
	TransItemCount        uint16
	InterfaceUUID         []byte `smb:"fixed:16"`
	InterfaceVersion      uint16
	InterfaceVersionMinor uint16
	TransferSyntaxUUID    []byte `smb:"fixed:16"`
	TransferSyntaxVersion uint32
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/a6b7b03c-4ac5-4c25-8c52-f2bec872ac97
type BindStruct struct {
	HeaderStruct
	MaxSendFrag  uint16
	MaxRecvFrag  uint16
	AssocGroup   uint32
	ContextCount uint32
	CtxEntries   []BindContextEntry
}

func NewBindStruct(syntax string, syntaxVer int, iface string, ifaceVer int, ifaceVerMinor int) *BindStruct {
	header := NewHeader()
	header.PacketType = PDUBind
	return &BindStruct{
		HeaderStruct: *header,
		MaxSendFrag:  4280,
		MaxRecvFrag:  4280,
		AssocGroup:   0,
		ContextCount: 1,
		CtxEntries: []BindContextEntry{
			{
				ContextID:             0,
				TransItemCount:        1,
				InterfaceUUID:         encoder.UUIDFromString(iface),
				InterfaceVersion:      uint16(ifaceVer),
				InterfaceVersionMinor: uint16(ifaceVerMinor),
				TransferSyntaxUUID:    encoder.UUIDFromString(syntax),
				TransferSyntaxVersion: uint32(syntaxVer),
			},
		},
	}
}

func (req *BindStruct) Bytes() []byte {
	b, _ := encoder.Marshal(req)
	sz := len(b)

	// Set FragLength to the size of the RPC request
	binary.LittleEndian.PutUint16(b[8:10], uint16(sz))
	return b
}
