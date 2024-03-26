package msrpc

import (
	"encoding/binary"
	"math/rand"

	"github.com/5amu/goad/pkg/encoder"
)

type MSRPCUUID struct {
	UUID         string
	Version      int
	VersionMinor int
	NamedPipe    string
}

// PDU PacketType
// https://pubs.opengroup.org/onlinepubs/9629399/chap12.htm
const (
	PDURequest = iota
	PDUPing
	PDUResponse
	PDUFault
	PDUWorking
	PDUNoCall
	PDUReject
	PDUAck
	PDUClCancel
	PDUFack
	PDUCancelAck
	PDUBind
	PDUBindAck
	PDUBindNak
	PDUAlterContext
	PDUAlterContextResp
	PDUShutdown
	PDUCoCancel
	PDUOrphaned
)

// PDU PacketFlags
// https://pubs.opengroup.org/onlinepubs/9629399/chap12.htm
const (
	FirstFrag          = 0x01
	LastFrag           = 0x02
	PDUFlagPending     = 0x03
	CancelPending      = 0x04
	PDUFlagNoFack      = 0x08
	PDUFlagMayBe       = 0x10
	PDUFlagIdemPotent  = 0x20
	PDUFlagBroadcast   = 0x40
	PDUFlagReserved_80 = 0x80
)

// Supported version is 5.0
const (
	PDUVersion      = 5
	PDUVersionMinor = 0
)

type HeaderStruct struct {
	RpcVersion         uint8
	RpcVersionMinor    uint8
	PacketType         uint8
	PacketFlags        byte
	DataRepresentation []byte `smb:"fixed:4"`
	FragLength         uint16
	AuthLength         uint16
	CallId             uint32
}

func NewHeader() *HeaderStruct {
	return &HeaderStruct{
		RpcVersion:         PDUVersion,
		RpcVersionMinor:    PDUVersionMinor,
		PacketType:         PDURequest,
		PacketFlags:        FirstFrag | LastFrag,
		DataRepresentation: []byte{0x10, 0, 0, 0}, // Little-Endian, float = IEEE, char = ASCII
		FragLength:         0,                     // must be updated before sending
		AuthLength:         0,
		// ^uint32(0) is the maximum number that can be represented with uint32
		CallId: uint32(rand.Intn(int(^uint32(0)))),
	}
}

type RequestStruct struct {
	HeaderStruct
	AllocHint uint32
	ContextID uint16
	OpNum     uint16
	Payload   interface{}
}

func (req *RequestStruct) Bytes() []byte {
	b, _ := encoder.Marshal(req)
	sz := len(b)

	// Set FragLength to the size of the RPC request
	binary.LittleEndian.PutUint16(b[8:10], uint16(sz))

	// Set AllocHint to the size of the RPC body (the header is 24 bytes)
	binary.LittleEndian.PutUint32(b[24:28], uint32(sz)-24)
	return b
}

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
