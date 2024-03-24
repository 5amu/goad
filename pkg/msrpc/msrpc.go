package msrpc

import "math/rand"

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
