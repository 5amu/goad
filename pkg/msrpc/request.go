package msrpc

import (
	"encoding/binary"

	"github.com/5amu/goad/pkg/encoder"
)

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
