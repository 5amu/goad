package msrpc

type PTR struct {
	ReferentId  uint32 `smb:"offset:Data"`
	MaxCount    uint32
	Offset      uint32
	ActualCount uint32
	Data        interface{}
}
