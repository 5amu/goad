package smb

import (
	"fmt"
	"net"
)

// SMBv1 is supported as far as DETECTION goes. In 2024 I'm not willing to
// fully support it... I guess that help would be appreciated wut not actively
// wanted. Thank you for your understanding.
const ProtocolSmb = "\xFFSMB"
const DialectSmb_1_0 = "\x02NT LM 0.12\x00"

type HeaderV1 struct {
	ProtocolID       []byte `smb:"fixed:4"`
	Command          uint8
	Status           uint32
	Flags            uint8
	Flags2           uint16
	PIDHigh          uint16
	SecurityFeatures []byte `smb:"fixed:8"`
	Reserved         uint16
	TID              uint16
	PIDLow           uint16
	UID              uint16
	MID              uint16
}

type NegotiateReqV1 struct {
	HeaderV1
	WordCount uint8
	ByteCount uint16  // hardcoded to 14
	Dialects  []uint8 `smb:"fixed:12"`
}

type V1Client struct {
	Host      string
	Port      int
	Conn      net.Conn
	messageId int
}

func NewV1Client(host string, port int) *V1Client {
	return &V1Client{
		Host: host,
		Port: port,
	}
}

func (c *V1Client) WithConn(conn net.Conn) *V1Client {
	c.Conn = conn
	return c
}

func (c *V1Client) IsSMBv1() (bool, error) {
	if c.Conn == nil {
		var err error
		c.Conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", c.Host, c.Port))
		if err != nil {
			return false, err
		}
	}

	c.messageId = 0
	req := NegotiateReqV1{
		HeaderV1: HeaderV1{
			ProtocolID:       []byte(ProtocolSmb),
			Command:          0x72, //SMB1 Negotiate
			Status:           0,
			Flags:            0x18,
			Flags2:           0xc843,
			PIDHigh:          0,
			SecurityFeatures: []byte{0, 0, 0, 0, 0, 0, 0, 0},
			Reserved:         0,
			TID:              0xffff,
			PIDLow:           0xfeff,
			UID:              0,
			MID:              uint16(c.messageId),
		},
		WordCount: 0,
		ByteCount: 14,
		Dialects:  []uint8(DialectSmb_1_0),
	}

	buf, err := Send(c.Conn, req)
	if err != nil {
		return false, err
	}
	return string(buf[0:4]) == ProtocolSmb, nil
}
