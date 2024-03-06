package smb

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/5amu/goad/pkg/encoder"
)

func Send(conn net.Conn, req interface{}) (res []byte, err error) {
	buf, err := encoder.Marshal(req)
	if err != nil {
		return nil, err
	}

	b := new(bytes.Buffer)
	if err = binary.Write(b, binary.BigEndian, uint32(len(buf))); err != nil {
		return nil, err
	}

	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	if _, err = rw.Write(append(b.Bytes(), buf...)); err != nil {
		return nil, err
	}
	rw.Flush()

	var size uint32
	if err = binary.Read(rw, binary.BigEndian, &size); err != nil {
		return
	}
	if size > 0x00FFFFFF || size < 4 {
		return nil, fmt.Errorf("invalid NetBIOS session message")
	}

	data := make([]byte, size)
	l, err := io.ReadFull(rw, data)
	if err != nil {
		return nil, err
	}
	if uint32(l) != size {
		return nil, fmt.Errorf("message size invalid")
	}

	protID := data[0:4]
	switch string(protID) {
	default:
		return nil, fmt.Errorf("protocol not recognized")
	case ProtocolSmb:
	case ProtocolSmb2:
	}

	return data, nil
}
