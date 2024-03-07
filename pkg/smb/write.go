package smb

import (
	"encoding/hex"
	"errors"
	"os"

	"github.com/5amu/goad/pkg/encoder"
	"github.com/5amu/goad/pkg/mstypes"
)

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e7046961-3318-4350-be2a-a8d69bb59ce8
type WriteRequest struct {
	Header
	StructureSize          uint16
	DataOffset             uint16 `smb:"offset:Buffer"`
	WriteLength            uint32 `smb:"len:Buffer"`
	FileOffset             uint64
	FileId                 []byte `smb:"fixed:16"`
	Channel                uint32
	RemainingBytes         uint32
	WriteChannelInfoOffset uint16
	WriteChannelInfoLength uint16
	WriteFlags             uint32
	Buffer                 []byte
}

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/7b80a339-f4d3-4575-8ce2-70a06f24f133
type WriteResponse struct {
	Header
	StructureSize          uint16
	Reserved               uint16
	WriteCount             uint32
	WriteRemaining         uint32
	WriteChannelInfoOffset uint16
	WriteChannelInfoLength uint16
}

// Channel Property
const (
	SMB2_CHANNEL_NONE               = 0x00000000
	SMB2_CHANNEL_RDMA_V1            = 0x00000001
	SMB2_CHANNEL_RDMA_V1_INVALIDATE = 0x00000002
	SMB2_CHANNEL_RDMA_TRANSFORM     = 0x00000003
)

func (s *Session) NewWriteRequest(treeId uint32, fileId []byte, buf []byte) WriteRequest {
	smb2Header := newHeader()
	smb2Header.Command = CommandWrite
	smb2Header.MessageID = s.MessageID
	smb2Header.SessionID = s.SessionID
	smb2Header.TreeID = treeId
	return WriteRequest{
		Header:         smb2Header,
		StructureSize:  49,
		FileId:         fileId,
		Channel:        SMB2_CHANNEL_NONE,
		RemainingBytes: 0,
		WriteFlags:     0,
		Buffer:         buf,
	}
}

func NewWriteResponse() WriteResponse {
	smb2Header := newHeader()
	return WriteResponse{
		Header: smb2Header,
	}
}

func (s *Session) WriteRequest(treeId uint32, filepath, filename string, fileId []byte) (err error) {
	s.Debug("Sending Write file request ["+filename+"]", nil)
	file, err := os.Open(filepath + filename)
	if err != nil {
		return err
	}
	defer file.Close()

	fileBuf := make([]byte, 10240)
	fileOffset := 0

	var stop bool = false
	for i := 0; !stop; {
		switch nr, _ := file.Read(fileBuf[:]); true {
		case nr < 0:
			return errors.New("Failed read file to [" + filepath + filename + "]")
		case nr == 0: // EOF
			stop = true
		case nr > 0:
			req := s.NewWriteRequest(treeId, fileId, fileBuf)
			if i == 0 {
				req.FileOffset = 0
			} else {
				req.FileOffset = uint64(fileOffset)
			}
			fileOffset += nr
			i++
			buf, err := s.Send(req)
			if err != nil {
				s.Debug("", err)
				return err
			}
			res := NewWriteResponse()
			s.Debug("Unmarshalling Write file response ["+filename+"]", nil)
			if err = encoder.Unmarshal(buf, &res); err != nil {
				s.Debug("Raw:\n"+hex.Dump(buf), err)
			}
			if res.Header.Status != mstypes.STATUS_SUCCESS {
				return errors.New("Failed to write file to [" + filename + "]: " + mstypes.StatusMap[res.Header.Status])
			}
		}
	}
	s.Debug("Completed WriteFile ["+filename+"]", nil)
	return nil
}

func (s *Session) WritePipeRequest(treeId uint32, buffer, fileId []byte) error {
	s.Debug("Sending Write pipe request", nil)
	req := s.NewWriteRequest(treeId, fileId, buffer)
	buf, err := s.Send(req)
	if err != nil {
		s.Debug("", err)
		return err
	}
	res := NewWriteResponse()
	s.Debug("Unmarshalling Write pipe response", nil)
	if err := encoder.Unmarshal(buf, &res); err != nil {
		s.Debug("Raw:\n"+hex.Dump(buf), err)
	}
	if res.Header.Status != mstypes.STATUS_SUCCESS {
		return errors.New("Failed to write pipe to " + mstypes.StatusMap[res.Header.Status])
	}
	s.Debug("Completed Write pipe ", nil)
	return nil
}
