package mstypes

import (
	"encoding/binary"
)

type MSDSManagedPasswordBlob struct {
	Version                         uint16
	Lenght                          uint32
	CurrentPasswordOffset           uint16
	PreviousPasswordOffset          uint16
	QueryPasswordIntervalOffset     uint16
	UnchangedPasswordIntervalOffset uint16
	CurrentPassword                 []byte
	PreviousPassword                []byte
	QueryPasswordInterval           uint64
	UnchangedPasswordInterval       uint64
}

func nextNul(b []byte) uint16 {
	var stop bool = false
	for i, n := range b {
		if n == 0 {
			if stop {
				return uint16(i - 1)
			} else {
				stop = true
			}
		} else {
			stop = false
		}
	}
	return 0
}

func NewMSDSManagedPasswordBlob(data []byte) *MSDSManagedPasswordBlob {
	var blob MSDSManagedPasswordBlob

	blob.Version = binary.LittleEndian.Uint16(data[0:2])
	blob.Lenght = binary.LittleEndian.Uint32(data[4:8])
	blob.CurrentPasswordOffset = binary.LittleEndian.Uint16(data[8:10])
	blob.PreviousPasswordOffset = binary.LittleEndian.Uint16(data[10:12])
	blob.QueryPasswordIntervalOffset = binary.LittleEndian.Uint16(data[12:14])
	blob.UnchangedPasswordIntervalOffset = binary.LittleEndian.Uint16(data[14:16])

	endOfCurrentPassword := 16 + nextNul(data[16:])
	blob.CurrentPassword = data[16:endOfCurrentPassword]
	endOfPreviousPassword := endOfCurrentPassword + nextNul(data[endOfCurrentPassword:])
	blob.PreviousPassword = data[endOfCurrentPassword:endOfPreviousPassword]

	endOfPadding := endOfPreviousPassword
	stop := false
	for !stop {
		tmp := endOfPadding
		endOfPadding = nextNul(data[endOfPadding:])
		if endOfPadding == 0 {
			endOfPadding = tmp
			stop = true
		}
	}

	blob.QueryPasswordInterval = binary.LittleEndian.Uint64(data[endOfPadding : endOfPadding+8])
	blob.UnchangedPasswordInterval = binary.LittleEndian.Uint64(data[endOfPadding+8 : endOfPadding+16])
	return &blob
}
