package optldap

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"
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

func toDN(s string) string {
	return fmt.Sprintf("dc=%s", strings.Join(strings.Split(s, "."), ",dc="))
}

func DecodeSID(s string) string {
	b := []byte(s)
	revisionLvl := int(b[0])
	subAuthorityCount := int(b[1]) & 0xFF

	var authority int
	for i := 2; i <= 7; i++ {
		authority = authority | int(b[i])<<(8*(5-(i-2)))
	}

	var size = 4
	var offset = 8
	var subAuthorities []int
	for i := 0; i < subAuthorityCount; i++ {
		var subAuthority int
		for k := 0; k < size; k++ {
			subAuthority = subAuthority | (int(b[offset+k])&0xFF)<<(8*k)
		}
		subAuthorities = append(subAuthorities, subAuthority)
		offset += size
	}

	var builder strings.Builder
	builder.WriteString("S-")
	builder.WriteString(fmt.Sprintf("%d-", revisionLvl))
	builder.WriteString(fmt.Sprintf("%d", authority))
	for _, v := range subAuthorities {
		builder.WriteString(fmt.Sprintf("-%d", v))
	}
	return builder.String()
}

func DecodeADTimestamp(timestamp string) string {
	adtime, _ := strconv.ParseInt(timestamp, 10, 64)
	if (adtime == 9223372036854775807) || (adtime == 0) {
		return "Not Set"
	}
	unixtime_int64 := adtime/(10*1000*1000) - 11644473600
	unixtime := time.Unix(unixtime_int64, 0)
	return unixtime.Format("2006-01-02 3:4:5 pm")
}

func DecodeZuluTimestamp(timestamp string) string {
	zulu, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return ""
	}
	return zulu.Format("2006-01-02 3:4:5 pm")
}

func UnpackToSlice(i interface{}) []string {
	toUnpack, ok := i.([]string)
	if ok {
		return toUnpack
	}
	unpacked, ok := i.(string)
	if !ok {
		return nil
	}
	return []string{unpacked}
}

func UnpackToString(i interface{}) string {
	unpacked, ok := i.([]string)
	if !ok {
		unpacked, ok := i.(string)
		if ok {
			return unpacked
		}
		return ""
	}
	switch len(unpacked) {
	case 0:
		return ""
	default:
		return unpacked[0]
	}
}
