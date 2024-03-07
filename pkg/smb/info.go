package smb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"time"

	"github.com/5amu/goad/pkg/encoder"
	"github.com/5amu/goad/pkg/krb5/ntlm"
)

type SMBFingerprint struct {
	// V1Support if supports SMBv1
	V1Support bool

	// Security Modes of the connection
	SigningEnabled  bool
	SigningRequired bool

	// Reported Vesion of OS
	OSVersion string

	// NETBIOS
	NetBIOSComputerName string
	NetBIOSDomainName   string

	// DNS
	DNSComputerName string
	DNSDomainName   string
	ForestName      string
}

func fingerprintV2(conn net.Conn) (*SMBFingerprint, error) {
	var info SMBFingerprint

	s := &Session{
		Conn: conn,
	}

	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5
	negotiateReqPacket := s.NewNegotiateReq()
	sessionPrefixLen := 4
	packetHeaderLen := 64
	minNegoResponseLen := 64

	response, err := s.Send(negotiateReqPacket)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil, nil
		}
		return nil, err
	}

	// Check the length of the response to see if it is lower than the minimum
	// packet size for SMB2 NEGOTIATE Response Packet
	if len(response) < sessionPrefixLen+packetHeaderLen+minNegoResponseLen {
		return nil, nil
	}

	negotiateResponseData := NewNegotiateRes()
	if err := encoder.Unmarshal(response, &negotiateResponseData); err != nil {
		return nil, err
	}

	if !reflect.DeepEqual(negotiateResponseData.Header.ProtocolID[:], []byte{0xFE, 'S', 'M', 'B'}) {
		return nil, nil
	}

	if negotiateResponseData.Header.StructureSize != 0x40 {
		return nil, nil
	}

	if negotiateResponseData.Header.Command != 0x0000 { // SMB2 NEGOTIATE (0x0000)
		return nil, nil
	}

	if negotiateResponseData.StructureSize != 0x41 {
		return nil, nil
	}

	signingEnabled := false
	signingRequired := false
	if negotiateResponseData.SecurityMode&1 == 1 {
		signingEnabled = true
	}
	if negotiateResponseData.SecurityMode&2 == 2 {
		signingRequired = true
	}
	info.SigningEnabled = signingEnabled
	info.SigningRequired = signingRequired

	/**
	 * At this point, we know SMBv2 is detected.
	 * Below, we try to obtain more metadata via session setup request w/ NTLM auth
	 */

	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-authsod/9a20f8ac-612a-4e0a-baab-30e922e7e1f5
	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a3c2c28-d6b0-48ed-b917-a86b2ca4575f
	sessionSetupReqPacket, err := s.NewSessionSetup1Req()
	if err != nil {
		return &info, err
	}

	response, err = s.Send(sessionSetupReqPacket)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return &info, nil
		}
		return &info, err
	}

	challengeLen := 56
	challengeStartOffset := bytes.Index(response, []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0})
	if challengeStartOffset == -1 {
		return &info, nil
	}
	if len(response) < challengeStartOffset+challengeLen {
		return &info, nil
	}

	sessionResponseData := ntlm.NewChallenge()
	response = response[challengeStartOffset:]
	if err := encoder.Unmarshal(response, &sessionResponseData); err != nil {
		return &info, err
	}

	challengeVersion := make([]byte, 8)
	binary.LittleEndian.PutUint64(challengeVersion, sessionResponseData.Version)

	// Check if valid NTLM challenge response message structure
	if sessionResponseData.MessageType != 0x00000002 || sessionResponseData.Reserved != 0 ||
		!reflect.DeepEqual(challengeVersion[4:], []byte{0, 0, 0, 0xF}) {
		return &info, nil
	}

	// Parse: Version
	type version struct {
		MajorVersion byte
		MinorVersion byte
		BuildNumber  uint16
	}
	var versionData version
	versionBuf := bytes.NewBuffer(challengeVersion)
	err = binary.Read(versionBuf, binary.LittleEndian, &versionData)
	if err != nil {
		return &info, err
	}
	info.OSVersion = fmt.Sprintf("%d.%d.%d", versionData.MajorVersion,
		versionData.MinorVersion,
		versionData.BuildNumber)

	// Parse: TargetInfo
	AvIDMap := map[uint16]string{
		1: "netbiosComputerName",
		2: "netbiosDomainName",
		3: "dnsComputerName",
		4: "dnsDomainName",
		5: "forestName", // MsvAvDnsTreeName
	}
	type AVPair struct {
		AvID  uint16
		AvLen uint16
		// Value (variable)
	}
	var avPairLen = 4
	targetInfoLen := int(sessionResponseData.TargetInfoLen)
	if targetInfoLen > 0 {
		startIdx := int(sessionResponseData.TargetInfoBufferOffset)
		if startIdx+targetInfoLen > len(response) {
			return &info, nil
		}
		var avPair AVPair
		avPairBuf := bytes.NewBuffer(response[startIdx : startIdx+avPairLen])
		err = binary.Read(avPairBuf, binary.LittleEndian, &avPair)
		if err != nil {
			return &info, err
		}
		currIdx := startIdx
		for avPair.AvID != 0 {
			if field, exists := AvIDMap[avPair.AvID]; exists {
				value := strings.ReplaceAll(string(response[currIdx+avPairLen:currIdx+avPairLen+int(avPair.AvLen)]), "\x00", "")
				switch field {
				case "netbiosComputerName":
					info.NetBIOSComputerName = value
				case "netbiosDomainName":
					info.NetBIOSDomainName = value
				case "dnsComputerName":
					info.DNSComputerName = value
				case "dnsDomainName":
					info.DNSDomainName = value
				case "forestName": // MsvAvDnsTreeName
					info.ForestName = value
				}
			}
			currIdx += avPairLen + int(avPair.AvLen)
			if currIdx+avPairLen > startIdx+targetInfoLen {
				return &info, nil
			}
			avPairBuf = bytes.NewBuffer(response[currIdx : currIdx+avPairLen])
			err = binary.Read(avPairBuf, binary.LittleEndian, &avPair)
			if err != nil {
				return &info, nil
			}
		}
	}

	return &info, nil
}

func FingerprintSMB2(conn net.Conn) (*SMBFingerprint, error) {
	return fingerprintV2(conn)
}

func FingerprintSMB(host string, port int, dialer func(network string, addr string) (net.Conn, error)) (*SMBFingerprint, error) {
	conn1, err := dialer("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}
	_ = conn1.SetDeadline(time.Now().Add(2 * time.Second))

	fprint, err := fingerprintV2(conn1)
	if err != nil {
		return fprint, err
	}
	go conn1.Close()

	conn2, err := dialer("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}
	_ = conn2.SetDeadline(time.Now().Add(2 * time.Second))

	fprint.V1Support = NewV1Client().WithConn(conn2).IsSMBv1()
	defer conn2.Close()
	return fprint, nil
}
