package smb

import (
	"context"
	"fmt"
	"net"
	"time"
)

type SMBFingerprint struct {
	// V1Support if supports SMBv1
	V1Support bool

	// Security Mode of the connection
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

func Fingerprint(host string, port int) (*SMBFingerprint, error) {
	var d net.Dialer
	return FingerprintWithDialer(host, port, d.Dial)
}

func fingerprintSignRequired(tcpConn net.Conn) bool {
	d := &Dialer{Initiator: &NTLMInitiator{User: "whatever"}}
	conn, err := d.Negotiator.negotiate(direct(tcpConn), openAccount(clientMaxCreditBalance), context.Background())
	if err != nil {
		return false
	}
	return conn.requireSigning
}

func FingerprintWithDialer(host string, port int, dialer func(network string, addr string) (net.Conn, error)) (*SMBFingerprint, error) {
	conn1, err := dialer("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}

	var info SMBFingerprint
	info.V1Support = NewV1Client().WithConn(conn1).IsSMBv1()
	go conn1.Close()

	conn2, err := dialer("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}
	info.SigningRequired = fingerprintSignRequired(conn2)

	conn3, err := dialer("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}

	d := &Dialer{
		Initiator: &NTLMInitiator{
			User: "whatever",
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, _ = d.DialContext(ctx, conn3)
	infomap := d.Initiator.(*NTLMInitiator).ntlm.Session().InfoMap()
	if infomap == nil {
		return &info, nil
	}

	info.NetBIOSComputerName = infomap.NbComputerName
	info.NetBIOSDomainName = infomap.NbDomainName
	info.DNSComputerName = infomap.DnsComputerName
	info.DNSDomainName = infomap.DnsDomainName
	info.ForestName = infomap.DnsTreeName
	return &info, nil
}
