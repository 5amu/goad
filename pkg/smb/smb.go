package smb

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	smbfingerprint "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/smb"
	zgrabsmb "github.com/zmap/zgrab2/lib/smb/smb"
)

type SMBInfo struct {
	WindowsVersion  string
	NetBIOSName     string
	DNSComputerName string
	Domain          string
	SigningRequired bool
	SMBv1Support    bool
}

func (i *SMBInfo) String() string {
	return fmt.Sprintf(
		"%s (version:%s) (name:%s) (domain:%s) (signing:%t) (SMBv1:%t)",
		i.DNSComputerName,
		i.WindowsVersion,
		i.NetBIOSName,
		i.Domain,
		i.SigningRequired,
		i.SMBv1Support,
	)
}

func GatherSMBInfo(host string) (*SMBInfo, error) {
	var info SMBInfo
	timeout := 3 * time.Second

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", 445)), timeout)
	if err != nil {
		return nil, err
	}

	var metadata *plugins.ServiceSMB

	metadata, err = smbfingerprint.DetectSMBv2(conn, timeout)
	if err != nil {
		return nil, err
	}
	_ = conn.Close()

	conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", host, 445))
	if err != nil {
		return nil, err
	}
	_, err = getSMBInfo(conn, true, true)
	info.SMBv1Support = err == nil
	_ = conn.Close()

	conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", host, 445))
	if err != nil {
		return nil, err
	}
	data, err := getSMBInfo(conn, true, false)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if data != nil {
		info.SigningRequired = data.NegotiationLog.SecurityMode&zgrabsmb.SecurityModeSigningRequired > 0
	}

	if metadata != nil {
		info.WindowsVersion = metadata.OSVersion
		info.NetBIOSName = metadata.NetBIOSComputerName
		info.Domain = metadata.DNSDomainName
		info.DNSComputerName = strings.ToLower(metadata.DNSComputerName)
	}
	return &info, nil
}

func getSMBInfo(conn net.Conn, setupSession, v1 bool) (*zgrabsmb.SMBLog, error) {
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	defer func() {
		_ = conn.SetDeadline(time.Time{})
	}()

	result, err := zgrabsmb.GetSMBLog(conn, setupSession, v1, false)
	if err != nil {
		return nil, err
	}
	return result, nil
}
