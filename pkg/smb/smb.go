package smb

import (
	"fmt"
	"strings"
	"time"

	"github.com/5amu/goad/pkg/utils"
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

func getMetadata(host string) (*plugins.ServiceSMB, error) {
	conn, err := utils.GetConnection(host, 445)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return smbfingerprint.DetectSMBv2(conn, 1*time.Second)
}

func GatherSMBInfo(host string) (*SMBInfo, error) {
	var info SMBInfo
	var err error

	var metadata *plugins.ServiceSMB
	mch := make(chan *plugins.ServiceSMB)
	go func() {
		if m, err := getMetadata(host); err == nil {
			mch <- m
		}
	}()

	select {
	case metadata = <-mch:
	case <-time.After(time.Second):
		return nil, fmt.Errorf("timeout smb metadata")
	}

	if metadata == nil {
		return nil, fmt.Errorf("invalid smb metadata")
	}
	info.WindowsVersion = metadata.OSVersion
	info.NetBIOSName = metadata.NetBIOSComputerName
	info.Domain = metadata.DNSDomainName
	info.DNSComputerName = strings.ToLower(metadata.DNSComputerName)

	var data *zgrabsmb.SMBLog
	if data, err = getSMBInfo(host, true, true); err != nil {
		if data, err = getSMBInfo(host, true, false); err != nil {
			fmt.Println(err)
			return nil, err
		}
	}

	if data != nil {
		info.SigningRequired = data.NegotiationLog.SecurityMode&zgrabsmb.SecurityModeSigningRequired > 0
	}
	return &info, nil
}

func getSMBInfo(host string, setupSession, v1 bool) (*zgrabsmb.SMBLog, error) {
	conn, err := utils.GetConnection(host, 445)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(1 * time.Second))

	result, err := zgrabsmb.GetSMBLog(conn, setupSession, v1, false)
	if err != nil {
		return nil, err
	}
	return result, nil
}
