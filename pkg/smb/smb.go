package smb

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/5amu/goad/pkg/utils"
	"github.com/hirochachacha/go-smb2"
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

type Client struct {
	Host    string
	Port    int
	Domain  string
	session *smb2.Session
}

func NewClient(host string, port int, domain string) *Client {
	return &Client{
		Host:   host,
		Port:   port,
		Domain: domain,
	}
}

func (c *Client) authenticate(username, password, hash string) error {
	conn, err := utils.GetConnection(c.Host, c.Port)
	if err != nil {
		return err
	}

	var initiator smb2.NTLMInitiator
	if password != "" {
		initiator = smb2.NTLMInitiator{
			User:     username,
			Password: password,
			Domain:   c.Domain,
		}
	} else {
		initiator = smb2.NTLMInitiator{
			User:   username,
			Hash:   []byte(hash),
			Domain: c.Domain,
		}
	}

	d := &smb2.Dialer{
		Initiator: &initiator,
	}

	session, err := d.DialContext(context.TODO(), conn)
	if err != nil {
		return err
	}

	c.session = session
	return nil
}

func (c *Client) Authenticate(username, password string) error {
	return c.authenticate(username, password, "")
}

func (c *Client) AuthenticateWithHash(username, hash string) error {
	return c.authenticate(username, "", hash)
}

type Share struct {
	Name     string
	Readable bool
	Writable bool
}

func (c *Client) ListSharenames() ([]string, error) {
	return c.session.ListSharenames()
}

func (c *Client) ListShares() ([]Share, error) {
	sh, err := c.session.ListSharenames()
	if err != nil {
		return nil, err
	}

	var res []Share
	for _, sname := range sh {
		if strings.EqualFold(sname, "IPC$") {
			res = append(res, Share{
				Name:     sname,
				Readable: true,
				Writable: false,
			})
			continue
		}
		var readable bool = false
		var writable bool = false

		fs, err := c.session.Mount(sname)
		if err != nil {
			res = append(res, Share{
				Name:     sname,
				Readable: readable,
				Writable: writable,
			})
			continue
		}
		readable = true

		err = fs.WriteFile("goadtest.txt", []byte("test"), 0444)
		writable = !os.IsPermission(err)
		if writable {
			// cleanup
			_ = fs.Remove("goadtest.txt")
		}

		_ = fs.Umount()

		res = append(res, Share{
			Name:     sname,
			Readable: readable,
			Writable: writable,
		})
	}
	return res, nil
}
