package winrm

type Transport string

const (
	PLAINTEXT Transport = "plaintext"
	KERBEROS  Transport = "kerberos"
	SSL       Transport = "ssl"
	NTLM      Transport = "ntlm"
	CREDSSP   Transport = "credssp"
)

type WinrmClient struct {
	Host       string
	Trans      Transport
	Username   string
	Password   string
	Realm      string
	Service    string
	Keytab     string
	Timeout    int
	KDC        string
	Encryption bool
	Proxy      string
}

func (c *WinrmClient) OpenShell() error {
	return nil
}
