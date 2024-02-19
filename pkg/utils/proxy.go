package utils

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/net/proxy"
)

var DefaultTimeout = 3 * time.Second

func GetConnection(host string, port int) (net.Conn, error) {
	pd := proxy.FromEnvironment()
	if pd != nil {
		return pd.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	}
	return net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), DefaultTimeout)
}
