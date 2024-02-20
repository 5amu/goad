package utils

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/net/proxy"
)

var DefaultTimeout = 3 * time.Second

func getConnection(network string, host string, port int) (net.Conn, error) {
	pd := proxy.FromEnvironment()
	if pd != nil {
		return pd.Dial(network, fmt.Sprintf("%s:%d", host, port))
	}
	return net.DialTimeout(network, fmt.Sprintf("%s:%d", host, port), DefaultTimeout)
}

func GetConnection(host string, port int) (net.Conn, error) {
	return getConnection("tcp", host, port)
}

func GetConnectionUDP(host string, port int) (net.Conn, error) {
	return getConnection("udp", host, port)
}
