package proxyconn

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/proxy"
)

var DefaultTimeout = 3 * time.Second

func GetDialFunc() func(network, addr string) (net.Conn, error) {
	pd := proxy.FromEnvironment()
	if pd != nil {
		return pd.Dial
	}
	return net.Dial
}

func getConnection(network string, host string, port int) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return proxy.Dial(ctx, network, fmt.Sprintf("%s:%d", host, port))
}

func GetConnection(host string, port int) (net.Conn, error) {
	return getConnection("tcp", host, port)
}

func GetConnectionUDP(host string, port int) (net.Conn, error) {
	return getConnection("udp", host, port)
}
