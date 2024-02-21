package utils

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/net/proxy"
)

var DefaultTimeout = 3 * time.Second

func GetDialer() func(network, addr string) (net.Conn, error) {
	pd := proxy.FromEnvironment()
	if pd != nil {
		return pd.Dial
	}
	return net.Dial
}

func getConnection(network string, host string, port int) (net.Conn, error) {
	pd := proxy.FromEnvironment()
	if pd != nil {
		conn, err := pd.Dial(network, fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			return nil, err
		}
		return conn, conn.SetDeadline(time.Now().Add(2 * time.Second))
	}
	conn, err := net.DialTimeout(network, fmt.Sprintf("%s:%d", host, port), 2*time.Second)
	if err != nil {
		return nil, err
	}
	return conn, conn.SetDeadline(time.Now().Add(2 * time.Second))
}

func GetConnection(host string, port int) (net.Conn, error) {
	return getConnection("tcp", host, port)
}

func GetConnectionUDP(host string, port int) (net.Conn, error) {
	return getConnection("udp", host, port)
}