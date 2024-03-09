package optftp

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/5amu/goad/internal/printer"
	"github.com/5amu/goad/pkg/proxyconn"
	"github.com/jlaffaye/ftp"
)

func connect(host string, port int) (*ftp.ServerConn, error) {
	srvC := make(chan *ftp.ServerConn)
	errC := make(chan error)
	go func(h string, p int) {
		if c, err := ftp.Dial(
			fmt.Sprintf("%s:%d", host, port),
			ftp.DialWithDialFunc(proxyconn.GetDialFunc()),
		); err != nil {
			errC <- err
		} else {
			srvC <- c
		}
	}(host, port)

	select {
	case err := <-errC:
		return nil, err
	case srv := <-srvC:
		return srv, nil
	case <-time.After(2 * time.Second):
	}
	return nil, fmt.Errorf("connect timed out")
}

func GrabBanner(host string, port int) (string, error) {
	conn, err := proxyconn.GetConnection(host, port)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = conn.Close()
	}()

	result := make(chan string)
	go func(c net.Conn) {
		banner := make([]byte, 256)
		n, err := conn.Read(banner)
		if err != nil {
			result <- ""
		}
		result <- strings.ReplaceAll(string(banner[:n]), "\r\n", "")
	}(conn)

	select {
	case r := <-result:
		if r != "" {
			sl := strings.Split(r, " ")
			if len(sl) > 1 {
				r = strings.Join(sl[1:len(sl)-1], " ")
			}
			return r, nil
		}
	case <-time.After(2 * time.Second):
	}
	return "", fmt.Errorf("unable to connect")
}

func gatherFTPBanner2Map(mutex *sync.Mutex, targets []string, port int) map[string]string {
	res := make(map[string]string)
	var mapMutex sync.Mutex

	mutex.Lock()
	defer mutex.Unlock()

	var wg sync.WaitGroup
	guard := make(chan struct{}, 64)
	for _, t := range targets {
		wg.Add(1)
		guard <- struct{}{}
		go func(p string) {
			s, err := GrabBanner(p, port)
			if err == nil {
				prt := printer.NewPrinter("FTP", p, s, port)
				mapMutex.Lock()
				res[p] = s
				mapMutex.Unlock()
				prt.PrintInfo(s)
			}
			wg.Done()
			<-guard
		}(t)
	}
	wg.Wait()
	return res
}
