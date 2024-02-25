package utils

import (
	"sync"

	"github.com/5amu/goad/internal/printer"
	"github.com/5amu/goad/pkg/smb"
)

func getSMBInfo(host string) *smb.SMBInfo {
	data, err := smb.GatherSMBInfo(host)
	if data == nil || err != nil {
		return nil
	}
	prt := printer.NewPrinter("SMB", host, data.NetBIOSName, 445)
	prt.PrintInfo(data.String())
	return data
}

func GatherSMBInfoToMap(targets []string, port int) map[string]*smb.SMBInfo {
	ret := make(map[string]*smb.SMBInfo)
	var wg sync.WaitGroup

	var mapMutex sync.Mutex
	guard := make(chan struct{}, DefaultMaxConcurrent)
	for _, t := range targets {
		wg.Add(1)
		guard <- struct{}{}
		go func(s string) {
			v := getSMBInfo(s)
			<-guard
			if v != nil {
				mapMutex.Lock()
				ret[s] = v
				mapMutex.Unlock()
			}
			wg.Done()
		}(t)
	}
	wg.Wait()
	return ret
}
