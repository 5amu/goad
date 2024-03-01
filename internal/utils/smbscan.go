package utils

import (
	"sync"

	"github.com/5amu/goad/internal/printer"
	"github.com/5amu/goad/pkg/smb"
)

func GetSMBInfo(host string) *smb.SMBInfo {
	data, err := smb.GatherSMBInfo(host)
	if data == nil || err != nil {
		return nil
	}
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
			v := GetSMBInfo(s)
			<-guard
			if v != nil {
				prt := printer.NewPrinter("SMB", s, v.NetBIOSName, 445)
				mapMutex.Lock()
				ret[s] = v
				mapMutex.Unlock()
				prt.PrintInfo(v.String())
			}
			wg.Done()
		}(t)
	}
	wg.Wait()
	return ret
}
