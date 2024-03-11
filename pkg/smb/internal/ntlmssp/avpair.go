package ntlmssp

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
)

type AvID uint16

const (
	MsvAvEOL AvID = iota
	MsvAvNbComputerName
	MsvAvNbDomainName
	MsvAvDNSComputerName
	MsvAvDNSDomainName
	MsvAvDNSTreeName
	MsvAvFlags
	MsvAvTimestamp
	MsvAvSingleHost
	MsvAvTargetName
	MsvChannelBindings
)

const (
	msvAvFlagAuthenticationConstrained uint32 = 1 << iota
	msvAvFlagMICProvided
	msvAvFlagUntrustedSPNSource
)

type avPair struct {
	ID     AvID
	Length uint16
}

type targetInfo struct {
	Pairs map[AvID][]uint8
	Order []AvID
}

func newTargetInfo() targetInfo {
	return targetInfo{
		Pairs: make(map[AvID][]uint8),
		Order: []AvID{},
	}
}

func (t *targetInfo) Get(id AvID) ([]uint8, bool) {
	v, ok := t.Pairs[id]
	return v, ok
}

func (t *targetInfo) GetString(id AvID) (string, bool) {
	v, ok := t.Get(id)
	if !ok {
		return "", ok
	}
	utf8String, err := utf16ToString(v)
	if err != nil {
		// not utf16 and not empty, casting
		return string(v), ok
	}
	return utf8String, ok
}

func (t *targetInfo) Set(id AvID, value []uint8) {
	if id == MsvAvEOL {
		return
	}
	if _, ok := t.Get(id); !ok {
		t.Order = append(t.Order, id)
	}
	t.Pairs[id] = value
}

func (t *targetInfo) Del(id AvID) {
	delete(t.Pairs, id)
	j := 0
	for _, n := range t.Order {
		if n != id {
			t.Order[j] = n
			j++
		}
	}
	t.Order = t.Order[:j]
}

func (t *targetInfo) Len() int {
	return len(t.Pairs)
}

func init() {
	gob.Register(targetInfo{})
}

func (t *targetInfo) Clone() (*targetInfo, error) {
	b := bytes.Buffer{}
	enc := gob.NewEncoder(&b)
	dec := gob.NewDecoder(&b)
	if err := enc.Encode(*t); err != nil {
		return nil, err
	}
	var copy targetInfo
	if err := dec.Decode(&copy); err != nil {
		return nil, err
	}
	return &copy, nil
}

func (t *targetInfo) Marshal() ([]byte, error) {
	b := bytes.Buffer{}

	for _, k := range t.Order {
		if k == MsvAvEOL {
			continue
		}

		v := t.Pairs[k]

		if err := binary.Write(&b, binary.LittleEndian, &avPair{k, uint16(len(v))}); err != nil {
			return nil, err
		}

		b.Write(v)
	}

	// Append required MsvAvEOL pair
	if err := binary.Write(&b, binary.LittleEndian, &avPair{MsvAvEOL, 0}); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func (t *targetInfo) Unmarshal(b []byte) error {
	reader := bytes.NewReader(b)

	for {
		var pair avPair

		if err := binary.Read(reader, binary.LittleEndian, &pair); err != nil {
			return err
		}

		if pair.ID == MsvAvEOL {
			break
		}

		value := make([]byte, pair.Length)
		n, err := reader.Read(value)
		if err != nil {
			return err
		}
		if n != int(pair.Length) {
			return fmt.Errorf("expected %d bytes, only read %d", pair.Length, n)
		}

		t.Set(pair.ID, value)
	}

	return nil
}
