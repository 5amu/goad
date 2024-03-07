package smb

import (
	"bufio"
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"runtime/debug"

	"github.com/5amu/goad/pkg/encoder"
	"github.com/5amu/goad/pkg/krb5/gss"
	"github.com/5amu/goad/pkg/krb5/ntlm"
)

type Session struct {
	IsSigningRequired bool
	IsAuthenticated   bool
	debug             bool
	SecurityMode      uint16
	MessageID         uint64
	SessionID         uint64
	Conn              net.Conn
	Dialect           uint16
	Options           Options
	Trees             map[string]uint32
}

type Options struct {
	Host        string
	Port        int
	Workstation string
	Domain      string
	User        string
	Password    string
	Hash        string
	Debug       bool
	Conn        net.Conn
}

func NewSession(opt Options) (s *Session, err error) {
	var conn net.Conn = opt.Conn
	if opt.Conn == nil {
		conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", opt.Host, opt.Port))
		if err != nil {
			return
		}
	}

	s = &Session{
		IsSigningRequired: false,
		IsAuthenticated:   false,
		debug:             opt.Debug,
		SecurityMode:      0,
		MessageID:         0,
		SessionID:         0,
		Dialect:           0,
		Conn:              conn,
		Options:           opt,
		Trees:             make(map[string]uint32),
	}

	s.Debug("Negotiating protocol", nil)
	err = s.NegotiateProtocol()
	if err != nil {
		return
	}
	return s, nil
}

func (s *Session) Debug(msg string, err error) {
	if s.debug {
		log.Println("[ DEBUG ] ", msg)
		if err != nil {
			debug.PrintStack()
		}
	}
}

func (s *Session) NegotiateProtocol() error {
	negReq := s.NewNegotiateReq()
	s.Debug("Sending NegotiateProtocol request", nil)
	buf, err := s.Send(negReq)
	if err != nil {
		s.Debug("", err)
		return err
	}

	negRes := NewNegotiateRes()
	s.Debug("Unmarshalling NegotiateProtocol response", nil)
	if err := encoder.Unmarshal(buf, &negRes); err != nil {
		s.Debug("Raw:\n"+hex.Dump(buf), err)
		return err
	}

	if negRes.Header.Status != StatusOk {
		return fmt.Errorf("NT Status Error: %d", negRes.Header.Status)
	}

	// Check SPNEGO security blob
	spnegoOID, err := gss.ObjectIDStrToInt(gss.SpnegoOid)
	if err != nil {
		return err
	}
	oid := negRes.SecurityBlob.OID
	if !oid.Equal(asn1.ObjectIdentifier(spnegoOID)) {
		return fmt.Errorf(
			"unknown security type OID [expecting %s]: %s",
			gss.SpnegoOid,
			negRes.SecurityBlob.OID)
	}

	// Check for NTLMSSP support
	ntlmsspOID, err := gss.ObjectIDStrToInt(gss.NtLmSSPMechTypeOid)
	if err != nil {
		s.Debug("", err)
		return err
	}

	hasNTLMSSP := false
	for _, mechType := range negRes.SecurityBlob.Data.MechTypes {
		if mechType.Equal(asn1.ObjectIdentifier(ntlmsspOID)) {
			hasNTLMSSP = true
			break
		}
	}
	if !hasNTLMSSP {
		return errors.New("server does not support NTLMSSP")
	}

	s.SecurityMode = negRes.SecurityMode
	s.Dialect = negRes.DialectRevision

	// Determine whether signing is required
	mode := uint16(s.SecurityMode)
	if mode&SecurityModeSigningEnabled > 0 {
		if mode&SecurityModeSigningRequired > 0 {
			s.IsSigningRequired = true
		} else {
			s.IsSigningRequired = false
		}
	} else {
		s.IsSigningRequired = false
	}

	s.Debug("Sending SessionSetup1 request", nil)
	ssreq, err := s.NewSessionSetup1Req()
	if err != nil {
		s.Debug("", err)
		return err
	}
	ssres, err := NewSessionSetup1Res()
	if err != nil {
		s.Debug("", err)
		return err
	}
	_, err = encoder.Marshal(ssreq)
	if err != nil {
		s.Debug("", err)
		return err
	}

	buf, err = s.Send(ssreq)
	if err != nil {
		s.Debug("Raw:\n"+hex.Dump(buf), err)
		return err
	}

	s.Debug("Unmarshalling SessionSetup1 response", nil)
	if err := encoder.Unmarshal(buf, &ssres); err != nil {
		s.Debug("", err)
		return err
	}

	challenge := ntlm.NewChallenge()
	resp := ssres.SecurityBlob
	if err := encoder.Unmarshal(resp.ResponseToken, &challenge); err != nil {
		s.Debug("", err)
		return err
	}

	if ssres.Header.Status != StatusMoreProcessingRequired {
		status := StatusMap[negRes.Header.Status]
		return fmt.Errorf("NT Status Error: %s", status)
	}
	s.SessionID = ssres.Header.SessionID

	s.Debug("Sending SessionSetup2 request", nil)
	ss2req, err := s.NewSessionSetup2Req()
	if err != nil {
		s.Debug("", err)
		return err
	}

	var auth ntlm.Authenticate
	if s.Options.Hash != "" {
		// Hash present, use it for auth
		s.Debug("Performing hash-based authentication", nil)
		auth = ntlm.NewAuthenticateHash(s.Options.Domain, s.Options.User, s.Options.Workstation, s.Options.Hash, challenge)
	} else {
		// No hash, use password
		s.Debug("Performing password-based authentication", nil)
		auth = ntlm.NewAuthenticatePass(s.Options.Domain, s.Options.User, s.Options.Workstation, s.Options.Password, challenge)
	}

	responseToken, err := encoder.Marshal(auth)
	if err != nil {
		s.Debug("", err)
		return err
	}
	resp2 := ss2req.SecurityBlob
	resp2.ResponseToken = responseToken
	ss2req.SecurityBlob = resp2
	ss2req.Header.Credits = 127
	_, err = encoder.Marshal(ss2req)
	if err != nil {
		s.Debug("", err)
		return err
	}

	buf, err = s.Send(ss2req)
	if err != nil {
		s.Debug("", err)
		return err
	}
	s.Debug("Unmarshalling SessionSetup2 response", nil)
	var authResp Header
	if err := encoder.Unmarshal(buf, &authResp); err != nil {
		s.Debug("Raw:\n"+hex.Dump(buf), err)
		return err
	}
	if authResp.Status != StatusOk {
		status := StatusMap[authResp.Status]
		return fmt.Errorf("NT Status Error: %s", status)
	}
	s.IsAuthenticated = true

	s.Debug("Completed NegotiateProtocol and SessionSetup", nil)
	return nil
}

func (s *Session) TreeConnect(name string) error {
	s.Debug("Sending TreeConnect request ["+name+"]", nil)
	req, err := s.NewTreeConnectReq(name)
	if err != nil {
		s.Debug("", err)
		return err
	}
	buf, err := s.Send(req)
	if err != nil {
		s.Debug("", err)
		return err
	}
	var res TreeConnectRes
	s.Debug("Unmarshalling TreeConnect response ["+name+"]", nil)
	if err := encoder.Unmarshal(buf, &res); err != nil {
		s.Debug("Raw:\n"+hex.Dump(buf), err)
		return err
	}

	if res.Header.Status != StatusOk {
		return errors.New("Failed to connect to tree: " + StatusMap[res.Header.Status])
	}
	s.Trees[name] = res.Header.TreeID

	s.Debug("Completed TreeConnect ["+name+"]", nil)
	return nil
}

func (s *Session) TreeDisconnect(name string) error {

	var (
		treeid    uint32
		pathFound bool
	)
	for k, v := range s.Trees {
		if k == name {
			treeid = v
			pathFound = true
			break
		}
	}

	if !pathFound {
		err := errors.New("unable to find tree path for disconnect")
		s.Debug("", err)
		return err
	}

	s.Debug("Sending TreeDisconnect request ["+name+"]", nil)
	req, err := s.NewTreeDisconnectReq(treeid)
	if err != nil {
		s.Debug("", err)
		return err
	}
	buf, err := s.Send(req)
	if err != nil {
		s.Debug("", err)
		return err
	}
	s.Debug("Unmarshalling TreeDisconnect response for ["+name+"]", nil)
	var res TreeDisconnectRes
	if err := encoder.Unmarshal(buf, &res); err != nil {
		s.Debug("Raw:\n"+hex.Dump(buf), err)
		return err
	}
	if res.Header.Status != StatusOk {
		return errors.New("Failed to disconnect from tree: " + StatusMap[res.Header.Status])
	}
	delete(s.Trees, name)

	s.Debug("TreeDisconnect completed ["+name+"]", nil)
	return nil
}

func (s *Session) Close() {
	s.Debug("Closing session", nil)
	for k := range s.Trees {
		s.TreeDisconnect(k)
	}
	s.Debug("Closing TCP connection", nil)
	s.Conn.Close()
	s.Debug("Session close completed", nil)
}

func (s *Session) Send(req interface{}) (res []byte, err error) {
	buf, err := encoder.Marshal(req)
	if err != nil {
		s.Debug("", err)
		return nil, err
	}

	b := new(bytes.Buffer)
	if err = binary.Write(b, binary.BigEndian, uint32(len(buf))); err != nil {
		s.Debug("", err)
		return
	}

	rw := bufio.NewReadWriter(bufio.NewReader(s.Conn), bufio.NewWriter(s.Conn))
	if _, err = rw.Write(append(b.Bytes(), buf...)); err != nil {
		s.Debug("", err)
		return
	}
	rw.Flush()

	var size uint32
	if err = binary.Read(rw, binary.BigEndian, &size); err != nil {
		s.Debug("", err)
		return
	}
	if size > 0x00FFFFFF || size < 4 {
		return nil, errors.New("invalid NetBIOS Session message")
	}

	data := make([]byte, size)
	l, err := io.ReadFull(rw, data)
	if err != nil {
		s.Debug("", err)
		return nil, err
	}
	if uint32(l) != size {
		return nil, errors.New("message size invalid")
	}

	protID := data[0:4]
	switch string(protID) {
	default:
		return nil, errors.New("protocol Not Implemented")
	case ProtocolSmb:
	case ProtocolSmb2:
	}

	s.MessageID++
	return data, nil
}
