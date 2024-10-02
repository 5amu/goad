package auth

import (
	"encoding/asn1"
	"fmt"

	"github.com/geoffgarside/ber"
)

var (
	SpnegoOid     = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 5, 5, 2})
	MsKerberosOid = asn1.ObjectIdentifier([]int{1, 2, 840, 48018, 1, 2, 2})
	KerberosOid   = asn1.ObjectIdentifier([]int{1, 2, 840, 113554, 1, 2, 2})
	NlmpOid       = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 311, 2, 2, 10})
)

// "not_defined_in_RFC4178@please_ignore"
var NegHints = asn1.RawValue{
	FullBytes: []byte{
		0xa3, 0x2a, 0x30, 0x28, 0xa0, 0x26, 0x1b, 0x24, 0x6e, 0x6f, 0x74, 0x5f, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x65, 0x64, 0x5f,
		0x69, 0x6e, 0x5f, 0x52, 0x46, 0x43, 0x34, 0x31, 0x37, 0x38, 0x40, 0x70, 0x6c, 0x65, 0x61, 0x73,
		0x65, 0x5f, 0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65,
	},
}

type NegTokenInit struct {
	MechTypes   []asn1.ObjectIdentifier `asn1:"explicit,optional,tag:0"`
	ReqFlags    asn1.BitString          `asn1:"explicit,optional,tag:1"`
	MechToken   []byte                  `asn1:"explicit,optional,tag:2"`
	MechListMIC []byte                  `asn1:"explicit,optional,tag:3"`
}

type NegTokenResp struct {
	NegState      asn1.Enumerated       `asn1:"optional,explicit,tag:0"`
	SupportedMech asn1.ObjectIdentifier `asn1:"optional,explicit,tag:1"`
	ResponseToken []byte                `asn1:"optional,explicit,tag:2"`
	MechListMIC   []byte                `asn1:"optional,explicit,tag:3"`
}

type InitialContextToken struct { // `asn1:"application,tag:0"`
	ThisMech asn1.ObjectIdentifier `asn1:"optional"`
	Init     []NegTokenInit        `asn1:"optional,explict,tag:0"`
	Resp     []NegTokenResp        `asn1:"optional,explict,tag:1"`
}

func EncodeNegTokenInit(types []asn1.ObjectIdentifier, token []byte) (bs []byte, err error) {
	initCtxToken := InitialContextToken{
		ThisMech: SpnegoOid,
		Init: []NegTokenInit{
			{
				MechTypes: types,
				MechToken: token,
			},
		},
	}
	if bs, err = asn1.Marshal(initCtxToken); err != nil {
		return nil, err
	}

	bs[0] = 0x60 // `asn1:"application,tag:0"`
	return bs, nil
}

func DecodeNegTokenInit(bs []byte) (*NegTokenInit, error) {
	var init InitialContextToken
	if _, err := ber.UnmarshalWithParams(bs, &init, "application,tag:0"); err != nil {
		return nil, err
	}
	return &init.Init[0], nil
}

func EncodeNegTokenResp(state asn1.Enumerated, typ asn1.ObjectIdentifier, token, mechListMIC []byte) (bs []byte, err error) {
	initCtxToken := InitialContextToken{
		Resp: []NegTokenResp{
			{
				NegState:      state,
				SupportedMech: typ,
				ResponseToken: token,
				MechListMIC:   mechListMIC,
			},
		},
	}
	if bs, err = asn1.Marshal(initCtxToken); err != nil {
		return nil, err
	}

	skip := 1
	if bs[skip] > 128 {
		skip += int(bs[skip]) - 128
	}
	return bs[skip+1:], nil
}

func DecodeNegTokenResp(bs []byte) (*NegTokenResp, error) {
	var resp NegTokenResp
	if _, err := ber.UnmarshalWithParams(bs, &resp, "explicit,tag:1"); err != nil {
		return nil, err
	}
	return &resp, nil
}

type Initiator interface {
	GetOID() asn1.ObjectIdentifier
	InitSecContext() ([]byte, error)            // GSS_Init_sec_context
	AcceptSecContext(sc []byte) ([]byte, error) // GSS_Accept_sec_context
	GetMIC(bs []byte) []byte                    // GSS_getMIC
	SessionKey() []byte                         // QueryContextAttributes(ctx, SECPKG_ATTR_SESSION_KEY, &out)
}

type SpnegoClient struct {
	Mechs        []Initiator
	MechTypes    []asn1.ObjectIdentifier
	SelectedMech Initiator
}

func NewSpnegoClient(mechs []Initiator) *SpnegoClient {
	mechTypes := make([]asn1.ObjectIdentifier, len(mechs))
	for i, mech := range mechs {
		mechTypes[i] = mech.GetOID()
	}
	return &SpnegoClient{
		Mechs:     mechs,
		MechTypes: mechTypes,
	}
}

func (c *SpnegoClient) GetOID() asn1.ObjectIdentifier {
	return SpnegoOid
}

func (c *SpnegoClient) InitSecContext() ([]byte, error) {
	if len(c.Mechs) < 1 {
		return nil, fmt.Errorf("no mech in spnego client")
	}

	// first mech in client is always preferred
	mechToken, err := c.Mechs[0].InitSecContext()
	if err != nil {
		return nil, err
	}
	return EncodeNegTokenInit(c.MechTypes, mechToken)
}

func (c *SpnegoClient) AcceptSecContext(negTokenRespBytes []byte) ([]byte, error) {
	negTokenResp, err := DecodeNegTokenResp(negTokenRespBytes)
	if err != nil {
		return nil, err
	}

	for i, mechType := range c.MechTypes {
		if mechType.Equal(negTokenResp.SupportedMech) {
			c.SelectedMech = c.Mechs[i]
			break
		}
	}

	responseToken, err := c.SelectedMech.AcceptSecContext(negTokenResp.ResponseToken)
	if err != nil {
		return nil, err
	}

	ms, err := asn1.Marshal(c.MechTypes)
	if err != nil {
		return nil, err
	}

	mechListMIC := c.SelectedMech.GetMIC(ms)
	return EncodeNegTokenResp(1, nil, responseToken, mechListMIC)
}

func (c *SpnegoClient) GetMIC(bs []byte) []byte {
	if c.SelectedMech == nil {
		return nil
	}
	return c.SelectedMech.GetMIC(bs)
}

func (c *SpnegoClient) SessionKey() []byte {
	if c.SelectedMech == nil {
		return nil
	}
	return c.SelectedMech.SessionKey()
}
