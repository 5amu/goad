package smb

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"
)

// SMBv1 is supported as far as DETECTION goes. In 2024 I'm not willing to
// fully support it... I guess that help would be appreciated wut not actively
// wanted. Thank you for your understanding.
const ProtocolSmb = "\xFFSMB"
const DialectSmb_1_0 = "\x02NT LM 0.12\x00"

type HeaderV1 struct {
	ProtocolID       []byte `smb:"fixed:4"`
	Command          uint8
	Status           uint32
	Flags            uint8
	Flags2           uint16
	PIDHigh          uint16
	SecurityFeatures []byte `smb:"fixed:8"`
	Reserved         uint16
	TID              uint16
	PIDLow           uint16
	UID              uint16
	MID              uint16
}

type NegotiateReqV1 struct {
	HeaderV1
	WordCount uint8
	ByteCount uint16  // hardcoded to 14
	Dialects  []uint8 `smb:"fixed:12"`
}

type V1Client struct {
	Host      string
	Port      int
	Conn      net.Conn
	messageId int
}

func NewV1Client() *V1Client {
	return &V1Client{}
}

func (c *V1Client) WithHostPort(host string, port int) *V1Client {
	c.Host = host
	c.Port = port
	return c
}

func (c *V1Client) WithConn(conn net.Conn) *V1Client {
	c.Conn = conn
	return c
}

func (c *V1Client) IsSMBv1() bool {
	if c.Conn == nil {
		var err error
		c.Conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", c.Host, c.Port))
		if err != nil {
			return false
		}
	}

	c.messageId = 0
	req := NegotiateReqV1{
		HeaderV1: HeaderV1{
			ProtocolID:       []byte(ProtocolSmb),
			Command:          0x72, //SMB1 Negotiate
			Status:           0,
			Flags:            0x18,
			Flags2:           0xc843,
			PIDHigh:          0,
			SecurityFeatures: []byte{0, 0, 0, 0, 0, 0, 0, 0},
			Reserved:         0,
			TID:              0xffff,
			PIDLow:           0xfeff,
			UID:              0,
			MID:              uint16(c.messageId),
		},
		WordCount: 0,
		ByteCount: 14,
		Dialects:  []uint8(DialectSmb_1_0),
	}

	buf, err := send(c.Conn, req)
	if err != nil {
		return false
	}
	return string(buf[0:4]) == ProtocolSmb
}

func send(conn net.Conn, req interface{}) (res []byte, err error) {
	buf, err := marshal(req, nil)
	if err != nil {
		return nil, err
	}

	b := new(bytes.Buffer)
	if err = binary.Write(b, binary.BigEndian, uint32(len(buf))); err != nil {
		return nil, err
	}

	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	if _, err = rw.Write(append(b.Bytes(), buf...)); err != nil {
		return nil, err
	}
	rw.Flush()

	var size uint32
	if err = binary.Read(rw, binary.BigEndian, &size); err != nil {
		return
	}
	if size > 0x00FFFFFF || size < 4 {
		return nil, fmt.Errorf("invalid NetBIOS session message")
	}

	data := make([]byte, size)
	l, err := io.ReadFull(rw, data)
	if err != nil {
		return nil, err
	}
	if uint32(l) != size {
		return nil, fmt.Errorf("message size invalid")
	}

	protID := data[0:4]
	switch string(protID) {
	default:
		return nil, fmt.Errorf("protocol not recognized")
	case ProtocolSmb:
	}

	return data, nil
}

type BinaryMarshallableV1 interface {
	MarshalBinary(*MetadataV1) ([]byte, error)
	UnmarshalBinary([]byte, *MetadataV1) error
}

type MetadataV1 struct {
	Tags       *TagMapV1
	Lens       map[string]uint64
	Offsets    map[string]uint64
	Parent     interface{}
	ParentBuf  []byte
	CurrOffset uint64
	CurrField  string
}

type TagMapV1 struct {
	m   map[string]interface{}
	has map[string]bool
}

func (t TagMapV1) Has(key string) bool {
	return t.has[key]
}

func (t TagMapV1) Set(key string, val interface{}) {
	t.m[key] = val
	t.has[key] = true
}

func (t TagMapV1) Get(key string) interface{} {
	return t.m[key]
}

func (t TagMapV1) GetInt(key string) (int, error) {
	if !t.Has(key) {
		return 0, fmt.Errorf("key does not exist in tag")
	}
	return t.Get(key).(int), nil
}

func (t TagMapV1) GetString(key string) (string, error) {
	if !t.Has(key) {
		return "", fmt.Errorf("key does not exist in tag")
	}
	return t.Get(key).(string), nil
}

func parseTags(sf reflect.StructField) (*TagMapV1, error) {
	ret := &TagMapV1{
		m:   make(map[string]interface{}),
		has: make(map[string]bool),
	}
	tag := sf.Tag.Get("smb")
	smbTags := strings.Split(tag, ",")
	for _, smbTag := range smbTags {
		tokens := strings.Split(smbTag, ":")
		switch tokens[0] {
		case "len", "offset", "count":
			if len(tokens) != 2 {
				return nil, errors.New("missing required tag data. Expecting key:val")
			}
			ret.Set(tokens[0], tokens[1])
		case "fixed":
			if len(tokens) != 2 {
				return nil, errors.New("missing required tag data. Expecting key:val")
			}
			i, err := strconv.Atoi(tokens[1])
			if err != nil {
				return nil, err
			}
			ret.Set(tokens[0], i)
		case "asn1":
			ret.Set(tokens[0], true)
		}
	}

	return ret, nil
}

func getOffsetByFieldName(fieldName string, meta *MetadataV1) (uint64, error) {
	if meta == nil || meta.Tags == nil || meta.Parent == nil || meta.Lens == nil {
		return 0, errors.New("cannot determine field offset. Missing required metadata")
	}
	var ret uint64
	var found bool
	parentvf := reflect.Indirect(reflect.ValueOf(meta.Parent))
	// To determine offset, we loop through all fields of the struct, summing lengths of previous elements
	// until we reach our field
	for i := 0; i < parentvf.NumField(); i++ {
		tf := parentvf.Type().Field(i)
		if tf.Name == fieldName {
			found = true
			break
		}
		if l, ok := meta.Lens[tf.Name]; ok {
			// Length of field is in cache
			ret += l
		} else {
			// Not in cache. Must marshal field to determine length. Add to cache after
			buf, err := marshal(parentvf.Field(i).Interface(), nil)
			if err != nil {
				return 0, err
			}
			l := uint64(len(buf))
			meta.Lens[tf.Name] = l
			ret += l
		}
	}
	if !found {
		return 0, errors.New("cannot find field name within struct: " + fieldName)
	}
	return ret, nil
}

func getFieldLengthByName(fieldName string, meta *MetadataV1) (uint64, error) {
	var ret uint64
	if meta == nil || meta.Tags == nil || meta.Parent == nil || meta.Lens == nil {
		return 0, errors.New("cannot determine field length. Missing required metadata")
	}

	// Check if length is stored in field length cache
	if val, ok := meta.Lens[fieldName]; ok {
		return uint64(val), nil
	}

	parentvf := reflect.Indirect(reflect.ValueOf(meta.Parent))

	field := parentvf.FieldByName(fieldName)
	if !field.IsValid() {
		return 0, errors.New("invalid field. Cannot determine length")
	}

	bm, ok := field.Interface().(BinaryMarshallableV1)
	if ok {
		// Custom marshallable interface found.
		buf, err := bm.MarshalBinary(meta)
		if err != nil {
			return 0, err
		}
		return uint64(len(buf)), nil
	}

	if field.Kind() == reflect.Ptr {
		field = field.Elem()
	}

	switch field.Kind() {
	case reflect.Struct:
		buf, err := marshal(field.Interface(), nil)
		if err != nil {
			return 0, err
		}
		ret = uint64(len(buf))
	case reflect.Interface:
		return 0, errors.New("interface length calculation not implemented")
	case reflect.Slice, reflect.Array:
		switch field.Type().Elem().Kind() {
		case reflect.Uint8:
			ret = uint64(len(field.Interface().([]byte)))
		default:
			return 0, errors.New("cannot calculate the length of unknown slice type for " + fieldName)
		}
	case reflect.Uint8:
		ret = uint64(binary.Size(field.Interface().(uint8)))
	case reflect.Uint16:
		ret = uint64(binary.Size(field.Interface().(uint16)))
	case reflect.Uint32:
		ret = uint64(binary.Size(field.Interface().(uint32)))
	case reflect.Uint64:
		ret = uint64(binary.Size(field.Interface().(uint64)))
	default:
		return 0, errors.New("cannot calculate the length of unknown kind for field " + fieldName)
	}
	meta.Lens[fieldName] = ret
	return ret, nil
}

func marshal(v interface{}, meta *MetadataV1) ([]byte, error) {
	var ret []byte
	tf := reflect.TypeOf(v)
	vf := reflect.ValueOf(v)

	bm, ok := v.(BinaryMarshallableV1)
	if ok {
		// Custom marshallable interface found.
		buf, err := bm.MarshalBinary(meta)
		if err != nil {
			return nil, err
		}
		return buf, nil
	}

	if tf.Kind() == reflect.Ptr {
		vf = reflect.Indirect(reflect.ValueOf(v))
		tf = vf.Type()
	}

	w := bytes.NewBuffer(ret)
	switch tf.Kind() {
	case reflect.Struct:
		m := &MetadataV1{
			Tags:   &TagMapV1{},
			Lens:   make(map[string]uint64),
			Parent: v,
		}
		for j := 0; j < vf.NumField(); j++ {
			tags, err := parseTags(tf.Field(j))
			if err != nil {
				return nil, err
			}
			m.Tags = tags
			buf, err := marshal(vf.Field(j).Interface(), m)
			if err != nil {
				return nil, err
			}
			m.Lens[tf.Field(j).Name] = uint64(len(buf))
			if err := binary.Write(w, binary.LittleEndian, buf); err != nil {
				return nil, err
			}
		}
	case reflect.Slice, reflect.Array:
		switch tf.Elem().Kind() {
		case reflect.Uint8:
			if err := binary.Write(w, binary.LittleEndian, v.([]uint8)); err != nil {
				return nil, err
			}
		case reflect.Uint16:
			if err := binary.Write(w, binary.LittleEndian, v.([]uint16)); err != nil {
				return nil, err
			}
		}
	case reflect.Uint8:
		if err := binary.Write(w, binary.LittleEndian, vf.Interface().(uint8)); err != nil {
			return nil, err
		}
	case reflect.Uint16:
		data := vf.Interface().(uint16)
		if meta != nil && meta.Tags.Has("len") {
			fieldName, err := meta.Tags.GetString("len")
			if err != nil {
				return nil, err
			}
			l, err := getFieldLengthByName(fieldName, meta)
			if err != nil {
				return nil, err
			}
			data = uint16(l)
		}
		if meta != nil && meta.Tags.Has("offset") {
			fieldName, err := meta.Tags.GetString("offset")
			if err != nil {
				return nil, err
			}
			l, err := getOffsetByFieldName(fieldName, meta)
			if err != nil {
				return nil, err
			}
			data = uint16(l)
		}
		if err := binary.Write(w, binary.LittleEndian, data); err != nil {
			return nil, err
		}
	case reflect.Uint32:
		data := vf.Interface().(uint32)
		if meta != nil && meta.Tags.Has("len") {
			fieldName, err := meta.Tags.GetString("len")
			if err != nil {
				return nil, err
			}
			l, err := getFieldLengthByName(fieldName, meta)
			if err != nil {
				return nil, err
			}
			data = uint32(l)
		}
		if meta != nil && meta.Tags.Has("offset") {
			fieldName, err := meta.Tags.GetString("offset")
			if err != nil {
				return nil, err
			}
			l, err := getOffsetByFieldName(fieldName, meta)
			if err != nil {
				return nil, err
			}
			data = uint32(l)
		}
		if err := binary.Write(w, binary.LittleEndian, data); err != nil {
			return nil, err
		}
	case reflect.Uint64:
		if err := binary.Write(w, binary.LittleEndian, vf.Interface().(uint64)); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("marshal not implemented for kind: %s", tf.Kind())
	}
	return w.Bytes(), nil
}
