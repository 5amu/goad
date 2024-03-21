package msrpc

import (
	"fmt"

	"github.com/5amu/goad/pkg/smb/internal/utf16le"
)

// e1af8308-5d1f-11c9-91a4-08002b14a0fa
//var EPMv4_UUID = []byte("0883afe11f5dc91191a408002b14a0fa")

var SVCCTL_UUID = []byte("81bb7a364498f135ad3298f038001003")

const (
	SVCCTL_VERSION       = 2
	SVCCTL_VERSION_MINOR = 0

	SVCCTL_DLL = "svcctl"
)

// opnum
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/0d7a7011-9f41-470d-ad52-8535b47ac282
const (
	RCloseServiceHandle         = 0
	RControlService             = 1
	RDeleteService              = 2
	RLockServiceDatabase        = 3
	RQueryServiceObjectSecurity = 4
	RSetServiceObjectSecurity   = 5
	RQueryServiceStatus         = 6
	RSetServiceStatus           = 7
	RUnlockServiceDatabase      = 8
	RNotifyBootConfigStatus     = 9
	RChangeServiceConfigW       = 11
	RCreateServiceW             = 12
	REnumDependentServicesW     = 13
	REnumServicesStatusW        = 14
	ROpenSCManagerW             = 15
	ROpenServiceW               = 16
	RQueryServiceConfigW        = 17
	RQueryServiceLockStatusW    = 18
	RStartServiceW              = 19
	RGetServiceDisplayNameW     = 20
	RGetServiceKeyNameW         = 21
	RChangeServiceConfigA       = 23
	RCreateServiceA             = 24
	REnumDependentServicesA     = 25
	REnumServicesStatusA        = 26
	ROpenSCManagerA             = 27
	ROpenServiceA               = 28
	RQueryServiceConfigA        = 29
	RQueryServiceLockStatusA    = 30
	RStartServiceA              = 31
	RGetServiceDisplayNameA     = 32
	RGetServiceKeyNameA         = 33
	REnumServiceGroupW          = 35
	RChangeServiceConfig2A      = 36
	RChangeServiceConfig2W      = 37
	RQueryServiceConfig2A       = 38
	RQueryServiceConfig2W       = 39
	RQueryServiceStatusEx       = 40
	REnumServicesStatusExA      = 41
	REnumServicesStatusExW      = 42
	RCreateServiceWOW64A        = 44
	RCreateServiceWOW64W        = 45
	RNotifyServiceStatusChange  = 47
	RGetNotifyResults           = 48
	RCloseNotifyHandle          = 49
	RControlServiceExA          = 50
	RControlServiceExW          = 51
	RQueryServiceConfigEx       = 56
	RCreateWowService           = 60
	ROpenSCManager2             = 64
)

// access request
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/0d7a7011-9f41-470d-ad52-8535b47ac282
const (
	SERVICE_ALL_ACCESS        = 0x000F01FF
	SC_MANAGER_CREATE_SERVICE = 0x00000002
	SC_MANAGER_CONNECT        = 0x00000001
)

type SVCCTLHandle struct {
	ReferentId  uint32 `smb:"offset:Data"`
	MaxCount    uint32
	Offset      uint32
	ActualCount uint32
	Data        []byte
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/dc84adb3-d51d-48eb-820d-ba1c6ca5faf2
type OpenSCManagerRequest struct {
	MachineName  SVCCTLHandle
	DatabaseName SVCCTLHandle
	Reserved     uint16
	AccessMask   uint32
}

type OpenSCManagerResponse struct {
	RpcHeaderStruct
	AllocHint     uint32
	ContextId     uint16
	CancelCount   uint8
	Reserved      uint8
	ContextHandle []byte `smb:"fixed:20"`
	ReturnCode    uint32
}

type OpenSCManager struct {
	CallId     uint32
	ServerName string
}

func (r *OpenSCManager) Size() int {
	off := utf16le.EncodedStringLen(r.ServerName) + 2
	off += utf16le.EncodedStringLen("ServicesActive") + 2

	off += 16      // Rpc base header
	off += 2       // context ID
	off += 2       // Opnum
	off += 16 + 16 // fixed bytes of the 2 handles
	off += 4       // access mask
	off += 4
	return roundup(off, 4)
}

func (r *OpenSCManager) Encode(b []byte) {
	var srvname []byte = make([]byte, utf16le.EncodedStringLen(r.ServerName))
	utf16le.EncodeString(srvname, r.ServerName)
	srvname = append(srvname, []byte{0, 0}...)
	var srvcount int = utf16le.EncodedStringLen(r.ServerName)/2 + 1

	var dbname []byte = make([]byte, utf16le.EncodedStringLen("ServicesActive"))
	utf16le.EncodeString(dbname, "ServicesActive")
	dbname = append(dbname, []byte{0, 0}...)
	var dbcount int = utf16le.EncodedStringLen("ServicesActive")/2 + 1

	req := RpcRequestStruct{
		RpcHeaderStruct: RpcHeaderStruct{
			RpcVersion:         RPC_VERSION,
			RpcVersionMinor:    RPC_VERSION_MINOR,
			PacketType:         RPC_TYPE_REQUEST,
			PacketFlags:        RPC_PACKET_FLAG_FIRST | RPC_PACKET_FLAG_LAST,
			DataRepresentation: []byte{0x10, 0, 0, 0},
			AuthLength:         0,
			CallId:             r.CallId,
		},
		ContextID: 0,
		OpNum:     ROpenSCManagerW,
		Payload: OpenSCManagerRequest{
			MachineName: SVCCTLHandle{
				MaxCount:    uint32(srvcount),
				Offset:      0,
				ActualCount: uint32(srvcount),
				Data:        srvname,
			},
			DatabaseName: SVCCTLHandle{
				MaxCount:    uint32(dbcount),
				Offset:      0,
				ActualCount: uint32(dbcount),
				Data:        dbname,
			},
			Reserved:   0xbfbf,
			AccessMask: SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT,
		},
	}
	copy(b, req.Bytes())
}

type OpenServiceRequest struct {
	ContextHandle []byte `smb:"fixed:20"`
	ServiceName   SVCCTLHandle
	AccessMask    uint32
}

type OpenServiceResponse struct {
	RpcHeaderStruct
	AllocHint     uint32
	ContextId     uint16
	CancelCount   uint8
	Reserved      uint8
	ContextHandle []byte `smb:"fixed:20"`
	ReturnCode    uint32
}

type OpenService struct {
	CallId        uint32
	ServiceName   string
	ContextHandle []byte `smb:"fixed:20"`
}

func (r *OpenService) Size() int {
	off := utf16le.EncodedStringLen(r.ServiceName) + 2
	off = roundup(off, 4)
	off += 16 // Rpc base header
	off += 2  // context ID
	off += 2  // Opnum
	off += 20 // Context Handle
	off += 16 // SVC Handle size
	off += 4  // accessmask
	return off + 1
}

func (r *OpenService) Encode(b []byte) {
	var srvname []byte = make([]byte, utf16le.EncodedStringLen(r.ServiceName))
	utf16le.EncodeString(srvname, r.ServiceName)
	srvname = append(srvname, []byte{0, 0}...)
	var srvcount int = utf16le.EncodedStringLen(r.ServiceName)/2 + 1

	req := RpcRequestStruct{
		RpcHeaderStruct: RpcHeaderStruct{
			RpcVersion:         RPC_VERSION,
			RpcVersionMinor:    RPC_VERSION_MINOR,
			PacketType:         RPC_TYPE_REQUEST,
			PacketFlags:        RPC_PACKET_FLAG_FIRST | RPC_PACKET_FLAG_LAST,
			DataRepresentation: []byte{0x10, 0, 0, 0},
			AuthLength:         0,
			CallId:             r.CallId,
		},
		ContextID: 0,
		OpNum:     ROpenServiceW,
		Payload: OpenServiceRequest{
			ContextHandle: r.ContextHandle,
			ServiceName: SVCCTLHandle{
				MaxCount:    uint32(srvcount),
				ActualCount: uint32(srvcount),
				Data:        srvname,
			},
			AccessMask: SERVICE_ALL_ACCESS,
		},
	}
	fmt.Println(req.Bytes(), r.Size())
	copy(b, req.Bytes())
}
