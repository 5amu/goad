package msrpc

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/e7a38186-cde2-40ad-90c7-650822bd6333
const (
	SCMRUUID         = "367abb81-9844-35f1-ad32-98f038001003"
	SCMRVersion      = 2
	SCMRVersionMinor = 0

	SCMRNamedPipe = "svcctl"
)

// opnum
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/0d7a7011-9f41-470d-ad52-8535b47ac282
const (
	RCloseServiceHandle = iota
	RControlService
	RDeleteService
	RLockServiceDatabase
	RQueryServiceObjectSecurity
	RSetServiceObjectSecurity
	RQueryServiceStatus
	RSetServiceStatus
	RUnlockServiceDatabase
	RNotifyBootConfigStatus
	_ // 10 is skipped (not used on wire)
	RChangeServiceConfigW
	RCreateServiceW
	REnumDependentServicesW
	REnumServicesStatusW
	ROpenSCManagerW
	ROpenServiceW
	RQueryServiceConfigW
	RQueryServiceLockStatusW
	RStartServiceW
	RGetServiceDisplayNameW
	RGetServiceKeyNameW
	_ // 22 is skipped (not used on wire)
	RChangeServiceConfigA
	RCreateServiceA
	REnumDependentServicesA
	REnumServicesStatusA
	ROpenSCManagerA
	ROpenServiceA
	RQueryServiceConfigA
	RQueryServiceLockStatusA
	RStartServiceA
	RGetServiceDisplayNameA
	RGetServiceKeyNameA
	_ // 34 is skipped (not used on wire)
	REnumServiceGroupW
	RChangeServiceConfig2A
	RChangeServiceConfig2W
	RQueryServiceConfig2A
	RQueryServiceConfig2W
	RQueryServiceStatusEx
	REnumServicesStatusExA
	REnumServicesStatusExW
	_ // 43 is skipped (not used on wire)
	RCreateServiceWOW64A
	RCreateServiceWOW64W
	_ // 46 is skipped (not used on wire)
	RNotifyServiceStatusChange
	RGetNotifyResults
	RCloseNotifyHandle
	RControlServiceExA
	RControlServiceExW
	_ // 52 is skipped (not used on wire)
	_ // 53 is skipped (not used on wire)
	_ // 54 is skipped (not used on wire)
	_ // 55 is skipped (not used on wire)
	RQueryServiceConfigEx
	_ // 57 is skipped (not used on wire)
	_ // 58 is skipped (not used on wire)
	_ // 59 is skipped (not used on wire)
	RCreateWowService
	_ // 61 is skipped (not used on wire)
	_ // 62 is skipped (not used on wire)
	_ // 63 is skipped (not used on wire)
	ROpenSCManager2
)

// access request (access mask)
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/0d7a7011-9f41-470d-ad52-8535b47ac282
const (
	SERVICE_ALL_ACCESS           = 0x000F01FF
	SERVICE_CHANGE_CONFIG        = 0x00000002
	SERVICE_ENUMERATE_DEPENDENTS = 0x00000008
	SERVICE_INTERROGATE          = 0x00000080
	SERVICE_PAUSE_CONTINUE       = 0x00000040
	SERVICE_QUERY_CONFIG         = 0x00000001
	SERVICE_QUERY_STATUS         = 0x00000004
	SERVICE_START                = 0x00000010
	SERVICE_STOP                 = 0x00000020
	SERVICE_USER_DEFINED_CONTROL = 0x00000100
	SERVICE_SET_STATUS           = 0x00008000
)

// Service Control Manager
const (
	SC_MANAGER_LOCK               = 0x00000008
	SC_MANAGER_CREATE_SERVICE     = 0x00000002
	SC_MANAGER_ENUMERATE_SERVICE  = 0x00000004
	SC_MANAGER_CONNECT            = 0x00000001
	SC_MANAGER_QUERY_LOCK_STATUS  = 0x00000010
	SC_MANAGER_MODIFY_BOOT_CONFIG = 0x0020
)

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/6a8ca926-9477-4dd4-b766-692fab07227e
const (
	SERVICE_KERNEL_DRIVER       = 0x00000001
	SERVICE_FILE_SYSTEM_DRIVER  = 0x00000002
	SERVICE_WIN32_OWN_PROCESS   = 0x00000010
	SERVICE_WIN32_SHARE_PROCESS = 0x00000020
	SERVICE_INTERACTIVE_PROCESS = 0x00000100
)

// Service Start Type
const (
	SERVICE_BOOT_START   = 0x00000000
	SERVICE_SYSTEM_START = 0x00000001
	SERVICE_AUTO_START   = 0x00000002
	SERVICE_DEMAND_START = 0x00000003
	SERVICE_DISABLED     = 0x00000004
)

// Service Error Control
const (
	SERVICE_ERROR_IGNORE   = 0x00000000
	SERVICE_ERROR_NORMAL   = 0x00000001
	SERVICE_ERROR_SEVERE   = 0x00000002
	SERVICE_ERROR_CRITICAL = 0x00000003
)

// Opnum 0
type RCloseServiceHandleStruct struct{}

// Opnum 1
type RControlServiceStruct struct{}

// Opnum 2
type RDeleteServiceStruct struct{}

// Opnum 3
type RLockServiceDatabaseStruct struct{}

// Opnum 4
type RQueryServiceObjectSecurityStruct struct{}

// Opnum 5
type RSetServiceObjectSecurityStruct struct{}

// Opnum 6
type RQueryServiceStatusStruct struct{}

// Opnum 7
type RSetServiceStatusStruct struct{}

// Opnum 8
type RUnlockServiceDatabaseStruct struct{}

// Opnum 9
type RNotifyBootConfigStatusStruct struct{}

// Opnum 11
type RChangeServiceConfigWStruct struct{}

// Opnum 12
type RCreateServiceWStruct struct{}

// Opnum 13
type REnumDependentServicesWStruct struct{}

// Opnum 14
type REnumServicesStatusWStruct struct{}

// Opnum 15
type ROpenSCManagerWStruct struct{}

// Opnum 16
type ROpenServiceWStruct struct{}

// Opnum 17
type RQueryServiceConfigWStruct struct{}

// Opnum 18
type RQueryServiceLockStatusWStruct struct{}

// Opnum 19
type RStartServiceWStruct struct{}

// Opnum 20
type RGetServiceDisplayNameWStruct struct{}

// Opnum 21
type RGetServiceKeyNameWStruct struct{}

// Opnum 23
type RChangeServiceConfigAStruct struct{}

// Opnum 24
type RCreateServiceAStruct struct{}

// Opnum 25
type REnumDependentServicesAStruct struct{}

// Opnum 26
type REnumServicesStatusAStruct struct{}

// Opnum 27
type ROpenSCManagerAStruct struct{}

// Opnum 28
type ROpenServiceAStruct struct{}

// Opnum 29
type RQueryServiceConfigAStruct struct{}

// Opnum 30
type RQueryServiceLockStatusAStruct struct{}

// ########################################################################################################
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
	HeaderStruct
	AllocHint     uint32
	ContextId     uint16
	CancelCount   uint8
	Reserved      uint8
	ContextHandle []byte `smb:"fixed:20"`
	ReturnCode    uint32
}

type SCRpcHandle struct {
	MaxCount    uint32
	Offset      uint32
	ActualCount uint32
	Data        []byte
}

type OpenServiceRequest struct {
	ContextHandle []byte `smb:"fixed:20"`
	ServiceName   SCRpcHandle
	Reserved      uint16
	AccessMask    uint32
}

type OpenServiceResponse struct {
	HeaderStruct
	AllocHint     uint32
	ContextId     uint16
	CancelCount   uint8
	Reserved      uint8
	ContextHandle []byte `smb:"fixed:20"`
	ReturnCode    uint32
}

type CreateServiceRequest struct {
	ContextHandle       []byte `smb:"fixed:20"`
	ServiceName         SCRpcHandle
	Reserved1           uint16
	DisplayName         SVCCTLHandle
	Reserved2           uint16
	AccessMask          uint32
	ServiceType         uint32
	ServiceStartType    uint32
	ServiceErrorControl uint32
	BinaryPathName      SCRpcHandle
	NULLPointer         uint32
	TagId               uint32
	NULLPointer2        uint32
	DependSize          uint32
	NULLPointer3        uint32
	NULLPointer4        uint32
	PasswordSize        uint32
}

type CreateServiceResponse struct {
	HeaderStruct
	AllocHint     uint32
	ContextId     uint16
	CancelCount   uint8
	Reserved      uint8
	TagId         uint32
	ContextHandle []byte `smb:"fixed:20"`
	ReturnCode    uint32
}

type StartServiceRequest struct {
	ContextHandle []byte `smb:"fixed:20"`
	Argc          uint32
	Argv          []byte `smb:"fixed:4"`
}

type StartServiceResponse struct {
	HeaderStruct
	AllocHint   uint32
	ContextId   uint16
	CancelCount uint8
	Reserved    uint8
	StubData    uint32
}

type DeleteServiceRequest struct {
	ContextHandle []byte `smb:"fixed:20"`
}

type DeleteServiceResponse struct {
	HeaderStruct
	AllocHint   uint32
	ContextId   uint16
	CancelCount uint8
	Reserved    uint8
	ReturnCode  uint32
}
