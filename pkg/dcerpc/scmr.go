package dcerpc

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/e7a38186-cde2-40ad-90c7-650822bd6333
var MSRPC_SCMR MsrpcUUID = MsrpcUUID{
	UUID:         "367abb81-9844-35f1-ad32-98f038001003",
	Version:      2,
	VersionMinor: 0,
	NamedPipe:    "svcctl",
}

// Access Codes
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
	SERVICE_USER_DEFINED_CTRL    = 0x00000100
	SERVICE_SET_STATUS           = 0x00008000
)

// SCM Access Codes
const (
	SC_MANAGER_LOCK               = 0x00000008
	SC_MANAGER_CREATE_SERVICE     = 0x00000002
	SC_MANAGER_ENUMERATE_SERVICE  = 0x00000004
	SC_MANAGER_CONNECT            = 0x00000001
	SC_MANAGER_QUERY_LOCK_STATUS  = 0x00000010
	SC_MANAGER_MODIFY_BOOT_CONFIG = 0x00000020
)

// ServiceNoChange
const SERVICE_NO_CHANGE = 0xFFFFFFFF

// Service Types
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/6a8ca926-9477-4dd4-b766-692fab07227e
const (
	SERVICE_KERNEL_DRIVER       = 0x00000001
	SERVICE_FILE_SYSTEM_DRIVER  = 0x00000002
	SERVICE_WIN32_OWN_PROCESS   = 0x00000010
	SERVICE_WIN32_SHARE_PROCESS = 0x00000020
	SERVICE_INTERACTIVE_PROCESS = 0x00000100
)

// Service Start Types
const (
	SERVICE_BOOT_START   = 0x00000000
	SERVICE_SYSTEM_START = 0x00000001
	SERVICE_AUTO_START   = 0x00000002
	SERVICE_DEMAND_START = 0x00000003
	SERVICE_DISABLED     = 0x00000004
)

// Error Control
const (
	SERVICE_ERROR_IGNORE   = 0x00000000
	SERVICE_ERROR_NORMAL   = 0x00000001
	SERVICE_ERROR_SEVERE   = 0x00000002
	SERVICE_ERROR_CRITICAL = 0x00000003
)

// Service Control Codes
const (
	SERVICE_CONTROL_CONTINUE       = 0x00000003
	SERVICE_CONTROL_INTERROGATE    = 0x00000004
	SERVICE_CONTROL_PARAMCHANGE    = 0x00000006
	SERVICE_CONTROL_PAUSE          = 0x00000002
	SERVICE_CONTROL_STOP           = 0x00000001
	SERVICE_CONTROL_NETBINDADD     = 0x00000007
	SERVICE_CONTROL_NETBINDREMOVE  = 0x00000008
	SERVICE_CONTROL_NETBINDENABLE  = 0x00000009
	SERVICE_CONTROL_NETBINDDISABLE = 0x0000000A
)

// Service State
const (
	SERVICE_ACTIVE    = 0x00000001
	SERVICE_INACTIVE  = 0x00000002
	SERVICE_STATE_ALL = 0x00000003
)

// Current State
const (
	SERVICE_CONTINUE_PENDING = 0x00000005
	SERVICE_PAUSE_PENDING    = 0x00000006
	SERVICE_PAUSED           = 0x00000007
	SERVICE_RUNNING          = 0x00000004
	SERVICE_START_PENDING    = 0x00000002
	SERVICE_STOP_PENDING     = 0x00000003
	SERVICE_STOPPED          = 0x00000001
)

// Controls Accepted
const (
	SERVICE_ACCEPT_PARAMCHANGE           = 0x00000008
	SERVICE_ACCEPT_PAUSE_CONTINUE        = 0x00000002
	SERVICE_ACCEPT_SHUTDOWN              = 0x00000004
	SERVICE_ACCEPT_STOP                  = 0x00000001
	SERVICE_ACCEPT_HARDWAREPROFILECHANGE = 0x00000020
	SERVICE_ACCEPT_POWEREVENT            = 0x00000040
	SERVICE_ACCEPT_SESSIONCHANGE         = 0x00000080
	SERVICE_ACCEPT_PRESHUTDOWN           = 0x00000100
	SERVICE_ACCEPT_TIMECHANGE            = 0x00000200
	ERVICE_ACCEPT_TRIGGEREVENT           = 0x00000400
)

// Security Information
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/deed7901-ba2b-45ce-ba66-e071928bdfc1
const (
	DACL_SECURITY_INFORMATION  = 0x4
	GROUP_SECURITY_INFORMATION = 0x2
	OWNER_SECURITY_INFORMATION = 0x1
	SACL_SECURITY_INFORMATION  = 0x8
)

// Service Config2 Info Levels
const (
	SERVICE_CONFIG_DESCRIPTION              = 0x00000001
	SERVICE_CONFIG_FAILURE_ACTIONS          = 0x00000002
	SERVICE_CONFIG_DELAYED_AUTO_START_INFO  = 0x00000003
	SERVICE_CONFIG_FAILURE_ACTIONS_FLAG     = 0x00000004
	SERVICE_CONFIG_SERVICE_SID_INFO         = 0x00000005
	SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO = 0x00000006
	SERVICE_CONFIG_PRESHUTDOWN_INFO         = 0x00000007
	SERVICE_CONFIG_PREFERRED_NODE           = 0x00000009
	SERVICE_CONFIG_RUNLEVEL_INFO            = 0x0000000A
)

// SC_ACTIONS Types
const (
	SC_ACTION_NONE        = 0
	SC_ACTION_RESTART     = 1
	SC_ACTION_REBOOT      = 2
	SC_ACTION_RUN_COMMAND = 3
)

// SERVICE_SID_INFO types
const (
	SERVICE_SID_TYPE_NONE         = 0x00000000
	SERVICE_SID_TYPE_RESTRICTED   = 0x00000003
	SERVICE_SID_TYPE_UNRESTRICTED = 0x00000001
)

// SC_STATUS_TYPE types
const SC_STATUS_PROCESS_INFO = 0

// Notify Mask
const (
	SERVICE_NOTIFY_CREATED          = 0x00000080
	SERVICE_NOTIFY_CONTINUE_PENDING = 0x00000010
	SERVICE_NOTIFY_DELETE_PENDING   = 0x00000200
	SERVICE_NOTIFY_DELETED          = 0x00000100
	SERVICE_NOTIFY_PAUSE_PENDING    = 0x00000020
	SERVICE_NOTIFY_PAUSED           = 0x00000040
	SERVICE_NOTIFY_RUNNING          = 0x00000008
	SERVICE_NOTIFY_START_PENDING    = 0x00000002
	SERVICE_NOTIFY_STOP_PENDING     = 0x00000004
	SERVICE_NOTIFY_STOPPED          = 0x00000001
)

// SERVICE_CONTROL_STATUS_REASON_IN_PARAMSW Reasons
const (
	SERVICE_STOP_CUSTOM    = 0x20000000
	SERVICE_STOP_PLANNED   = 0x40000000
	SERVICE_STOP_UNPLANNED = 0x10000000
)

// SERVICE_TRIGGER triggers
const (
	SERVICE_TRIGGER_TYPE_DEVICE_INTERFACE_ARRIVAL = 0x00000001
	SERVICE_TRIGGER_TYPE_IP_ADDRESS_AVAILABILITY  = 0x00000002
	SERVICE_TRIGGER_TYPE_DOMAIN_JOIN              = 0x00000003
	SERVICE_TRIGGER_TYPE_FIREWALL_PORT_EVENT      = 0x00000004
	SERVICE_TRIGGER_TYPE_GROUP_POLICY             = 0x00000005
	SERVICE_TRIGGER_TYPE_CUSTOM                   = 0x00000020
)

// SERVICE_TRIGGER actions
const (
	SERVICE_TRIGGER_ACTION_SERVICE_START = 0x00000001
	SERVICE_TRIGGER_ACTION_SERVICE_STOP  = 0x00000002
)

// SERVICE_TRIGGER subTypes
const (
	DOMAIN_JOIN_GUID                              = "1ce20aba-9851-4421-9430-1ddeb766e809"
	DOMAIN_LEAVE_GUID                             = "ddaf516e-58c2-4866-9574-c3b615d42ea1"
	FIREWALL_PORT_OPEN_GUID                       = "b7569e07-8421-4ee0-ad10-86915afdad09"
	FIREWALL_PORT_CLOSE_GUID                      = "a144ed38-8e12-4de4-9d96-e64740b1a524"
	MACHINE_POLICY_PRESENT_GUID                   = "659FCAE6-5BDB-4DA9-B1FF-CA2A178D46E0"
	NETWORK_MANAGER_FIRST_IP_ADDRESS_ARRIVAL_GUID = "4f27f2de-14e2-430b-a549-7cd48cbc8245"
	NETWORK_MANAGER_LAST_IP_ADDRESS_REMOVAL_GUID  = "cc4ba62a-162e-4648-847a-b6bdf993e335"
	USER_POLICY_PRESENT_GUID                      = "54FB46C8-F089-464C-B1FD-59D1B62C3B50"
)

// SERVICE_TRIGGER_SPECIFIC_DATA_ITEM dataTypes
const (
	SERVICE_TRIGGER_DATA_TYPE_BINARY = 0x00000001
	SERVICE_TRIGGER_DATA_TYPE_STRING = 0x00000002
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

// Return Values for SCMR Operations
const (
	ERROR_SUCCESS                   = 0
	ERROR_ACCESS_DENIED             = 5
	ERROR_INVALID_HANDLE            = 6
	ERROR_INVALID_DATA              = 13
	ERROR_INVALID_PARAMETER         = 87
	ERROR_SERVICE_DATABASE_LOCKED   = 1055
	ERROR_INVALID_SERVICE_ACCOUNT   = 1057
	ERROR_CIRCULAR_DEPENDENCY       = 1059
	ERROR_INVALID_SERVICE_LOCK      = 1071
	ERROR_SERVICE_MARKED_FOR_DELETE = 1072
	ERROR_DUPLICATE_SERVICE_NAME    = 1078
	ERROR_SHUTDOWN_IN_PROGRESS      = 1115
)

// ============================================================================
// BEGIN: Data Types
// ============================================================================

type ScRpcHandle struct {
	Handle []byte `smb:"fixed:20"`
}
type LpScRpcHandle ScRpcHandle

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d
type SecurityDescriptor struct {
	Revision    uint8
	Sbz1        uint8
	Control     uint16
	OffsetOwner uint32 `smb:"offset:OwnserSid"`
	OffsetGroup uint32 `smb:"offset:GroupSid"`
	OffsetSacl  uint32 `smb:"offset:Sacl"`
	OffsetDacl  uint32 `smb:"offset:Dacl"`
	OwnerSid    []byte
	GroupSid    []byte
	Sacl        []byte
	Dacl        []byte
}
type LpSecurityDescriptor struct {
	PointerHeader
	SecurityDescriptor
}

type ServiceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

type LpServiceStatus struct {
	PointerHeader
	ServiceStatus
}

type SvcCtlHandleW WcharTPtr

// ============================================================================
// END: Data Types
// ============================================================================

// Opnum 0
//
//	[in, out] LPSC_RPC_HANDLE hSCObject
//
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/a2a4e174-09fb-4e55-bad3-f77c4b13245c
type RCloseServiceHandleRequest struct {
	HSCObject ScRpcHandle
}

type RCloseServiceHandleResponse struct {
	HSCObject ScRpcHandle
}

// Opnum 1
//
//	[in] SC_RPC_HANDLE hService,
//	[in] DWORD dwControl,
//	[out] LPSERVICE_STATUS lpServiceStatus
//
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/e1c478be-117f-4512-9b67-17c20a48af97
type RControlServiceRequest struct {
	HSCObject ScRpcHandle
	DWControl uint32
}

type RControlServiceResponse struct {
	Status LpServiceStatus
}

// Opnum 2
//
//	[in] SC_RPC_HANDLE hService
//
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/6744cdb8-f162-4be0-bb31-98996b6495be
type RDeleteServiceStruct struct {
	HSCObject ScRpcHandle
}

// Opnum 3
//
//	[in] SC_RPC_HANDLE hSCManager,
//	[out] LPSC_RPC_LOCK lpLock
//
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/ff71f732-e91d-4189-8fb9-a410674c63ad
type RLockServiceDatabaseStruct struct {
	HSCManager ScRpcHandle
}

// Opnum 4
//
//	[in] SC_RPC_HANDLE hService,
//	[in] SECURITY_INFORMATION dwSecurityInformation,
//	[out, size_is(cbBufSize)] LPBYTE lpSecurityDescriptor,
//	[in, range(0, 1024*256)] DWORD cbBufSize,
//	[out] LPBOUNDED_DWORD_256K pcbBytesNeeded
//
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/7f339950-ce73-4782-9e10-4e1c5924594e
type RQueryServiceObjectSecurityStruct struct {
	HService              ScRpcHandle
	DWSecurityInformation uint32
	LPSecurityDescriptor  LpSecurityDescriptor
	CBBufSize             uint32
}

// Opnum 5
//
//	[in] SC_RPC_HANDLE hService,
//	[in] SECURITY_INFORMATION dwSecurityInformation,
//	[in, size_is(cbBufSize)] LPBYTE lpSecurityDescriptor,
//	[in] DWORD cbBufSize
//
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/ea93548f-3917-4626-bef7-2f3f8fa39299
type RSetServiceObjectSecurityStruct struct {
	HService              ScRpcHandle
	DWSecurityInformation uint32
	LPSecurityDescriptor  LpSecurityDescriptor
	CBBufSize             uint32
}

// Opnum 6
//
//	[in] SC_RPC_HANDLE hService,
//	[out] LPSERVICE_STATUS lpServiceStatus
//
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/cf94d915-b4e1-40e5-872b-a9cb3ad09b46
type RQueryServiceStatusStruct struct {
	HService ScRpcHandle
}

// Opnum 7
//
//	[in] SC_RPC_HANDLE hServiceStatus,
//	[in] LPSERVICE_STATUS lpServiceStatus
//
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/df67cf3b-1bae-4359-b684-1b481d27a30c
type RSetServiceStatusStruct struct {
	HServiceStatus  ScRpcHandle
	LPServiceStatus LpServiceStatus
}

// Opnum 8
//
//	[in, out] LPSC_RPC_LOCK Lock
//
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/3456de79-5250-4982-8a30-debd2ea0df92
type RUnlockServiceDatabaseStruct struct {
	Lock LpScRpcHandle
}

// Opnum 9
//
//	[in, string, unique, range(0, SC_MAX_COMPUTER_NAME_LENGTH)] SVCCTL_HANDLEW lpMachineName,
//	[in] DWORD BootAcceptable
//
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/624e57ef-772d-45d2-ab99-03455879a424
type RNotifyBootConfigStatusStruct struct {
	LPMachineName  SvcCtlHandleW
	BootAcceptable uint32
}

// Opnum 11
//
//	[in] SC_RPC_HANDLE hService,
//	[in] DWORD dwServiceType,
//	[in] DWORD dwStartType,
//	[in] DWORD dwErrorControl,
//	[in, string, unique, range(0, SC_MAX_PATH_LENGTH)] wchar_t* lpBinaryPathName,
//	[in, string, unique, range(0, SC_MAX_NAME_LENGTH)] wchar_t* lpLoadOrderGroup,
//	[in, out, unique] LPDWORD lpdwTagId,
//	[in, unique, size_is(dwDependSize)] LPBYTE lpDependencies,
//	[in, range(0, SC_MAX_DEPEND_SIZE)] DWORD dwDependSize,
//	[in, string, unique, range(0, SC_MAX_ACCOUNT_NAME_LENGTH)] wchar_t* lpServiceStartName,
//	[in, unique, size_is(dwPwSize)] LPBYTE lpPassword,
//	[in, range(0, SC_MAX_PWD_SIZE)] DWORD dwPwSize,
//	[in, string, unique, range(0, SC_MAX_NAME_LENGTH)] wchar_t* lpDisplayName
//
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/61ea7ed0-c49d-4152-a164-b4830f16c8a4
type RChangeServiceConfigWStruct struct {
	HService           ScRpcHandle
	DWServiceType      uint32
	DWStartType        uint32
	DWErrorControl     uint32
	LPBinaryPathName   WcharTPtr
	LPLoadOrderGroup   WcharTPtr
	LPDWTagId          WcharTPtr
	LPDependencies     WcharTPtr
	DWDependSize       uint32
	LPServiceStartName WcharTPtr
	LPPassword         WcharTPtr
	DWPWSize           uint32
	LPDisplayName      WcharTPtr
}

// Opnum 12
//
//	[in] SC_RPC_HANDLE hSCManager,
//	[in, string, range(0, SC_MAX_NAME_LENGTH)] wchar_t* lpServiceName,
//	[in, string, unique, range(0, SC_MAX_NAME_LENGTH)] wchar_t* lpDisplayName,
//	[in] DWORD dwDesiredAccess,
//	[in] DWORD dwServiceType,
//	[in] DWORD dwStartType,
//	[in] DWORD dwErrorControl,
//	[in, string, range(0, SC_MAX_PATH_LENGTH)] wchar_t* lpBinaryPathName,
//	[in, string, unique, range(0, SC_MAX_NAME_LENGTH)] wchar_t* lpLoadOrderGroup,
//	[in, out, unique] LPDWORD lpdwTagId,
//	[in, unique, size_is(dwDependSize)] LPBYTE lpDependencies,
//	[in, range(0, SC_MAX_DEPEND_SIZE)] DWORD dwDependSize,
//	[in, string, unique, range(0, SC_MAX_ACCOUNT_NAME_LENGTH)] wchar_t* lpServiceStartName,
//	[in, unique, size_is(dwPwSize)] LPBYTE lpPassword,
//	[in, range(0, SC_MAX_PWD_SIZE)] DWORD dwPwSize,
//	[out] LPSC_RPC_HANDLE lpServiceHandle
//
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/6a8ca926-9477-4dd4-b766-692fab07227e
type RCreateServiceWStruct struct {
	HSCManager         ScRpcHandle
	LPServiceName      WcharTPtr
	LPDisplayName      WcharTPtr
	DWDesiredAccess    uint32
	DWServiceType      uint32
	DWStartType        uint32
	DWErrorControl     uint32
	LPBinaryPathName   WcharTPtr
	LPLoadOrderGroup   WcharTPtr
	LPDWTagId          WcharTPtr
	LPDependencies     WcharTPtr
	DWDependSize       uint32
	LPServiceStartName WcharTPtr
	LPPassword         WcharTPtr
	DWPWSize           uint32
}

// Opnum 13
//
//	[in] SC_RPC_HANDLE hService,
//	[in] DWORD dwServiceState,
//	[out, size_is(cbBufSize)] LPBYTE lpServices,
//	[in, range(0, 1024*256)] DWORD cbBufSize,
//	[out] LPBOUNDED_DWORD_256K pcbBytesNeeded,
//	[out] LPBOUNDED_DWORD_256K lpServicesReturned
//
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/6269bea8-9dd3-4092-bd33-67cec685d38e
type REnumDependentServicesWStruct struct {
	HService       ScRpcHandle
	DWServiceState uint32
}

// Opnum 14
type REnumServicesStatusWStruct struct{}

// Opnum 15
//
//	[in, string, unique, range(0, SC_MAX_COMPUTER_NAME_LENGTH)]
//	SVCCTL_HANDLEW lpMachineName,
//	[in, string, unique, range(0, SC_MAX_NAME_LENGTH)]
//	wchar_t* lpDatabaseName,
//	[in] DWORD dwDesiredAccess,
//	[out] LPSC_RPC_HANDLE lpScHandle
//
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/dc84adb3-d51d-48eb-820d-ba1c6ca5faf2
type ROpenSCManagerWRequest struct {
	LpMachineName   SvcCtlHandleW
	LpDatabaseName  SvcCtlHandleW
	DwDesiredAccess uint32
}

type ROpenSCManagerWResponse struct {
}

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

// Opnum 31
type RStartServiceAStruct struct{}

// Opnum 32
type RGetServiceDisplayNameAStruct struct{}

// Opnum 33
type RGetServiceKeyNameAStruct struct{}

// Opnum 35
type REnumServiceGroupWStruct struct{}

// Opnum 36
type RChangeServiceConfig2AStruct struct{}

// Opnum 37
type RChangeServiceConfig2WStruct struct{}

// Opnum 38
type RQueryServiceConfig2AStruct struct{}

// Opnum 39
type RQueryServiceConfig2WStruct struct{}

// Opnum 40
type RQueryServiceStatusExStruct struct{}

// Opnum 41
type REnumServicesStatusExAStruct struct{}

// Opnum 42
type REnumServicesStatusExWStruct struct{}

// Opnum 44
type RCreateServiceWOW64AStruct struct{}

// Opnum 45
type RCreateServiceWOW64WStruct struct{}

// Opnum 47
type RNotifyServiceStatusChangeStruct struct{}

// Opnum 48
type RGetNotifyResultsStruct struct{}

// Opnum 49
type RCloseNotifyHandleStruct struct{}

// Opnum 50
type RControlServiceExAStruct struct{}

// Opnum 51
type RControlServiceExWStruct struct{}

// Opnum 56
type RQueryServiceConfigExStruct struct{}

// Opnum 60
type RCreateWowServiceStruct struct{}

// Opnum 64
type ROpenSCManager2Struct struct{}

// ########################################################################################################

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/dc84adb3-d51d-48eb-820d-ba1c6ca5faf2
type OpenSCManagerRequest struct {
	MachineName  PointerHeader
	DatabaseName PointerHeader
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
	DisplayName         PointerHeader
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
