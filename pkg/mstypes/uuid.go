package mstypes

const (
	SRVSVC_UUID                 = "4b324fc8-1670-01d3-1278-5a47bf6ee188"
	SRVSVC_VERSION              = 2
	NTSVCS_UUID                 = "367abb81-9844-35f1-ad32-98f038001003"
	NTSVCS_VERSION              = 2
	IID_IObjectExporter         = "99fcfec4-5260-101b-bbcb-00aa0021347a"
	IID_IObjectExporter_VERSION = 0
	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/b6090c2b-f44a-47a1-a13b-b82ade0137b2
	NDR_UUID                         = "8a885d04-1ceb-11c9-9fe8-08002b104860"
	NDR_VERSION                      = 2
	Time_Feature_Negotiation_UUID    = "6cb71c2c-9812-4540-0300-000000000000"
	Time_Feature_Negotiation_VERSION = 1
	// epmapper
	EPMv4_UUID    = "e1af8308-5d1f-11c9-91a4-08002b14a0fa"
	EPMv4_VERSION = 3
)

var UUIDMap = map[string]string{
	SRVSVC_UUID:         "\\PIPE\\srvsvc",
	NTSVCS_UUID:         "\\PIPE\\ntsvcs",
	IID_IObjectExporter: "IID_IObjectExporter",
}
