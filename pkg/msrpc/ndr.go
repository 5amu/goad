package msrpc

// x32: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/b6090c2b-f44a-47a1-a13b-b82ade0137b2
var MSRPC_NDR32 MSRPCUUID = MSRPCUUID{
	UUID:    "8a885d04-1ceb-11c9-9fe8-08002b104860",
	Version: 2,
}

// x64: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/dca648a5-42d3-432c-9927-2f22e50fa266
var MSRPC_NDR64 MSRPCUUID = MSRPCUUID{
	UUID:    "71710533-beba-4937-8319-b5dbef9ccc36",
	Version: 1,
}
