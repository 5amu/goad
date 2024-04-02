package dcerpc

import "fmt"

func AlignBytes(data []byte, x64 bool) []byte {
	if x64 {
		return append(data, make([]byte, len(data)%8)...)
	}
	return append(data, make([]byte, len(data)%4)...)
}

func AlignBytes32(data []byte) []byte {
	return AlignBytes(data, false)
}

func AlignBytes64(data []byte) []byte {
	return AlignBytes(data, true)
}

func RpcErrFmt(ret uint32) error {
	switch ret {
	case ERROR_SUCCESS:
		return nil
	case ERROR_ACCESS_DENIED:
		return fmt.Errorf("error code %d: ERROR_ACCESS_DENIED", ret)
	case ERROR_INVALID_HANDLE:
		return fmt.Errorf("error code %d: ERROR_INVALID_HANDLE", ret)
	case ERROR_INVALID_DATA:
		return fmt.Errorf("error code %d: ERROR_INVALID_DATA", ret)
	case ERROR_INVALID_PARAMETER:
		return fmt.Errorf("error code %d: ERROR_INVALID_PARAMETER", ret)
	case ERROR_SERVICE_DATABASE_LOCKED:
		return fmt.Errorf("error code %d: ERROR_SERVICE_DATABASE_LOCKED", ret)
	case ERROR_INVALID_SERVICE_ACCOUNT:
		return fmt.Errorf("error code %d: ERROR_INVALID_SERVICE_ACCOUNT", ret)
	case ERROR_CIRCULAR_DEPENDENCY:
		return fmt.Errorf("error code %d: ERROR_CIRCULAR_DEPENDENCY", ret)
	case ERROR_INVALID_SERVICE_LOCK:
		return fmt.Errorf("error code %d: ERROR_INVALID_SERVICE_LOCK", ret)
	case ERROR_SERVICE_MARKED_FOR_DELETE:
		return fmt.Errorf("error code %d: ERROR_SERVICE_MARKED_FOR_DELETE", ret)
	case ERROR_DUPLICATE_SERVICE_NAME:
		return fmt.Errorf("error code %d: ERROR_DUPLICATE_SERVICE_NAME", ret)
	case ERROR_SHUTDOWN_IN_PROGRESS:
		return fmt.Errorf("error code %d: ERROR_SHUTDOWN_IN_PROGRESS", ret)
	default:
		return fmt.Errorf("unknown return code %d", ret)
	}
}
