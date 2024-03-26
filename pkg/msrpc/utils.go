package msrpc

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
