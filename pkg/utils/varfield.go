package utils

type VarField struct {
	Len          uint16
	MaxLen       uint16
	BufferOffset uint32
}

func NewVarField(ptr *int, fieldsize int) VarField {
	f := VarField{
		Len:          uint16(fieldsize),
		MaxLen:       uint16(fieldsize),
		BufferOffset: uint32(*ptr),
	}
	*ptr += fieldsize
	return f
}
