package mstypes

type MSDSManagedPasswordBlob struct {
	Version                         uint16
	Reserved                        uint16
	Lenght                          uint32
	CurrentPasswordOffset           uint16
	PreviousPasswordOffset          uint16
	QueryPasswordIntervalOffset     uint16
	UnchangedPasswordIntervalOffset uint16
	CurrentPassword                 []byte `delimiter:"16bitnull"`
	PreviousPassword                []byte `delimiter:"16bitnull"`
	AlignmentPadding                []byte `padding:"null"`
	QueryPasswordInterval           uint64
	UnchangedPasswordInterval       uint64
}
