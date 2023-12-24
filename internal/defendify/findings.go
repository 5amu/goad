package defendify

type ADObject struct {
	DN                         string
	SAMAccountName             string
	OperatingSystem            string
	OperatingSystemVersion     string
	OperatingSystemServicePack string
	MemberOf                   []string
}

type Finding struct {
	ID          FindingID
	Name        string
	Description string
	Remediation string
	Objects     []*ADObject
	References  []string
}

type FindingID int

const (
	DCNotUpdated            FindingID = 1
	DCNotUpdatedName        string    = "Obsolete Domain Controller OS Version"
	DCNotUpdatedDescription string    = "aaaaaaaaa"
	DCNotUpdatedRemediation string    = "aaaaaaaaa"
)

var (
	DCNotUpdatedReferences []string = []string{"a"}
)

func InitFinding(id FindingID) *Finding {
	switch id {
	case DCNotUpdated:
		return &Finding{
			ID:          id,
			Name:        DCNotUpdatedName,
			Description: DCNotUpdatedDescription,
			Remediation: DCNotUpdatedRemediation,
			References:  DCNotUpdatedReferences,
		}
	}
	return nil
}
