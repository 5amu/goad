package defendify

// Critical AD Groups
const (
	DomainAdminsGroup     = "Domain Admins"
	EnterpriseAdminsGroup = "Enterprise Admins"
	SchemaAdminsGroup     = "Schema Admins"
	AdministratorsGroup   = "Administrators"
	AccounOperatorsGroup  = "Account Operators"
	ServerOperatorsGroup  = "Server Operators"
	BackupOperatorsGroup  = "Backup Operators"
	PrintOperatorsGroup   = "Print Operators"
)

var CriticalADGroups = []string{
	DomainAdminsGroup,
	EnterpriseAdminsGroup,
	SchemaAdminsGroup,
	AdministratorsGroup,
	AccounOperatorsGroup,
	ServerOperatorsGroup,
	BackupOperatorsGroup,
	PrintOperatorsGroup,
}
