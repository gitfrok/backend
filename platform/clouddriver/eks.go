package clouddriver

// Setting keys the EKS driver requires.
const (
	// SettingEKSIRSARoleArn is the IAM Roles for Service Accounts role the plane's keyless
	// identity assumes (ADR-0010). EKS cannot default it — it is a tenant decision.
	SettingEKSIRSARoleArn = "eks.irsaRoleArn"
)

// eksDriver carries what differs on EKS.
type eksDriver struct{}

func init() { Register(eksDriver{}) }

func (eksDriver) Provider() Provider         { return ProviderEKS }
func (eksDriver) RequiredSettings() []string { return []string{SettingEKSIRSARoleArn} }
func (eksDriver) StorageClass() string       { return "gp3" }
func (eksDriver) IdentityMode() string       { return "irsa" }
func (eksDriver) IngressClass() string       { return "nginx" }
func (eksDriver) LoadBalancerClass() string  { return "service.k8s.aws/nlb" }
func (eksDriver) Capabilities() []string {
	return []string{"object-storage:s3", "identity:irsa", "ingress:nginx"}
}
