package clouddriver

// Setting keys the AKS driver requires.
const (
	// SettingAKSEntraClientID is the Microsoft Entra application client ID the plane's
	// workload identity federates against (ADR-0010). AKS cannot default it — it is a tenant
	// decision.
	SettingAKSEntraClientID = "aks.entraClientId"
)

// aksDriver carries what differs on AKS.
type aksDriver struct{}

func init() { Register(aksDriver{}) }

func (aksDriver) Provider() Provider         { return ProviderAKS }
func (aksDriver) RequiredSettings() []string { return []string{SettingAKSEntraClientID} }
func (aksDriver) StorageClass() string       { return "managed-csi" }
func (aksDriver) IdentityMode() string       { return "entra-workload-identity" }
func (aksDriver) IngressClass() string       { return "nginx" }
func (aksDriver) LoadBalancerClass() string  { return "" }
func (aksDriver) Capabilities() []string {
	return []string{"object-storage:blob", "identity:entra-workload-identity", "ingress:nginx"}
}
