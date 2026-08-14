package clouddriver

// Setting keys the GKE driver requires. Named here so the refusal message and the chart's
// values schema agree on one vocabulary.
const (
	// SettingGKEWorkloadIdentitySA is the Workload Identity service account the plane's
	// keyless identity binds to (ADR-0010). GKE cannot default it — it is a tenant decision.
	SettingGKEWorkloadIdentitySA = "gke.workloadIdentityServiceAccount"
)

// gkeDriver carries what differs on GKE.
type gkeDriver struct{}

func init() { Register(gkeDriver{}) }

func (gkeDriver) Provider() Provider         { return ProviderGKE }
func (gkeDriver) RequiredSettings() []string { return []string{SettingGKEWorkloadIdentitySA} }
func (gkeDriver) StorageClass() string       { return "standard-rwo" }
func (gkeDriver) IdentityMode() string       { return "workload-identity" }
func (gkeDriver) IngressClass() string       { return "gce" }
func (gkeDriver) LoadBalancerClass() string  { return "" }
func (gkeDriver) Capabilities() []string {
	return []string{"object-storage:gcs", "identity:workload-identity", "ingress:gateway-api"}
}
