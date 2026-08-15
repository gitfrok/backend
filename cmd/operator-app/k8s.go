package main

import (
	"context"
	"fmt"
	"os"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// dataPlaneGVR is the DataPlane CR the chart installs: byo.gitfrok.dev/v1alpha1
// dataplanes. The operator reads spec.version and writes the rollout report on
// the status subresource — the exact fields the CRD schema names.
var dataPlaneGVR = schema.GroupVersionResource{
	Group: "byo.gitfrok.dev", Version: "v1alpha1", Resource: "dataplanes",
}

// kubePlane is the real-cluster half of the operator: one namespace-scoped
// pair of clients speaking to the cluster's own API server. It opens no
// listener — the outbound-only shape holds (ADR-0011).
type kubePlane struct {
	apps      kubernetes.Interface
	dyn       dynamic.Interface
	namespace string
	workload  string
	container string
	crName    string
}

// newKubePlane builds the clients: in-cluster credentials first (the operator
// runs inside the data plane's cluster), KUBECONFIG as the dev fallback.
func newKubePlane(ctx context.Context, namespace, workload, container, crName string) (*kubePlane, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		if kc := os.Getenv("KUBECONFIG"); kc != "" {
			cfg, err = clientcmd.BuildConfigFromFlags("", kc)
		}
		if err != nil {
			return nil, fmt.Errorf("neither in-cluster credentials nor KUBECONFIG are usable: %w", err)
		}
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	p := &kubePlane{apps: cs, dyn: dyn, namespace: namespace, workload: workload, container: container, crName: crName}
	// Fail fast at startup on a CR that cannot be read: a reconciler with no
	// desired-state source has nothing to converge.
	if _, err := p.DesiredVersion(ctx); err != nil {
		return nil, fmt.Errorf("DataPlane CR %s/%s unreadable at startup: %w", namespace, crName, err)
	}
	return p, nil
}

// DesiredVersion reads spec.version from the DataPlane CR — the desired
// release the control plane published over the agent channel.
func (p *kubePlane) DesiredVersion(ctx context.Context) (string, error) {
	obj, err := p.dyn.Resource(dataPlaneGVR).Namespace(p.namespace).Get(ctx, p.crName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	version, found, err := unstructured.NestedString(obj.Object, "spec", "version")
	if err != nil || !found || version == "" {
		return "", fmt.Errorf("spec.version is absent — the reconcile loop has no desired-state driver")
	}
	return version, nil
}

// CurrentWorkloadImage is the image the data-plane workload runs right now.
func (p *kubePlane) CurrentWorkloadImage(ctx context.Context) (string, bool, error) {
	dep, err := p.apps.AppsV1().Deployments(p.namespace).Get(ctx, p.workload, metav1.GetOptions{})
	if err != nil {
		return "", false, nil // not created yet: the reconciler treats absence as "apply"
	}
	for _, c := range dep.Spec.Template.Spec.Containers {
		if c.Name == p.container {
			return c.Image, true, nil
		}
	}
	return "", false, fmt.Errorf("workload %s has no container %q", p.workload, p.container)
}

// ApplyWorkloadImage converges the workload's container onto the digest pin.
// The update is idempotent: the API server no-ops an unchanged spec.
func (p *kubePlane) ApplyWorkloadImage(ctx context.Context, digestPinnedImage string) error {
	dep, err := p.apps.AppsV1().Deployments(p.namespace).Get(ctx, p.workload, metav1.GetOptions{})
	if err != nil {
		return err
	}
	found := false
	for i := range dep.Spec.Template.Spec.Containers {
		if dep.Spec.Template.Spec.Containers[i].Name == p.container {
			dep.Spec.Template.Spec.Containers[i].Image = digestPinnedImage
			found = true
		}
	}
	if !found {
		return fmt.Errorf("workload %s has no container %q", p.workload, p.container)
	}
	_, err = p.apps.AppsV1().Deployments(p.namespace).Update(ctx, dep, metav1.UpdateOptions{})
	return err
}

// WriteStatus puts the rollout report on the CR's status subresource:
// observedVersion, phase, message, lastHeartbeatTime — the schema's exact
// fields, and nothing else (no credential material may ride a CR, AC2).
func (p *kubePlane) WriteStatus(ctx context.Context, rep StatusReport) error {
	obj, err := p.dyn.Resource(dataPlaneGVR).Namespace(p.namespace).Get(ctx, p.crName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	status := map[string]any{
		"observedVersion":   rep.ObservedVersion,
		"phase":             rep.Phase,
		"message":           rep.Message,
		"lastHeartbeatTime": rep.LastHeartbeatTime.UTC().Format(time.RFC3339),
	}
	if err := unstructured.SetNestedMap(obj.Object, status, "status"); err != nil {
		return err
	}
	_, err = p.dyn.Resource(dataPlaneGVR).Namespace(p.namespace).UpdateStatus(ctx, obj, metav1.UpdateOptions{})
	return err
}
