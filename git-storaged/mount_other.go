//go:build !linux

package main

// Kubernetes storage nodes run Linux. Other local development hosts retain the deployment root
// check in NewServer; their CSI-specific filesystem validation belongs to that platform adapter.
type systemMount struct{}

func (systemMount) Check(string) error { return nil }
