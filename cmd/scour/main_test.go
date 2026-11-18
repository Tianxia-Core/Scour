// ffp: FFP-SCOUR-TEST io-edge go
package main

import "testing"

func TestComputeSecurityHardeningIndex(t *testing.T) {
	out := ComputeSecurityHardeningIndex([]Signal{
		{ID: "sig-1", Lane: "security_hardening", Source: "edge_tls_headers", Severity: "PASS", Title: "OK"},
	})
	if score, _ := out["composite_shi_score"].(float64); score != 100.0 {
		t.Fatalf("expected 100.0 SHI score, got %v", score)
	}
}
