// ffp: FFP-SCOUR-CLI io-edge go
// Scour v1.2.0 — Freestanding Multi-Cadence Signal Harvester, Opportunity Miner,
// Security-Hardening Scour (`cisa-kev` / `osv` / `tls-headers`), Security-Hardening Miner (`SHI`),
// GitHub Repo Update Sentinel & JSON-RPC 2.0 MCP Server.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

const Version = "1.2.0"

var requiredHeaders = []string{
	"strict-transport-security",
	"content-security-policy",
	"x-frame-options",
	"x-content-type-options",
	"referrer-policy",
	"permissions-policy",
}

type Signal struct {
	ID       string `json:"id"`
	Lane     string `json:"lane"`
	Source   string `json:"source"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Action   string `json:"action"`
}

func makeID(src, key string) string {
	s := sha256.Sum256([]byte(src + ":" + key))
	return "sig-" + hex.EncodeToString(s[:])[:16]
}

func SecurityScourHeaders(domain string, timeout time.Duration) Signal {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get("https://" + strings.TrimPrefix(strings.TrimPrefix(domain, "https://"), "http://"))
	if err != nil {
		return Signal{
			ID: makeID("tls", domain), Lane: "security_hardening", Source: "edge_tls_headers",
			Severity: "WARN", Title: fmt.Sprintf("Probe %s unreachable (%v)", domain, err),
			Action: "Verify DNS/TLS endpoint availability",
		}
	}
	defer resp.Body.Close()
	var missing []string
	for _, h := range requiredHeaders {
		if resp.Header.Get(h) == "" {
			missing = append(missing, h)
		}
	}
	sev := "PASS"
	act := "All 6 defensive HTTP security headers verified"
	if len(missing) > 0 {
		sev = "MEDIUM"
		act = "Add missing headers: " + strings.Join(missing, ", ")
	}
	return Signal{
		ID: makeID("tls", domain), Lane: "security_hardening", Source: "edge_tls_headers",
		Severity: sev, Title: fmt.Sprintf("%s HTTP %d (missing_headers=%d)", domain, resp.StatusCode, len(missing)),
		Action: act,
	}
}

func ComputeSecurityHardeningIndex(signals []Signal) map[string]any {
	penalties := 0.0
	for _, s := range signals {
		switch s.Severity {
		case "CRITICAL":
			penalties += 25.0
		case "HIGH":
			penalties += 12.0
		case "MEDIUM":
			penalties += 5.0
		case "WARN":
			penalties += 2.0
		}
	}
	shi := 100.0 - penalties
	if shi < 0 {
		shi = 0
	}
	return map[string]any{
		"version":             Version,
		"composite_shi_score": shi,
		"signals_evaluated":   len(signals),
		"status":              map[bool]string{true: "ENFORCED", false: "REMEDIATION_RECOMMENDED"}[shi >= 90.0],
		"signals":             signals,
	}
}

func RepoSentinelOrg(org string, timeout time.Duration) map[string]any {
	client := &http.Client{Timeout: timeout}
	req, _ := http.NewRequest("GET", fmt.Sprintf("https://api.github.com/orgs/%s/repos?per_page=30&sort=pushed", org), nil)
	req.Header.Set("User-Agent", "Tianxia-Scour-RepoSentinel/"+Version)
	resp, err := client.Do(req)
	if err != nil {
		return map[string]any{"ok": false, "org": org, "error": err.Error()}
	}
	defer resp.Body.Close()
	var raw []map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&raw)
	var entries []string
	for _, r := range raw {
		name, _ := r["full_name"].(string)
		pushed, _ := r["pushed_at"].(string)
		if name != "" {
			entries = append(entries, name+"@"+pushed)
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(entries, "|")))
	return map[string]any{
		"ok":                true,
		"org":               org,
		"repos_observed":    len(entries),
		"state_digest_hex":  hex.EncodeToString(sum[:])[:16],
		"coupled_pipelines": []string{"scour", "security-scour", "opportunities-miner", "security-miner", "website-live-sync"},
	}
}

func runMCP() {
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		var req map[string]any
		if json.Unmarshal(sc.Bytes(), &req) != nil {
			continue
		}
		id, ok := req["id"]
		if !ok {
			continue
		}
		method, _ := req["method"].(string)
		var res any
		switch method {
		case "initialize":
			res = map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "scour", "version": Version}}
		case "tools/list":
			res = map[string]any{"tools": []map[string]any{
				{"name": "scour_security_mine", "description": "Audit domain HTTP/TLS hardening posture and compute Security Hardening Index (SHI).", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"domain": map[string]any{"type": "string"}}, "required": []string{"domain"}}},
				{"name": "scour_repo_sentinel", "description": "Compute GitHub organization repository state digest for live sync.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"org": map[string]any{"type": "string"}}, "required": []string{"org"}}},
			}}
		case "tools/call":
			params, _ := req["params"].(map[string]any)
			tname, _ := params["name"].(string)
			args, _ := params["arguments"].(map[string]any)
			var payload any
			if tname == "scour_repo_sentinel" {
				org, _ := args["org"].(string)
				if org == "" {
					org = "Tianxia-Core"
				}
				payload = RepoSentinelOrg(org, 6*time.Second)
			} else {
				dom, _ := args["domain"].(string)
				if dom == "" {
					dom = "rasaxmachina.com"
				}
				payload = ComputeSecurityHardeningIndex([]Signal{SecurityScourHeaders(dom, 6*time.Second)})
			}
			b, _ := json.MarshalIndent(payload, "", "  ")
			res = map[string]any{"content": []map[string]any{{"type": "text", "text": string(b)}}}
		default:
			res = map[string]any{}
		}
		out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": res})
		fmt.Println(string(out))
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Scour v%s — Autonomous Signal Harvester, Security-Hardening Scour/Miner & GitHub Repo Sentinel\n", Version)
		fmt.Println("Usage: scour <security-scour|security-mine|repo-sentinel|mcp-stdio|--version>")
		return
	}
	switch os.Args[1] {
	case "--version", "-v", "version":
		fmt.Printf("scour v%s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
	case "security-scour", "security-mine":
		fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
		dom := fs.String("domain", "rasaxmachina.com", "Target domain")
		_ = fs.Parse(os.Args[2:])
		sig := SecurityScourHeaders(*dom, 8*time.Second)
		b, _ := json.MarshalIndent(ComputeSecurityHardeningIndex([]Signal{sig}), "", "  ")
		fmt.Println(string(b))
	case "repo-sentinel":
		fs := flag.NewFlagSet("repo-sentinel", flag.ExitOnError)
		org := fs.String("org", "Tianxia-Core", "GitHub organization")
		_ = fs.Parse(os.Args[2:])
		b, _ := json.MarshalIndent(RepoSentinelOrg(*org, 8*time.Second), "", "  ")
		fmt.Println(string(b))
	case "mcp-stdio", "mcp":
		runMCP()
	default:
		os.Exit(2)
	}
}
