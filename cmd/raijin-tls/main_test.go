package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = "../../testdata/sample.jsonl"

func scopeFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(p, []byte("*.example.com\n10.0.0.0/8\n2001:db8::/32\n!10.0.0.200\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type output struct {
	Summary  string
	Findings []struct {
		ID        string
		Locations []string
	}
	Groups []struct {
		ID        string
		Locations []string
	}
	Omitted map[string]int
	Errors  []struct{ Kind, Hint string }
	Raw     string
}

func TestNoBannerByDefault(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "--input", sample}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if errb.Len() != 0 {
		t.Errorf("stderr should be empty without --banner, got %q", errb.String())
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
}

func TestBannerGoesToStderrOnly(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--banner", "--scope", scopeFile(t), "--input", sample}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "TGT-LOCK") || !strings.Contains(errb.String(), "raijin-tls v"+version) {
		t.Errorf("banner missing or without the version: %q", errb.String())
	}
	if strings.Contains(out.String(), "TGT-LOCK") {
		t.Error("banner leaked into stdout")
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON with --banner: %v", err)
	}
}

func TestCompactByDefault(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", sample}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if n := strings.Count(out.String(), "\n"); n != 1 {
		t.Errorf("default JSON should be one line, got %d lines", n)
	}
	var pretty bytes.Buffer
	if code := run([]string{"--pretty", "--scope", scopeFile(t), "--input", sample}, &pretty, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(pretty.String(), "\n  \"tool\"") {
		t.Errorf("--pretty should indent: %q", pretty.String())
	}
	var a, b map[string]any
	if json.Unmarshal(out.Bytes(), &a) != nil || json.Unmarshal(pretty.Bytes(), &b) != nil || len(a) != len(b) {
		t.Error("compact and pretty should carry the same fields")
	}
	want := `"summary":"10 endpoints, 6 certificates, 12 findings (4 high, 5 medium, 2 low, 1 info), 10 groups, 1 no TLS"`
	if !strings.Contains(out.String(), want) {
		t.Errorf("summary: %s", out.String())
	}
	if !strings.Contains(out.String(), `"omitted":{"duplicates":1,"out_of_scope":1}`) {
		t.Errorf("omitted: %s", out.String())
	}
}

func TestTableFormat(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--format", "table", "--scope", scopeFile(t), "--input", sample}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"HIGH     Expired certificate (1)", "old.example.com:443 [expired 2025-06-01]", "group    cert CN=www.example.com, O=Example until 2027-01-01 (3 endpoints)", "group    failed: port closed or filtered (1 endpoint)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("table should contain %q:\n%s", want, out.String())
		}
	}
}

// fakeTLSX writes a shell script that answers like tlsx -json: one result per target in the list it is
// given. It logs its arguments and the targets, and fails if it is asked to scan an excluded address.
func fakeTLSX(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "args.log")
	body := `#!/bin/sh
echo "$@" > "` + log + `"
while [ "$1" != "-l" ]; do shift; done
cat "$2" >> "` + log + `"
while read -r h; do
  case "$h" in
    10.0.0.200) echo "excluded address sent to tlsx" >&2; exit 1 ;;
    down.example.com) echo "{\"host\":\"$h\",\"port\":\"443\",\"probe_status\":false,\"error\":\"cause=\\\"port closed or filtered\\\" address=$h:443\"}" ;;
    *) echo "{\"timestamp\":\"2026-10-24T12:00:00Z\",\"host\":\"$h\",\"ip\":\"10.0.0.9\",\"port\":\"443\",\"probe_status\":true,\"tls_version\":\"tls12\",\"cipher\":\"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\",\"version_enum\":[\"tls10\",\"tls12\"],\"subject_dn\":\"CN=$h\",\"subject_cn\":\"$h\",\"subject_an\":[\"$h\"],\"not_after\":\"2027-01-01T00:00:00Z\",\"fingerprint_hash\":{\"sha256\":\"0123456789abcdef\"}}" ;;
  esac
done < "$2"
`
	bin := filepath.Join(dir, "tlsx")
	if err := os.WriteFile(bin, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin, log
}

func TestLiveRunWithFakeEngine(t *testing.T) {
	bin, log := fakeTLSX(t)
	raw := filepath.Join(t.TempDir(), "raw.jsonl")
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "--tlsx", bin, "--raw", raw, "-u", "a.example.com,down.example.com", "-u", "10.0.0.200", "-u", "evil.test", "-p", "443,8443"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, errb.String(), out.String())
	}
	args, _ := os.ReadFile(log)
	for _, want := range []string{"-json", "-ex -ss -mm -wc -tps", "-ve -ce", "-p 443,8443", "a.example.com", "down.example.com"} {
		if !strings.Contains(string(args), want) {
			t.Errorf("tlsx should get %q: %s", want, args)
		}
	}
	if strings.Contains(string(args), "evil.test") || strings.Contains(string(args), "10.0.0.200") {
		t.Errorf("out-of-scope targets reached tlsx: %s", args)
	}
	var o output
	if err := json.Unmarshal(out.Bytes(), &o); err != nil {
		t.Fatal(err)
	}
	if o.Raw != raw || o.Omitted["out_of_scope"] != 2 {
		t.Errorf("raw %q, omitted %v", o.Raw, o.Omitted)
	}
	if b, _ := os.ReadFile(raw); strings.Count(string(b), "\n") != 2 {
		t.Errorf("raw should hold tlsx's two lines: %q", b)
	}
	if len(o.Findings) != 1 || o.Findings[0].ID != "old-tls" || o.Findings[0].Locations[0] != "a.example.com:443 [tls10]" {
		t.Errorf("findings: %s", out.String())
	}
}

func TestNoEnumSkipsEnumeration(t *testing.T) {
	bin, log := fakeTLSX(t)
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--tlsx", bin, "--raw", filepath.Join(t.TempDir(), "raw"), "-u", "a.example.com", "--no-enum", "--", "-re"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	args, _ := os.ReadFile(log)
	if strings.Contains(string(args), "-ve") || strings.Contains(string(args), "-ce") || !strings.Contains(string(args), "-re") {
		t.Errorf("--no-enum should drop -ve -ce, and -- should pass -re: %s", args)
	}
}

func TestMissingEngineExitsTwoWithHint(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "-u", "a.example.com", "--tlsx", "/nonexistent/tlsx"}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	var o output
	if err := json.Unmarshal(out.Bytes(), &o); err != nil || len(o.Errors) != 1 || o.Errors[0].Kind != "missing_engine" || !strings.Contains(o.Errors[0].Hint, "--tlsx") {
		t.Errorf("stdout = %s", out.String())
	}
	if o.Raw != "" {
		t.Errorf("no raw file when nothing ran: %q", o.Raw)
	}
}

func TestUsageErrorsExitOne(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--input", sample}, &out, &errb); code != 1 {
		t.Errorf("no --scope: exit %d, want 1", code)
	}
	if code := run([]string{"--scope", scopeFile(t), "-u", "out.of-scope.net"}, &out, &errb); code != 1 {
		t.Errorf("no target in scope: exit %d, want 1", code)
	}
	if code := run([]string{"--scope", scopeFile(t), "--bogus"}, &out, &errb); code != 1 {
		t.Errorf("unknown flag: exit %d, want 1", code)
	}
}

func TestBudgetCutsAreCountedAndPointToRaw(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", sample, "--max-bytes", "1500"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if out.Len() > 1501 {
		t.Errorf("output is %d bytes, over --max-bytes", out.Len())
	}
	s := out.String()
	if !strings.Contains(s, `"truncated":true`) || !strings.Contains(s, "read "+sample+" for what was cut") {
		t.Errorf("a cut must set budget.truncated and point to the input: %s", s)
	}
	var o output
	json.Unmarshal(out.Bytes(), &o)
	if o.Omitted["groups"]+o.Omitted["locations"]+o.Omitted["findings"] == 0 {
		t.Errorf("cuts must be counted: %v", o.Omitted)
	}
}
