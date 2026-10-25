// Package schema defines the Raijin Schema, the JSON shape every Raijin tool returns.
//
// Nothing the engine found is dropped silently: every host:port tlsx reported is listed in a group, with
// its certificate, protocol versions and ciphers, every issue tlsx flagged on it is a finding, and
// anything a budget cuts is counted in Omitted. What an agent can rebuild is left out of the JSON to
// save tokens: empty lists, the budget when nothing was cut, a count equal to the locations listed, and
// fields at their documented default.
//
// raijin-tls adds the TLS profile to groups: the negotiated version and cipher, every version and
// cipher the server accepts, and the certificate.
package schema

import (
	"bytes"
	"encoding/json"
)

// Marshal is json.Marshal without HTML escaping: "->" stays "->" instead of "->", which costs
// tokens and nothing else.
func Marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// Result is the top-level object a Raijin tool writes to stdout.
type Result struct {
	Tool     string         `json:"tool"`
	Version  string         `json:"version"`
	Target   string         `json:"target"`
	Summary  string         `json:"summary"`
	Findings []Finding      `json:"findings"`
	Groups   []Group        `json:"groups"`
	Omitted  map[string]int `json:"omitted,omitempty"`
	Errors   []Error        `json:"errors,omitempty"`
	Next     []string       `json:"next,omitempty"`
	// Raw is the file with the engine's full output, for details the result leaves out.
	Raw    string `json:"raw,omitempty"`
	Budget Budget `json:"budget"`
}

// MarshalJSON writes the budget only when something was cut.
func (r Result) MarshalJSON() ([]byte, error) {
	type plain Result
	out := struct {
		plain
		Budget *Budget `json:"budget,omitempty"`
	}{plain: plain(r)}
	if r.Budget.Truncated {
		out.Budget = &r.Budget
	}
	return Marshal(out)
}

// Finding is one TLS issue (an expired certificate, TLS 1.0 enabled, a weak cipher...) with every
// host:port that has it. The ID is the issue, so the same tool and ID in two runs is the same finding.
type Finding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	// Confidence is "verified" or "heuristic"; empty means "matched".
	Confidence string `json:"confidence,omitempty"`
	// Locations are every host:port with the issue, each with what was found there in brackets:
	// "localhost:8443 [tls10, tls11]", "app.example.com:443 [expired 2025-01-01]".
	Locations []string `json:"locations"`
	// Count is the number of locations; it is written only when the budget cut Locations.
	Count int `json:"count,omitempty"`
	// Fingerprint is the internal key for --state; it is derived from the ID and not written.
	Fingerprint string `json:"-"`
	New         bool   `json:"new,omitempty"`
}

// MarshalJSON leaves out count when every location is listed.
func (f Finding) MarshalJSON() ([]byte, error) {
	type plain Finding
	p := plain(f)
	if p.Count <= len(p.Locations) {
		p.Count = 0
	}
	return Marshal(p)
}

// Cert is a server certificate. Only the strongest fingerprint tlsx wrote is kept (SHA-256 when it has
// one), and SAN is left out when it is just the subject CN.
type Cert struct {
	SHA256    string   `json:"sha256,omitempty"`
	SHA1      string   `json:"sha1,omitempty"`
	MD5       string   `json:"md5,omitempty"`
	Subject   string   `json:"subject,omitempty"`
	SAN       []string `json:"san,omitempty"`
	Issuer    string   `json:"issuer,omitempty"`
	NotBefore string   `json:"not_before,omitempty"`
	NotAfter  string   `json:"not_after,omitempty"`
}

// Group is one TLS profile, with every host:port that serves it: the same certificate, the same
// negotiated version and cipher, and the same accepted versions and ciphers. 40 ports behind one load
// balancer are one group. A target that did not answer TLS is a group with Error.
type Group struct {
	ID string `json:"id"`
	// Version and Cipher are what tlsx negotiated ("tls13", "TLS_AES_256_GCM_SHA384").
	Version string `json:"version,omitempty"`
	Cipher  string `json:"cipher,omitempty"`
	// Versions are every protocol version the server accepts, oldest first. Left out when tlsx did not
	// enumerate them (--no-enum).
	Versions []string `json:"versions,omitempty"`
	// Ciphers are the cipher suites the server accepts, by IANA name, keyed by the protocol versions that
	// accept exactly that list: {"tls10,tls11": [...], "tls12": [...]}. A version tlsx found no cipher
	// for (tlsx does not enumerate TLS 1.3 suites) is only in Versions.
	Ciphers map[string][]string `json:"ciphers,omitempty"`
	Cert    *Cert               `json:"cert,omitempty"`
	// ClientCert is true when the server asks for a client certificate.
	ClientCert bool   `json:"client_cert,omitempty"`
	JARM       string `json:"jarm,omitempty"`
	JA3S       string `json:"ja3s,omitempty"`
	// Error is why the target did not answer TLS (tlsx's first cause).
	Error string `json:"error,omitempty"`
	// IP is the address every location resolved to, written once when it is not in the locations.
	IP string `json:"ip,omitempty"`
	// Locations are every host:port with this profile: "10.0.0.5:443", or "app.example.com:443
	// [10.0.0.5]" when the host is a name and the group has no IP.
	Locations []string `json:"locations,omitempty"`
	// Count is the number of locations; it is written only when the budget cut Locations.
	Count int `json:"count,omitempty"`
}

// MarshalJSON leaves out count when every location is listed.
func (g Group) MarshalJSON() ([]byte, error) {
	type plain Group
	p := plain(g)
	if p.Count <= len(p.Locations) {
		p.Count = 0
	}
	return Marshal(p)
}

// Error is a problem during the run, with a hint about what to try next.
type Error struct {
	Kind string `json:"kind"`
	Hint string `json:"hint"`
}

// Budget reports the output limits that were applied.
type Budget struct {
	MaxItems  int  `json:"max_items"`
	MaxBytes  int  `json:"max_bytes"`
	Truncated bool `json:"truncated"`
}

// SeverityRank orders severities from most to least important.
var SeverityRank = map[string]int{
	"critical": 5,
	"high":     4,
	"medium":   3,
	"low":      2,
	"info":     1,
	"unknown":  0,
}

// ConfidenceRank orders confidence values: a verified finding before a matched one before a heuristic one.
var ConfidenceRank = map[string]int{
	"verified":  2,
	"":          1,
	"heuristic": 0,
}
