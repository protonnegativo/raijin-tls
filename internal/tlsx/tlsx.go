// Package tlsx runs the ProjectDiscovery tlsx binary and parses its JSONL output.
package tlsx

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// ErrNotFound is returned when the tlsx binary is not on PATH.
var ErrNotFound = errors.New("tlsx binary not found")

// Event is the subset of a tlsx JSONL result that Raijin uses.
type Event struct {
	Timestamp   string `json:"timestamp"`
	Host        string `json:"host"`
	IP          string `json:"ip"`
	Port        Port   `json:"port"`
	ProbeStatus bool   `json:"probe_status"`
	Error       string `json:"error"`
	SNI         string `json:"sni"`

	TLSVersion string `json:"tls_version"`
	Cipher     string `json:"cipher"`

	Expired    bool `json:"expired"`
	SelfSigned bool `json:"self_signed"`
	Mismatched bool `json:"mismatched"`
	Revoked    bool `json:"revoked"`
	Untrusted  bool `json:"untrusted"`
	Wildcard   bool `json:"wildcard_certificate"`

	NotBefore       string            `json:"not_before"`
	NotAfter        string            `json:"not_after"`
	SubjectDN       string            `json:"subject_dn"`
	SubjectCN       string            `json:"subject_cn"`
	SubjectAN       []string          `json:"subject_an"`
	IssuerDN        string            `json:"issuer_dn"`
	IssuerCN        string            `json:"issuer_cn"`
	FingerprintHash map[string]string `json:"fingerprint_hash"`

	VersionEnum []string     `json:"version_enum"`
	CipherEnum  []CipherEnum `json:"cipher_enum"`

	ClientCertRequired bool   `json:"client_cert_required"`
	JARM               string `json:"jarm_hash"`
	JA3S               string `json:"ja3s_hash"`
}

// CipherEnum is the ciphers tlsx found for one protocol version, by tlsx's cipher type (secure,
// insecure, weak, unknown).
type CipherEnum struct {
	Version string              `json:"version"`
	Ciphers map[string][]string `json:"ciphers"`
}

// Port is the port as tlsx writes it: a string ("443"), or a number in older versions.
type Port string

// UnmarshalJSON accepts a string or a number.
func (p *Port) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*p = Port(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*p = Port(n.String())
	return nil
}

// Options are the tlsx settings Raijin passes through.
type Options struct {
	Binary string
	// Ports is tlsx -p (default 443).
	Ports string
	// NoEnum skips the enumeration of protocol versions and ciphers (-ve -ce), which is most of the run
	// time: only the negotiated version and cipher are checked.
	NoEnum  bool
	Timeout int
	Threads int
	Extra   []string
	// Raw, if set, receives tlsx's JSONL output unchanged.
	Raw io.Writer
}

// Run scans the targets and returns every event and the line counts, plus the last stderr lines if tlsx
// failed.
func Run(ctx context.Context, targets []string, opt Options) ([]Event, Stats, string, error) {
	bin := opt.Binary
	if bin == "" {
		bin = "tlsx"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return nil, Stats{}, "", ErrNotFound
	}

	list, err := os.CreateTemp("", "raijin-tls-targets-*.txt")
	if err != nil {
		return nil, Stats{}, "", err
	}
	defer os.Remove(list.Name())
	if _, err := io.WriteString(list, strings.Join(targets, "\n")+"\n"); err != nil {
		list.Close()
		return nil, Stats{}, "", err
	}
	list.Close()

	cmd := exec.CommandContext(ctx, path, Args(list.Name(), opt)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, Stats{}, "", err
	}
	var r io.Reader = stdout
	if opt.Raw != nil {
		r = io.TeeReader(stdout, opt.Raw)
	}
	if err := cmd.Start(); err != nil {
		return nil, Stats{}, "", err
	}
	events, st, parseErr := ParseCount(r)
	waitErr := cmd.Wait()
	if parseErr != nil {
		return events, st, tail(stderr.String(), 3), parseErr
	}
	if waitErr != nil {
		return events, st, tail(stderr.String(), 3), fmt.Errorf("tlsx exited: %w", waitErr)
	}
	return events, st, "", nil
}

// Args builds the tlsx command line. The certificate, the negotiated version and cipher, and the
// fingerprints are always in tlsx's JSON; -ex -ss -mm -wc add the certificate checks, -tps reports the
// targets that did not answer, and -ve -ce enumerate every protocol version and cipher the server accepts.
// Revocation (-re) is not checked by default: it asks the CA's OCSP and CRL servers, which are not the
// target; pass it after --.
func Args(listFile string, opt Options) []string {
	args := []string{"-l", listFile, "-json", "-silent", "-nc", "-duc", "-ex", "-ss", "-mm", "-wc", "-tps"}
	if !opt.NoEnum {
		args = append(args, "-ve", "-ce")
	}
	if opt.Ports != "" {
		args = append(args, "-p", opt.Ports)
	}
	if opt.Timeout > 0 {
		args = append(args, "-timeout", fmt.Sprint(opt.Timeout))
	}
	if opt.Threads > 0 {
		args = append(args, "-c", fmt.Sprint(opt.Threads))
	}
	return append(args, opt.Extra...)
}

// Parse reads tlsx JSONL. Lines that are not JSON objects with a host are skipped.
func Parse(r io.Reader) ([]Event, error) {
	events, _, err := ParseCount(r)
	return events, err
}

// Stats counts what Parse saw, for the format check.
type Stats struct {
	// Lines is every non-empty line.
	Lines int
	// Unparsed is the lines that are not JSON objects with a host: they are not in the events.
	Unparsed int
	// Incomplete is the lines without the fields the reducer needs: a host, a port, and a tls_version
	// (answered) or an error (did not answer). Unparsed lines count here too.
	Incomplete int
}

// Essential names the fields Stats.Incomplete checks, for the engine_format hint.
const Essential = "host, port and (tls_version or error)"

// ParseCount is Parse plus the line counts.
func ParseCount(r io.Reader) ([]Event, Stats, error) {
	var events []Event
	var st Stats
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		st.Lines++
		var ev Event
		if line[0] != '{' || json.Unmarshal(line, &ev) != nil {
			st.Unparsed++
			st.Incomplete++
			continue
		}
		if ev.Host == "" {
			ev.Host = ev.IP
		}
		if ev.Host == "" {
			st.Unparsed++
			st.Incomplete++
			continue
		}
		if ev.Port == "" || (ev.TLSVersion == "" && ev.Error == "") {
			st.Incomplete++
		}
		events = append(events, ev)
	}
	return events, st, sc.Err()
}

// FormatHint is the engine_format hint, or "" when every line had the essential fields.
func (st Stats) FormatHint(raw string) string {
	if st.Incomplete == 0 {
		return ""
	}
	return fmt.Sprintf("%d of %d tlsx results had no %s; the engine's output format may have changed. Read %s for the full output",
		st.Incomplete, st.Lines, Essential, raw)
}

// Add sums two counts (several --input files).
func (st Stats) Add(o Stats) Stats {
	return Stats{st.Lines + o.Lines, st.Unparsed + o.Unparsed, st.Incomplete + o.Incomplete}
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
