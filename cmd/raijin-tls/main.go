// Command raijin-tls runs tlsx and returns a small, grouped, ranked result for AI agents.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"

	raijintls "github.com/protonnegativo/raijin-tls"
	"github.com/protonnegativo/raijin-tls/internal/banner"
	"github.com/protonnegativo/raijin-tls/internal/reduce"
	"github.com/protonnegativo/raijin-tls/internal/schema"
	"github.com/protonnegativo/raijin-tls/internal/scope"
	"github.com/protonnegativo/raijin-tls/internal/state"
	"github.com/protonnegativo/raijin-tls/internal/tlsx"
)

const version = "0.1.0"

// maxCIDR is the largest range a target can expand to (a /16). Each address is checked against the
// scope before tlsx runs, so exclusions inside a range are never scanned.
const maxCIDR = 1 << 16

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("raijin-tls", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var hosts, inputs multi
	fs.Var(&hosts, "u", "host, host:port, IP or CIDR to scan, comma-separated (repeatable; default: every host the scope names)")
	list := fs.String("l", "", "file with one host, host:port, IP or CIDR per line")
	scopeFile := fs.String("scope", "", "scope file (required): domains, *.wildcards, IPs, CIDRs, !exclusions")
	ports := fs.String("p", "", "ports to connect to (tlsx -p), comma-separated (default: 443)")
	noEnum := fs.Bool("no-enum", false, "do not enumerate protocol versions and ciphers (tlsx -ve -ce); only check what is negotiated")
	timeout := fs.Int("timeout", 0, "TLS connection timeout in seconds (tlsx -timeout)")
	threads := fs.Int("threads", 0, "concurrent connections (tlsx -c)")
	maxItems := fs.Int("max-items", 0, "maximum findings in the output (0 keeps all)")
	maxBytes := fs.Int("max-bytes", reduce.Defaults().MaxBytes, "maximum size of the JSON output; cuts are counted in omitted")
	rawPath := fs.String("raw", "", "file for tlsx's full JSONL output (default: a new file in the temp dir)")
	statePath := fs.String("state", "", "state file; marks findings that are new since the last run")
	format := fs.String("format", "json", "output format: json or table")
	pretty := fs.Bool("pretty", false, "indent the JSON (compact by default, which costs fewer tokens)")
	fs.Var(&inputs, "input", "read existing tlsx JSONL instead of running tlsx (repeatable)")
	bin := fs.String("tlsx", "tlsx", "path to the tlsx binary")
	showVersion := fs.Bool("version", false, "print the version")
	showBanner := fs.Bool("banner", false, "print the Raijin banner to stderr (off by default to keep output small)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: raijin-tls --scope scope.txt [-u target | -l targets.txt | --input results.jsonl] [flags] [-- extra tlsx args]\n\nWith no targets it scans every host the scope names.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *showBanner {
		banner.Write(stderr, "raijin-tls", version, useColor(stderr))
	}
	if *showVersion {
		fmt.Fprintln(stdout, "raijin-tls", version)
		return 0
	}
	if *scopeFile == "" {
		fmt.Fprintln(stderr, "raijin-tls: --scope is required")
		return 1
	}
	sc, err := scope.Load(*scopeFile)
	if err != nil {
		fmt.Fprintln(stderr, "raijin-tls: scope:", err)
		return 1
	}

	res := schema.Result{
		Tool:     "raijin-tls",
		Version:  version,
		Findings: []schema.Finding{},
		Groups:   []schema.Group{},
		Omitted:  map[string]int{},
		Errors:   []schema.Error{},
		Next:     []string{},
		Budget:   schema.Budget{MaxItems: *maxItems, MaxBytes: *maxBytes},
	}
	opt := reduce.Defaults()
	opt.MaxItems = *maxItems
	opt.MaxBytes = *maxBytes
	opt.InScope = sc.Allowed

	var events []tlsx.Event
	var stats tlsx.Stats
	if len(inputs) > 0 {
		for _, in := range inputs {
			b, err := os.ReadFile(in)
			if err != nil {
				fmt.Fprintln(stderr, "raijin-tls:", err)
				return 1
			}
			ev, st, err := tlsx.ParseCount(bytes.NewReader(b))
			if err != nil {
				fmt.Fprintln(stderr, "raijin-tls:", err)
				return 1
			}
			events = append(events, ev...)
			stats = stats.Add(st)
		}
		res.Target = strings.Join(inputs, ", ")
	} else {
		if *list != "" {
			lines, err := readLines(*list)
			if err != nil {
				fmt.Fprintln(stderr, "raijin-tls:", err)
				return 1
			}
			hosts = append(hosts, lines...)
		}
		var targets []string
		if len(hosts) == 0 {
			// no targets given: scan what the scope names (tlsx connects to port 443 unless -p says otherwise)
			var wildcards, ranges []string
			targets, wildcards, ranges = sc.Targets()
			for _, w := range wildcards {
				res.Next = append(res.Next, "raijin-subs --scope "+*scopeFile+" -d "+strings.TrimPrefix(w, "*.")+", then raijin-tls -l <live hosts> to cover "+w)
			}
			for _, r := range ranges {
				res.Next = append(res.Next, "raijin-ports --scope "+*scopeFile+" -host "+r+", then raijin-tls -l <open ports> to cover "+r)
			}
		} else {
			var err error
			targets, err = filter(hosts, sc, res.Omitted)
			if err != nil {
				fmt.Fprintln(stderr, "raijin-tls:", err)
				return 1
			}
		}
		if len(targets) == 0 {
			if len(res.Next) > 0 {
				res.Summary = "the scope names no single host to scan"
				res.Target = *scopeFile
				write(stdout, &res, *format, *pretty)
				return 1
			}
			fmt.Fprintln(stderr, "raijin-tls: no targets in scope")
			return 1
		}
		res.Target = targetSummary(targets, res.Omitted["out_of_scope"])

		if *rawPath == "" {
			f, err := os.CreateTemp("", "raijin-tls-*.jsonl")
			if err != nil {
				fmt.Fprintln(stderr, "raijin-tls:", err)
				return 1
			}
			f.Close()
			*rawPath = f.Name()
		}
		raw, err := os.Create(*rawPath)
		if err != nil {
			fmt.Fprintln(stderr, "raijin-tls:", err)
			return 1
		}
		defer raw.Close()
		res.Raw = *rawPath

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		if e := checkVersion(ctx, *bin); e != nil {
			res.Errors = append(res.Errors, *e)
		}
		var stderrTail string
		events, stats, stderrTail, err = tlsx.Run(ctx, targets, tlsx.Options{
			Binary: *bin, Ports: *ports, NoEnum: *noEnum, Timeout: *timeout, Threads: *threads,
			Extra: fs.Args(), Raw: raw,
		})
		switch {
		case errors.Is(err, tlsx.ErrNotFound):
			res.Errors = append(res.Errors, schema.Error{Kind: "missing_engine", Hint: "install tlsx (go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest) or pass --tlsx <path>"})
			res.Summary = "tlsx not found, nothing scanned"
			res.Raw = ""
			raw.Close()
			os.Remove(*rawPath)
			write(stdout, &res, *format, *pretty)
			return 2
		case err != nil:
			hint := err.Error()
			if stderrTail != "" {
				hint += ": " + stderrTail
			}
			res.Errors = append(res.Errors, schema.Error{Kind: "engine_error", Hint: hint})
		}
	}

	out := reduce.Reduce(events, opt)
	res.Findings, res.Groups = out.Findings, out.Groups
	for k, v := range out.Omitted {
		res.Omitted[k] += v
	}
	if stats.Unparsed > 0 {
		res.Omitted["unparsed"] += stats.Unparsed
	}
	if hint := stats.FormatHint(res.Raw + strings.Join(inputs, ", ")); hint != "" {
		res.Errors = append(res.Errors, schema.Error{Kind: "engine_format", Hint: hint})
	}

	newCount := -1
	if *statePath != "" {
		st, err := state.Load(*statePath)
		if err != nil {
			res.Errors = append(res.Errors, schema.Error{Kind: "state_error", Hint: err.Error()})
		} else {
			newCount = st.Mark(res.Findings, out.AllLocations)
			if err := st.Save(*statePath); err != nil {
				res.Errors = append(res.Errors, schema.Error{Kind: "state_error", Hint: err.Error()})
			}
		}
	}

	res.Summary = summary(res, out, newCount)
	if res.Omitted["findings"] > 0 {
		res.Budget.Truncated = true
	}
	reduce.Fit(&res, *maxBytes)
	if res.Budget.Truncated {
		hint := "raise --max-bytes"
		if src := res.Raw + strings.Join(inputs, ", "); src != "" {
			hint += " or read " + src + " for what was cut"
		}
		res.Next = append(res.Next, hint)
		reduce.Fit(&res, *maxBytes) // the hint takes room too
	}
	write(stdout, &res, *format, *pretty)
	return 0
}

// checkVersion is the engine_version error when the installed tlsx is not the tested version (another
// major, or older). It never stops the run; a version it cannot read is not reported.
func checkVersion(ctx context.Context, bin string) *schema.Error {
	path, err := exec.LookPath(bin)
	if err != nil {
		return nil // Run reports missing_engine
	}
	engines, err := raijintls.Engines()
	tested, ok := engines["tlsx"]
	if err != nil || !ok {
		return nil
	}
	installed := tlsx.Version(ctx, path)
	if !tlsx.Untested(installed, tested.Version) {
		return nil
	}
	return &schema.Error{Kind: "engine_version", Hint: fmt.Sprintf("tlsx %s is not the tested %s; results may be incomplete. Install the tested version: %s",
		installed, tested.Version, tested.Install())}
}

// summary is written before the budget, so it stays true when Fit cuts.
func summary(res schema.Result, out reduce.Output, newCount int) string {
	bySev := map[string]int{}
	for _, f := range res.Findings {
		bySev[f.Severity]++
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		if n := bySev[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	s := fmt.Sprintf("%d endpoints, %d certificates, %d findings", out.Endpoints, out.Certs, len(res.Findings))
	if len(parts) > 0 {
		s += " (" + strings.Join(parts, ", ") + ")"
	}
	s += fmt.Sprintf(", %d groups", len(res.Groups))
	if out.Failed > 0 {
		s += fmt.Sprintf(", %d no TLS", out.Failed)
	}
	if newCount >= 0 {
		s += fmt.Sprintf(", %d new", newCount)
	}
	return s
}

func write(w io.Writer, res *schema.Result, format string, pretty bool) {
	if format == "table" {
		fmt.Fprintln(w, res.Summary)
		for _, f := range res.Findings {
			mark := ""
			if f.New {
				mark = " [new]"
			}
			fmt.Fprintf(w, "%-8s %s (%d)%s\n", strings.ToUpper(f.Severity), f.Title, max(f.Count, len(f.Locations)), mark)
			for _, l := range f.Locations {
				fmt.Fprintf(w, "         %s\n", l)
			}
		}
		for _, g := range res.Groups {
			n, unit := max(g.Count, len(g.Locations)), "endpoints"
			if n == 1 {
				unit = "endpoint"
			}
			fmt.Fprintf(w, "group    %s (%d %s)\n", describe(g), n, unit)
		}
		for _, e := range res.Errors {
			fmt.Fprintf(w, "error    %s: %s\n", e.Kind, e.Hint)
		}
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if pretty {
		enc.SetIndent("", "  ")
	}
	_ = enc.Encode(res)
}

// describe is a one-line view of a group for the table: the certificate subject and expiry, or the
// protocol versions.
func describe(g schema.Group) string {
	if g.Error != "" {
		return "failed: " + g.Error
	}
	if g.Cert != nil {
		s := "cert " + g.Cert.Subject
		if len(g.Cert.NotAfter) >= 10 {
			s += " until " + g.Cert.NotAfter[:10]
		}
		return s
	}
	v := strings.Join(g.Versions, ",")
	if v == "" {
		v = g.Version
	}
	return "tls " + v
}

// useColor is true when w is a terminal and NO_COLOR is not set.
func useColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// filter keeps the targets the scope allows. A CIDR is expanded and each address is checked on its own,
// so an exclusion inside a range is never scanned; out-of-scope targets are counted per address.
func filter(raw []string, sc *scope.Scope, omitted map[string]int) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	keep := func(t string) {
		if t == "" || seen[t] {
			return
		}
		seen[t] = true
		if !sc.Allowed(t) {
			omitted["out_of_scope"]++
			return
		}
		out = append(out, t)
	}
	for _, line := range raw {
		for _, t := range strings.Split(line, ",") {
			t = strings.ToLower(strings.TrimSpace(t))
			if !strings.Contains(t, "/") {
				keep(strings.TrimSuffix(t, "."))
				continue
			}
			ips, err := expand(t)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				keep(ip)
			}
		}
	}
	return out, nil
}

// expand lists every address in a CIDR, up to maxCIDR.
func expand(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid target %q: %v", cidr, err)
	}
	ones, bits := ipnet.Mask.Size()
	if bits-ones > 16 {
		return nil, fmt.Errorf("target %q has more than %d addresses; split it", cidr, maxCIDR)
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	ip = ip.Mask(ipnet.Mask)
	var out []string
	for cur := append(net.IP(nil), ip...); ipnet.Contains(cur); cur = next(cur) {
		out = append(out, cur.String())
		if len(out) >= maxCIDR {
			break
		}
	}
	return out, nil
}

func next(ip net.IP) net.IP {
	n := append(net.IP(nil), ip...)
	for i := len(n) - 1; i >= 0; i-- {
		n[i]++
		if n[i] != 0 {
			break
		}
	}
	return n
}

func targetSummary(targets []string, skipped int) string {
	s := fmt.Sprintf("%d target(s)", len(targets))
	if len(targets) == 1 {
		s = targets[0]
	}
	if skipped > 0 {
		s += fmt.Sprintf(" (%d out of scope skipped)", skipped)
	}
	return s
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}
