// Package reduce turns raw tlsx events into a small, ranked Raijin result.
//
// It is lossless for what an agent acts on: every host:port tlsx reported is in exactly one group, with
// the negotiated version and cipher, every version and cipher the server accepts, and the certificate
// (fingerprint, subject, SANs, issuer, validity). Host:ports with the same profile share one group.
// Every issue is a finding that lists every host:port with it. Only exact duplicates are dropped. A
// byte budget can cut, but every cut is counted in omitted.
package reduce

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/protonnegativo/raijin-tls/internal/schema"
	"github.com/protonnegativo/raijin-tls/internal/tlsx"
)

// Options control what the reducer keeps.
type Options struct {
	MaxItems    int // 0 keeps every finding
	MaxBytes    int
	MaxLocation int // longest finding location, details included
	// SoonDays is how close to its expiry a certificate is "expiring soon".
	SoonDays int
	// Now is the time an event without a timestamp is checked against; nil is time.Now.
	Now     func() time.Time
	InScope func(target string) bool
}

// Defaults keep every finding and cap the JSON at a size that fits comfortably in an agent's context.
func Defaults() Options {
	return Options{MaxBytes: 32000, MaxLocation: 300, SoonDays: 30}
}

// Output is what Reduce returns.
type Output struct {
	Findings []schema.Finding
	Groups   []schema.Group
	Omitted  map[string]int
	// AllLocations are every location per finding fingerprint, before any budget, for --state.
	AllLocations map[string][]string
	// Endpoints, Certs and Failed count the host:ports kept, the distinct certificates and the
	// host:ports that did not answer TLS, for the summary.
	Endpoints, Certs, Failed int
}

// issue is one rule. Each has a fixed severity; its ID is the finding ID.
type issue struct {
	id, title, severity string
}

// The rules, in the order they are checked; Reduce ranks the findings afterwards.
var issues = []issue{
	{"expired-cert", "Expired certificate", "high"},
	{"revoked-cert", "Revoked certificate", "high"},
	{"sslv3", "SSLv3 enabled", "high"},
	{"insecure-cipher", "Insecure ciphers accepted (NULL, export, anonymous, RC4, DES, MD5)", "high"},
	{"self-signed", "Self-signed certificate", "medium"},
	{"mismatched", "Certificate does not match the host name", "medium"},
	{"untrusted", "Untrusted certificate", "medium"},
	{"old-tls", "TLS 1.0 or 1.1 enabled", "medium"},
	{"weak-cipher", "Weak 64-bit block ciphers accepted (3DES, IDEA, RC2)", "medium"},
	{"cbc-old-protocol", "CBC ciphers on SSLv3, TLS 1.0 or 1.1", "low"},
	{"expiring-soon", "Certificate expires within 30 days", "low"},
	{"wildcard-cert", "Wildcard certificate", "info"},
}

// versionOrder sorts protocol versions oldest first.
var versionOrder = map[string]int{"ssl20": 0, "ssl2": 0, "ssl30": 1, "ssl3": 1, "tls10": 2, "tls11": 3, "tls12": 4, "tls13": 5}

// oldVersions are the versions where no AEAD cipher exists, so every block cipher there is CBC.
var oldVersions = map[string]bool{"ssl20": true, "ssl2": true, "ssl30": true, "ssl3": true, "tls10": true, "tls11": true}

var (
	// insecureCipher matches suites with no encryption, no authentication, export-grade keys, RC4,
	// single DES or MD5, by IANA name (or OpenSSL name when tlsx wrote one the table does not know).
	insecureCipher = regexp.MustCompile(`(?i)(_NULL_|WITH_NULL|^NULL-|-NULL-|EXPORT|^EXP-|_anon_|^ADH-|^AECDH-|RC4|_DES_CBC_|_DES40_|^DES-CBC-|-DES-CBC-|_MD5$|-MD5$)`)
	// weakCipher matches suites with a 64-bit block cipher (Sweet32).
	weakCipher = regexp.MustCompile(`(?i)(3DES|DES-CBC3|IDEA|RC2)`)
	causeRe    = regexp.MustCompile(`cause="([^"]*)"`)
)

// profile is what tlsx found on one host:port: its TLS configuration, its certificate, or why it failed.
type profile struct {
	version, cipher string
	versions        []string
	ciphers         map[string][]string
	cert            *schema.Cert
	clientCert      bool
	jarm, ja3s      string
	err             string
}

// A cluster is one group: a certificate ("cert"), a TLS configuration ("tls") or a failure ("failed"),
// with every location that has it.
type cluster struct {
	kind string
	key  string
	prof profile
	locs map[string]string // location -> IP
}

// Reduce collapses events into findings (one per issue) and groups: one per certificate and one per TLS
// configuration, each listing every host:port that serves it, and one per failure.
func Reduce(events []tlsx.Event, opt Options) Output {
	out := Output{Omitted: map[string]int{}, AllLocations: map[string][]string{}}
	now := opt.Now
	if now == nil {
		now = time.Now
	}

	var kept []tlsx.Event
	seen := map[string]bool{}
	ips := map[string]map[string]bool{} // base location -> IPs
	for _, ev := range events {
		if opt.InScope != nil && !opt.InScope(ev.Host) {
			out.Omitted["out_of_scope"]++
			continue
		}
		key := exact(ev)
		if seen[key] {
			out.Omitted["duplicates"]++
			continue
		}
		seen[key] = true
		kept = append(kept, ev)
		b := Base(ev)
		if ips[b] == nil {
			ips[b] = map[string]bool{}
		}
		ips[b][ev.IP] = true
	}

	clusters := map[string]*cluster{}
	var keys []string
	byIssue := map[string]map[string]bool{}
	certs := map[string]bool{}
	for _, ev := range kept {
		loc := Base(ev)
		if len(ips[loc]) > 1 && ev.IP != "" {
			loc += " [" + ev.IP + "]" // the same host:port on several IPs (tlsx -sa)
		}
		p := Profile(ev)
		add := func(kind, key string) {
			key = kind + key
			c, ok := clusters[key]
			if !ok {
				c = &cluster{kind: kind, key: key, prof: p, locs: map[string]string{}}
				clusters[key] = c
				keys = append(keys, key)
			}
			c.locs[loc] = ev.IP
		}
		if p.err != "" {
			add("failed", p.err)
			out.Failed++
			continue
		}
		add("tls", configSignature(p))
		if p.cert != nil {
			add("cert", certSignature(p.cert))
			certs[certSignature(p.cert)] = true
		}
		ref := now()
		if t, err := time.Parse(time.RFC3339Nano, ev.Timestamp); err == nil {
			ref = t
		}
		for id, detail := range Issues(ev, p, ref, opt.SoonDays) {
			if byIssue[id] == nil {
				byIssue[id] = map[string]bool{}
			}
			l := loc
			if detail != "" {
				l += " [" + detail + "]"
			}
			byIssue[id][trim(l, opt.MaxLocation)] = true
		}
	}
	out.Endpoints = len(kept)
	out.Certs = len(certs)

	findings := []schema.Finding{}
	for _, is := range issues {
		locs := byIssue[is.id]
		if len(locs) == 0 {
			continue
		}
		l := sortedLocations(locs)
		f := schema.Finding{ID: is.id, Title: is.title, Severity: is.severity, Locations: l, Count: len(l), Fingerprint: is.id}
		out.AllLocations[f.Fingerprint] = l
		findings = append(findings, f)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if schema.SeverityRank[a.Severity] != schema.SeverityRank[b.Severity] {
			return schema.SeverityRank[a.Severity] > schema.SeverityRank[b.Severity]
		}
		if schema.ConfidenceRank[a.Confidence] != schema.ConfidenceRank[b.Confidence] {
			return schema.ConfidenceRank[a.Confidence] > schema.ConfidenceRank[b.Confidence]
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.ID < b.ID
	})

	groups := []schema.Group{}
	for _, key := range keys {
		groups = append(groups, group(clusters[key]))
	}
	sort.SliceStable(groups, func(i, j int) bool {
		a, b := groups[i], groups[j]
		if groupRank(a) != groupRank(b) {
			return groupRank(a) < groupRank(b) // certificates, then TLS configurations, then failures
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.ID < b.ID
	})

	if opt.MaxItems > 0 && len(findings) > opt.MaxItems {
		out.Omitted["findings"] += len(findings) - opt.MaxItems
		findings = findings[:opt.MaxItems]
	}
	out.Findings, out.Groups = findings, groups
	return out
}

// Base is the location of an event: "host:port" ("[v6]:port" for an IPv6 host), plus " sni=<name>" when
// tlsx sent an SNI that is not the host.
func Base(ev tlsx.Event) string {
	h := ev.Host
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	s := h
	if ev.Port != "" {
		s += ":" + string(ev.Port)
	}
	if ev.SNI != "" && !strings.EqualFold(ev.SNI, ev.Host) {
		s += " sni=" + ev.SNI
	}
	return s
}

// Profile is the TLS profile of an event: what is the same on every host:port of a group.
func Profile(ev tlsx.Event) profile {
	if !ev.ProbeStatus && ev.TLSVersion == "" && ev.SubjectDN == "" && ev.SubjectCN == "" {
		return profile{err: ErrorText(ev.Error)}
	}
	p := profile{
		version:    ev.TLSVersion,
		cipher:     CipherName(ev.Cipher),
		versions:   sortVersions(ev.VersionEnum),
		ciphers:    Ciphers(ev.CipherEnum),
		cert:       cert(ev),
		clientCert: ev.ClientCertRequired,
		jarm:       ev.JARM,
		ja3s:       ev.JA3S,
	}
	return p
}

// Issues returns the rules an event matches, each with the detail written in its location's brackets.
// ref is when the event was seen (its timestamp), so a replay gives the same result.
func Issues(ev tlsx.Event, p profile, ref time.Time, soonDays int) map[string]string {
	out := map[string]string{}
	notAfter, okAfter := parseTime(ev.NotAfter)
	switch {
	case ev.Expired || okAfter && notAfter.Before(ref):
		d := "expired"
		if okAfter {
			d += " " + notAfter.UTC().Format("2006-01-02")
		}
		out["expired-cert"] = d
	case okAfter && soonDays > 0 && notAfter.Sub(ref) < time.Duration(soonDays)*24*time.Hour:
		days := int(notAfter.Sub(ref).Hours() / 24)
		out["expiring-soon"] = fmt.Sprintf("%s, %d days", notAfter.UTC().Format("2006-01-02"), days)
	}
	if ev.Revoked {
		out["revoked-cert"] = ""
	}
	if ev.SelfSigned {
		out["self-signed"] = ""
	}
	if ev.Mismatched {
		out["mismatched"] = strings.Join(certNames(ev), ", ")
	}
	if ev.Untrusted {
		out["untrusted"] = ""
	}
	if ev.Wildcard {
		var w []string
		for _, n := range certNames(ev) {
			if strings.HasPrefix(n, "*.") {
				w = append(w, n)
			}
		}
		out["wildcard-cert"] = strings.Join(w, ", ")
	}

	versions := map[string]bool{}
	for _, v := range append(append([]string(nil), ev.VersionEnum...), ev.TLSVersion) {
		if v != "" {
			versions[strings.ToLower(v)] = true
		}
	}
	var ssl, old []string
	for _, v := range sortVersions(keys(versions)) {
		switch {
		case versionOrder[v] <= 1 && strings.HasPrefix(v, "ssl"):
			ssl = append(ssl, v)
		case v == "tls10" || v == "tls11":
			old = append(old, v)
		}
	}
	if len(ssl) > 0 {
		out["sslv3"] = strings.Join(ssl, ", ")
	}
	if len(old) > 0 {
		out["old-tls"] = strings.Join(old, ", ")
	}

	// Every cipher the server accepts, by version, with the type tlsx gave it.
	insecure, weak, cbc := map[string]bool{}, map[string]bool{}, map[string]bool{}
	check := func(version, name, kind string) {
		if name == "" {
			return
		}
		switch {
		case kind == "insecure" || insecureCipher.MatchString(name):
			insecure[name] = true
		case kind == "weak" || weakCipher.MatchString(name):
			weak[name] = true
		}
		if oldVersions[strings.ToLower(version)] && !strings.Contains(strings.ToUpper(name), "RC4") && !strings.Contains(strings.ToUpper(name), "NULL") {
			cbc[strings.ToLower(version)] = true
		}
	}
	for _, ce := range ev.CipherEnum {
		for kind, names := range ce.Ciphers {
			for _, n := range names {
				check(ce.Version, CipherName(n), kind)
			}
		}
	}
	check(ev.TLSVersion, CipherName(ev.Cipher), "")
	if len(insecure) > 0 {
		out["insecure-cipher"] = strings.Join(sortedSet(insecure), ", ")
	}
	if len(weak) > 0 {
		out["weak-cipher"] = strings.Join(sortedSet(weak), ", ")
	}
	if len(cbc) > 0 {
		out["cbc-old-protocol"] = strings.Join(sortVersions(keys(cbc)), ", ")
	}
	return out
}

// CipherName is the IANA name of a cipher suite: tlsx writes OpenSSL names for the suites it found
// with OpenSSL. A name the table does not know is kept as it is.
func CipherName(n string) string {
	if v, ok := opensslNames[n]; ok {
		return v
	}
	return n
}

// Ciphers lists the accepted suites per version, by IANA name, sorted and once each, with the versions
// that accept exactly the same suites joined into one key. Versions with no suites are left out.
func Ciphers(enum []tlsx.CipherEnum) map[string][]string {
	per := map[string]map[string]bool{}
	for _, ce := range enum {
		v := strings.ToLower(ce.Version)
		for _, names := range ce.Ciphers {
			for _, n := range names {
				if per[v] == nil {
					per[v] = map[string]bool{}
				}
				per[v][CipherName(n)] = true
			}
		}
	}
	byList := map[string][]string{}
	lists := map[string][]string{}
	for _, v := range sortVersions(keys(per)) {
		l := sortedSet(per[v])
		k := strings.Join(l, ",")
		byList[k] = append(byList[k], v)
		lists[k] = l
	}
	if len(byList) == 0 {
		return nil
	}
	out := map[string][]string{}
	for k, vs := range byList {
		out[strings.Join(vs, ",")] = lists[k]
	}
	return out
}

// ErrorText is tlsx's first cause ("port closed or filtered"), or its first error when it has none.
// tlsx repeats the error once per retry, and the address is the location.
func ErrorText(e string) string {
	if m := causeRe.FindStringSubmatch(e); m != nil {
		return m[1]
	}
	e = strings.TrimSpace(strings.SplitN(e, ";", 2)[0])
	if e == "" {
		return "no response"
	}
	return e
}

func cert(ev tlsx.Event) *schema.Cert {
	c := &schema.Cert{Subject: ev.SubjectDN, Issuer: ev.IssuerDN, NotBefore: ev.NotBefore, NotAfter: ev.NotAfter}
	switch {
	case ev.FingerprintHash["sha256"] != "":
		c.SHA256 = ev.FingerprintHash["sha256"]
	case ev.FingerprintHash["sha1"] != "":
		c.SHA1 = ev.FingerprintHash["sha1"]
	default:
		c.MD5 = ev.FingerprintHash["md5"]
	}
	if c.Subject == "" && ev.SubjectCN != "" {
		c.Subject = "CN=" + ev.SubjectCN
	}
	if c.Issuer == "" && ev.IssuerCN != "" {
		c.Issuer = "CN=" + ev.IssuerCN
	}
	if !(len(ev.SubjectAN) == 1 && ev.SubjectAN[0] == ev.SubjectCN) && len(ev.SubjectAN) > 0 {
		c.SAN = append([]string(nil), ev.SubjectAN...)
	}
	if c.SHA256+c.SHA1+c.MD5+c.Subject+c.Issuer+c.NotBefore+c.NotAfter == "" && len(c.SAN) == 0 {
		return nil
	}
	return c
}

// certNames are the names the certificate is valid for: its SANs, or its CN when it has none.
func certNames(ev tlsx.Event) []string {
	if len(ev.SubjectAN) > 0 {
		return ev.SubjectAN
	}
	if ev.SubjectCN != "" {
		return []string{ev.SubjectCN}
	}
	return nil
}

func group(c *cluster) schema.Group {
	p := c.prof
	var g schema.Group
	switch c.kind {
	case "cert":
		g = schema.Group{ID: "cert-" + certID(p.cert, c.key), Cert: p.cert}
	case "tls":
		g = schema.Group{
			ID: "tls-" + fingerprint(c.key)[:8], Version: p.version, Cipher: p.cipher, Versions: p.versions,
			Ciphers: p.ciphers, ClientCert: p.clientCert, JARM: p.jarm, JA3S: p.ja3s,
		}
	default:
		g = schema.Group{ID: "failed-" + fingerprint(c.key)[:8], Error: p.err}
	}
	// One IP for every location is written once; otherwise a name gets its IP in brackets.
	ipSet := map[string]bool{}
	named := false
	for loc, ip := range c.locs {
		ipSet[ip] = true
		named = named || (!strings.HasSuffix(loc, "]") && net.ParseIP(hostOf(loc)) == nil)
	}
	shared := ""
	if len(ipSet) == 1 && named {
		for ip := range ipSet {
			shared = ip
		}
	}
	g.IP = shared
	locs := map[string]bool{}
	for loc, ip := range c.locs {
		if shared == "" && ip != "" && !strings.HasSuffix(loc, "]") && net.ParseIP(hostOf(loc)) == nil {
			loc += " [" + ip + "]"
		}
		locs[loc] = true
	}
	g.Locations = sortedLocations(locs)
	g.Count = len(g.Locations)
	return g
}

// hostOf is the host of a location: "a.example.com:443 sni=x" -> "a.example.com", "[::1]:443" -> "::1".
func hostOf(loc string) string {
	loc = strings.SplitN(loc, " ", 2)[0]
	if h, _, err := net.SplitHostPort(loc); err == nil {
		return h
	}
	return loc
}

// exact is everything tlsx wrote that the output keeps, so only true repeats are dropped.
func exact(ev tlsx.Event) string {
	b, _ := schema.Marshal([]any{ev.Host, ev.IP, ev.Port, ev.SNI, signature(Profile(ev)), ev.Expired, ev.SelfSigned, ev.Mismatched, ev.Revoked, ev.Untrusted, ev.Wildcard})
	return string(b)
}

func signature(p profile) string {
	return configSignature(p) + certSignature(p.cert) + p.err
}

// configSignature is what makes two host:ports the same TLS configuration.
func configSignature(p profile) string {
	b, _ := schema.Marshal([]any{p.version, p.cipher, p.versions, p.ciphers, p.clientCert, p.jarm, p.ja3s})
	return string(b)
}

// certSignature is the certificate: its fingerprint and the fields written about it.
func certSignature(c *schema.Cert) string {
	b, _ := schema.Marshal(c)
	return string(b)
}

// certID is the start of the certificate fingerprint, so the same certificate has the same group ID in
// every run; a certificate without a fingerprint gets a hash of its fields.
func certID(c *schema.Cert, key string) string {
	if fp := c.SHA256 + c.SHA1 + c.MD5; len(fp) >= 8 {
		return fp[:8]
	}
	return fingerprint(key)[:8]
}

func groupRank(g schema.Group) int {
	switch {
	case g.Cert != nil:
		return 0
	case g.Error == "":
		return 1
	}
	return 2
}

// Fit shrinks the result until its JSON is at most maxBytes. It cuts the least important data first:
// group locations, then groups, then the locations of the lowest-ranked findings (each keeps one, and
// its count), then the lowest-ranked findings. Every cut is counted in Omitted.
func Fit(res *schema.Result, maxBytes int) {
	if maxBytes <= 0 || size(res) <= maxBytes {
		return
	}
	res.Budget.Truncated = true
	if res.Omitted == nil {
		res.Omitted = map[string]int{}
	}
	total := size(res) // now includes the budget object
	for i := len(res.Groups) - 1; i >= 0 && total > maxBytes; i-- {
		g := &res.Groups[i]
		before := size(g)
		res.Omitted["locations"] += len(g.Locations)
		g.Locations = nil
		total += size(g) - before
	}
	for total > maxBytes && len(res.Groups) > 0 {
		last := len(res.Groups) - 1
		total -= size(res.Groups[last]) + 1
		res.Groups = res.Groups[:last]
		res.Omitted["groups"]++
	}
	for i := len(res.Findings) - 1; i >= 0 && total > maxBytes; i-- {
		f := &res.Findings[i]
		if len(f.Locations) <= 1 {
			continue
		}
		before := size(f)
		res.Omitted["locations"] += len(f.Locations) - 1
		f.Locations = f.Locations[:1]
		total += size(f) - before
	}
	for total > maxBytes && len(res.Findings) > 1 {
		last := len(res.Findings) - 1
		total -= size(res.Findings[last]) + 1
		res.Findings = res.Findings[:last]
		res.Omitted["findings"]++
	}
	// the estimate above ignores the omitted counters it adds; settle on the real size
	for size(res) > maxBytes && len(res.Findings) > 1 {
		res.Findings = res.Findings[:len(res.Findings)-1]
		res.Omitted["findings"]++
	}
}

func parseTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}

// sortVersions sorts protocol versions oldest first; unknown names go last, alphabetically.
func sortVersions(vs []string) []string {
	if len(vs) == 0 {
		return nil
	}
	out := make([]string, 0, len(vs))
	seen := map[string]bool{}
	for _, v := range vs {
		v = strings.ToLower(v)
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, okA := versionOrder[out[i]]
		b, okB := versionOrder[out[j]]
		switch {
		case okA && okB && a != b:
			return a < b
		case okA != okB:
			return okA
		}
		return out[i] < out[j]
	})
	return out
}

// sortedLocations sorts by host, then numerically by port.
func sortedLocations(set map[string]bool) []string {
	out := sortedSet(set)
	sort.SliceStable(out, func(i, j int) bool {
		hi, pi := splitLoc(out[i])
		hj, pj := splitLoc(out[j])
		if hi != hj {
			return hi < hj
		}
		if pi != pj {
			return pi < pj
		}
		return out[i] < out[j]
	})
	return out
}

func splitLoc(loc string) (string, int) {
	first := strings.SplitN(loc, " ", 2)[0]
	h, p, err := net.SplitHostPort(first)
	if err != nil {
		return first, 0
	}
	n, _ := strconv.Atoi(p)
	return h, n
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedSet(set map[string]bool) []string {
	return keys(set)
}

func size(v any) int {
	b, _ := schema.Marshal(v)
	return len(b)
}

func fingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}

func trim(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
