package reduce

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/protonnegativo/raijin-tls/internal/schema"
	"github.com/protonnegativo/raijin-tls/internal/scope"
	"github.com/protonnegativo/raijin-tls/internal/tlsx"
)

const ts = "2026-10-24T12:00:00Z"

// ev is a TLS 1.2 + 1.3 endpoint with a one-year certificate for "site"; the certificate is the same
// for the same fp.
func ev(host, port, ip, fp string) tlsx.Event {
	return tlsx.Event{
		Timestamp: ts, Host: host, IP: ip, Port: tlsx.Port(port), SNI: host, ProbeStatus: true,
		TLSVersion: "tls13", Cipher: "TLS_AES_128_GCM_SHA256", VersionEnum: []string{"tls13", "tls12"},
		CipherEnum: []tlsx.CipherEnum{{Version: "tls13"}, {Version: "tls12", Ciphers: map[string][]string{"unknown": {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}}}},
		SubjectDN:  "CN=site", SubjectCN: "site", SubjectAN: []string{"site"}, IssuerDN: "CN=CA",
		NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z",
		FingerprintHash: map[string]string{"sha256": fp, "sha1": "ignored"},
	}
}

func finding(out Output, id string) *schema.Finding {
	for i := range out.Findings {
		if out.Findings[i].ID == id {
			return &out.Findings[i]
		}
	}
	return nil
}

// grouped reports whether a location is in a group of the given kind ("cert", "tls" or "failed").
func grouped(out Output, kind, loc string) bool {
	for _, g := range out.Groups {
		if !strings.HasPrefix(g.ID, kind+"-") {
			continue
		}
		for _, l := range g.Locations {
			if l == loc {
				return true
			}
		}
	}
	return false
}

func TestEveryEndpointIsInACertAndATLSGroup(t *testing.T) {
	events := []tlsx.Event{ev("a.example.com", "443", "", "aa11aa11aa"), ev("b.example.com", "443", "", "bb22bb22bb"), ev("10.0.0.1", "8443", "10.0.0.1", "aa11aa11aa")}
	out := Reduce(events, Defaults())
	for _, loc := range []string{"a.example.com:443", "b.example.com:443", "10.0.0.1:8443"} {
		if !grouped(out, "cert", loc) || !grouped(out, "tls", loc) {
			t.Errorf("%s should be in a cert group and a tls group: %+v", loc, out.Groups)
		}
	}
	if out.Endpoints != 3 || out.Certs != 2 {
		t.Errorf("endpoints %d certs %d", out.Endpoints, out.Certs)
	}
}

func TestSameCertificateAndConfigCollapse(t *testing.T) {
	var events []tlsx.Event
	for _, p := range []string{"443", "8443", "9443"} {
		events = append(events, ev("lb.example.com", p, "10.0.0.5", "fp1fp1fp1"))
	}
	other := ev("lb.example.com", "10443", "10.0.0.5", "fp1fp1fp1")
	other.VersionEnum = []string{"tls12"}
	events = append(events, other)
	out := Reduce(events, Defaults())
	if len(out.Groups) != 3 {
		t.Fatalf("one certificate and two configurations should be 3 groups: %+v", out.Groups)
	}
	if g := out.Groups[0]; g.ID != "cert-fp1fp1fp" || len(g.Locations) != 4 || g.IP != "10.0.0.5" || g.Cert.SHA256 != "fp1fp1fp1" || g.Cert.SHA1 != "" {
		t.Errorf("certificate group: %+v", g)
	}
	if g := out.Groups[1]; len(g.Locations) != 3 || g.Locations[0] != "lb.example.com:443" || g.Locations[2] != "lb.example.com:9443" {
		t.Errorf("ports should sort numerically in the larger tls group: %+v", g)
	}
}

func TestExactDuplicatesAreCountedNearOnesKept(t *testing.T) {
	a := ev("a.example.com", "443", "10.0.0.1", "fp")
	b := a
	b.Timestamp = "2026-10-24T12:00:05Z" // only the timestamp differs: a repeat
	c := a
	c.SNI = "other.example.com" // another SNI: another result
	out := Reduce([]tlsx.Event{a, b, c}, Defaults())
	if out.Omitted["duplicates"] != 1 || out.Endpoints != 2 {
		t.Errorf("duplicates %d endpoints %d", out.Omitted["duplicates"], out.Endpoints)
	}
	if !grouped(out, "tls", "a.example.com:443 sni=other.example.com") {
		t.Errorf("the SNI should be in the location: %+v", out.Groups)
	}
}

func TestSameHostPortOnSeveralIPsKeepsTheIP(t *testing.T) {
	out := Reduce([]tlsx.Event{ev("m.example.com", "443", "10.0.0.5", "fp"), ev("m.example.com", "443", "10.0.0.6", "fp")}, Defaults())
	for _, loc := range []string{"m.example.com:443 [10.0.0.5]", "m.example.com:443 [10.0.0.6]"} {
		if !grouped(out, "cert", loc) {
			t.Errorf("%s missing: %+v", loc, out.Groups)
		}
	}
	if out.Groups[0].IP != "" {
		t.Errorf("no shared IP: %+v", out.Groups[0])
	}
}

func TestNamesGetTheirIPWhenTheGroupHasSeveral(t *testing.T) {
	out := Reduce([]tlsx.Event{ev("a.example.com", "443", "10.0.0.1", "fp"), ev("b.example.com", "443", "10.0.0.2", "fp")}, Defaults())
	if !grouped(out, "cert", "a.example.com:443 [10.0.0.1]") || !grouped(out, "cert", "b.example.com:443 [10.0.0.2]") {
		t.Errorf("each name needs its IP: %+v", out.Groups)
	}
}

func TestOpenSSLNamesBecomeIANANamesOnce(t *testing.T) {
	e := ev("a.example.com", "443", "", "fp")
	e.VersionEnum = []string{"tls10", "tls11", "tls12"}
	e.CipherEnum = []tlsx.CipherEnum{
		{Version: "tls10", Ciphers: map[string][]string{"unknown": {"TLS_RSA_WITH_AES_128_CBC_SHA", "AES128-SHA", "ECDHE-RSA-AES256-SHA"}}},
		{Version: "tls11", Ciphers: map[string][]string{"unknown": {"ECDHE-RSA-AES256-SHA", "TLS_RSA_WITH_AES_128_CBC_SHA"}}},
		{Version: "tls12", Ciphers: map[string][]string{"secure": {"ECDHE-RSA-AES128-GCM-SHA256"}, "unknown": {"MADE-UP-CIPHER"}}},
	}
	g := Profile(e)
	want := map[string]string{
		"tls10,tls11": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA",
		"tls12":       "MADE-UP-CIPHER,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	}
	if len(g.ciphers) != len(want) {
		t.Fatalf("ciphers: %v", g.ciphers)
	}
	for k, v := range want {
		if strings.Join(g.ciphers[k], ",") != v {
			t.Errorf("%s: %v, want %s", k, g.ciphers[k], v)
		}
	}
	if strings.Join(g.versions, ",") != "tls10,tls11,tls12" {
		t.Errorf("versions oldest first: %v", g.versions)
	}
}

func TestEveryFlagIsAFindingWithEveryLocation(t *testing.T) {
	a := ev("a.example.com", "443", "", "fa")
	a.Expired, a.SelfSigned, a.Mismatched, a.Revoked, a.Untrusted = true, true, true, true, true
	a.SubjectAN = []string{"other.example", "*.other.example"}
	a.Wildcard = true
	b := ev("b.example.com", "443", "", "fb")
	b.Mismatched = true
	out := Reduce([]tlsx.Event{a, b}, Defaults())
	for id, n := range map[string]int{"expired-cert": 1, "self-signed": 1, "mismatched": 2, "revoked-cert": 1, "untrusted": 1, "wildcard-cert": 1} {
		f := finding(out, id)
		if f == nil || len(f.Locations) != n {
			t.Errorf("%s: %+v", id, f)
		}
	}
	if f := finding(out, "mismatched"); f.Locations[0] != "a.example.com:443 [other.example, *.other.example]" {
		t.Errorf("mismatched should name the certificate: %v", f.Locations)
	}
	if f := finding(out, "wildcard-cert"); f.Locations[0] != "a.example.com:443 [*.other.example]" {
		t.Errorf("wildcard: %v", f.Locations)
	}
}

func TestExpiryIsCheckedAgainstTheTimestamp(t *testing.T) {
	soon := ev("soon.example.com", "443", "", "f1")
	soon.NotAfter = "2026-11-03T12:00:00Z"
	old := ev("old.example.com", "443", "", "f2")
	old.NotAfter = "2025-01-01T00:00:00Z" // tlsx did not flag it (no -ex), the date says so
	opt := Defaults()
	opt.Now = func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) } // never used: events have a timestamp
	out := Reduce([]tlsx.Event{soon, old}, opt)
	if f := finding(out, "expiring-soon"); f == nil || f.Locations[0] != "soon.example.com:443 [2026-11-03, 10 days]" {
		t.Errorf("expiring-soon: %+v", f)
	}
	if f := finding(out, "expired-cert"); f == nil || f.Locations[0] != "old.example.com:443 [expired 2025-01-01]" {
		t.Errorf("expired: %+v", f)
	}
}

func TestProtocolAndCipherRules(t *testing.T) {
	e := ev("legacy.example.com", "443", "", "fp")
	e.TLSVersion, e.Cipher = "tls12", "ECDHE-RSA-AES128-GCM-SHA256"
	e.VersionEnum = []string{"ssl30", "tls10", "tls11", "tls12"}
	e.CipherEnum = []tlsx.CipherEnum{
		{Version: "ssl30", Ciphers: map[string][]string{"unknown": {"RC4-MD5", "DES-CBC3-SHA"}}},
		{Version: "tls10", Ciphers: map[string][]string{"unknown": {"AES128-SHA", "EXP-RC4-MD5"}}},
		{Version: "tls11", Ciphers: map[string][]string{"insecure": {"TLS_FOO_TLSX_SAYS_INSECURE"}}},
		{Version: "tls12", Ciphers: map[string][]string{"unknown": {"NULL-SHA", "ADH-AES128-SHA", "IDEA-CBC-SHA", "ECDHE-RSA-AES128-GCM-SHA256"}, "weak": {"TLS_BAR_TLSX_SAYS_WEAK"}}},
	}
	out := Reduce([]tlsx.Event{e}, Defaults())
	want := map[string]string{
		"sslv3":            "legacy.example.com:443 [ssl30]",
		"old-tls":          "legacy.example.com:443 [tls10, tls11]",
		"insecure-cipher":  "legacy.example.com:443 [TLS_DH_anon_WITH_AES_128_CBC_SHA, TLS_FOO_TLSX_SAYS_INSECURE, TLS_RSA_EXPORT_WITH_RC4_40_MD5, TLS_RSA_WITH_NULL_SHA, TLS_RSA_WITH_RC4_128_MD5]",
		"weak-cipher":      "legacy.example.com:443 [TLS_BAR_TLSX_SAYS_WEAK, TLS_RSA_WITH_3DES_EDE_CBC_SHA, TLS_RSA_WITH_IDEA_CBC_SHA]",
		"cbc-old-protocol": "legacy.example.com:443 [ssl30, tls10, tls11]",
	}
	for id, loc := range want {
		if f := finding(out, id); f == nil || f.Locations[0] != loc {
			t.Errorf("%s: %+v, want %s", id, f, loc)
		}
	}
	if g := out.Groups[1]; g.Cipher != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {
		t.Errorf("the negotiated cipher is written by its IANA name: %+v", g)
	}
	// a modern endpoint has no protocol or cipher finding
	if out := Reduce([]tlsx.Event{ev("ok.example.com", "443", "", "fp")}, Defaults()); len(out.Findings) != 0 {
		t.Errorf("modern endpoint: %+v", out.Findings)
	}
}

func TestNegotiatedCipherIsCheckedWithoutEnumeration(t *testing.T) {
	e := ev("a.example.com", "443", "", "fp")
	e.VersionEnum, e.CipherEnum = nil, nil
	e.TLSVersion, e.Cipher = "tls10", "TLS_RSA_WITH_RC4_128_SHA"
	out := Reduce([]tlsx.Event{e}, Defaults())
	for _, id := range []string{"old-tls", "insecure-cipher"} {
		if finding(out, id) == nil {
			t.Errorf("%s from the negotiated version and cipher: %+v", id, out.Findings)
		}
	}
	if g := out.Groups[1]; len(g.Versions) != 0 || len(g.Ciphers) != 0 {
		t.Errorf("no enumeration, no versions or ciphers: %+v", g)
	}
}

func TestFailuresAreGroupedByCause(t *testing.T) {
	retries := `cause="port closed or filtered" address=a.example.com:443 chain="connection refused"; cause="port closed or filtered" address=a.example.com:443`
	a := tlsx.Event{Host: "a.example.com", Port: "443", Error: retries}
	b := tlsx.Event{Host: "b.example.com", Port: "443", Error: `cause="port closed or filtered" address=b.example.com:443`}
	c := tlsx.Event{Host: "c.example.com", Port: "443", Error: "tls: handshake failure"}
	out := Reduce([]tlsx.Event{a, b, c}, Defaults())
	if len(out.Groups) != 2 || out.Groups[0].Error != "port closed or filtered" || len(out.Groups[0].Locations) != 2 || out.Groups[1].Error != "tls: handshake failure" {
		t.Errorf("failures: %+v", out.Groups)
	}
	if out.Failed != 3 || len(out.Findings) != 0 {
		t.Errorf("failed %d findings %v", out.Failed, out.Findings)
	}
}

func TestOutOfScopeResultsAreDropped(t *testing.T) {
	sc, _ := scope.Parse([]string{"*.example.com"})
	opt := Defaults()
	opt.InScope = sc.Allowed
	out := Reduce([]tlsx.Event{ev("a.example.com", "443", "", "fp"), ev("evil.test", "443", "", "fp")}, opt)
	if out.Omitted["out_of_scope"] != 1 || out.Endpoints != 1 || grouped(out, "cert", "evil.test:443") {
		t.Errorf("out of scope: %+v", out)
	}
}

func TestIPv6Location(t *testing.T) {
	out := Reduce([]tlsx.Event{ev("2001:db8::5", "443", "2001:db8::5", "fp")}, Defaults())
	if !grouped(out, "cert", "[2001:db8::5]:443") || out.Groups[0].IP != "" {
		t.Errorf("IPv6: %+v", out.Groups)
	}
}

func TestRankingIsDeterministic(t *testing.T) {
	a := ev("a.example.com", "443", "", "fa")
	a.Wildcard, a.SubjectAN = true, []string{"*.example.com"}
	b := ev("b.example.com", "443", "", "fb")
	b.SelfSigned = true
	c := ev("c.example.com", "443", "", "fc")
	c.Mismatched, c.SelfSigned = true, true
	d := ev("d.example.com", "443", "", "fd")
	d.Expired = true
	for i := 0; i < 5; i++ {
		out := Reduce([]tlsx.Event{a, b, c, d}, Defaults())
		var ids []string
		for _, f := range out.Findings {
			ids = append(ids, f.ID)
		}
		// severity first, then the number of locations, then the id
		if got := strings.Join(ids, ","); got != "expired-cert,self-signed,mismatched,wildcard-cert" {
			t.Fatalf("order: %s", got)
		}
	}
}

func TestMaxItemsIsCounted(t *testing.T) {
	a := ev("a.example.com", "443", "", "fa")
	a.Expired, a.SelfSigned, a.Mismatched = true, true, true
	opt := Defaults()
	opt.MaxItems = 1
	out := Reduce([]tlsx.Event{a}, opt)
	if len(out.Findings) != 1 || out.Omitted["findings"] != 2 || len(out.AllLocations) != 3 {
		t.Errorf("max items: %+v", out)
	}
}

func TestFitCutsGroupsBeforeFindings(t *testing.T) {
	var events []tlsx.Event
	for _, h := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		e := ev(h+".example.com", "443", "10.0.0.1", "fp-"+h)
		e.Expired = true
		events = append(events, e)
	}
	out := Reduce(events, Defaults())
	res := schema.Result{Tool: "raijin-tls", Findings: out.Findings, Groups: out.Groups, Omitted: out.Omitted}
	Fit(&res, 700)
	if size(res) > 700 || !res.Budget.Truncated {
		t.Fatalf("size %d truncated %v", size(res), res.Budget.Truncated)
	}
	if len(res.Findings) != 1 || len(res.Findings[0].Locations) != 8 {
		t.Errorf("the finding keeps every location while groups are cut: %+v", res.Findings)
	}
	if res.Omitted["groups"]+res.Omitted["locations"] == 0 {
		t.Errorf("cuts are counted: %v", res.Omitted)
	}
}

func TestSampleIsLossless(t *testing.T) {
	f, err := os.Open("../../testdata/sample.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	events, err := tlsx.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	sc, _ := scope.Parse([]string{"*.example.com", "10.0.0.0/8", "2001:db8::/32"})
	opt := Defaults()
	opt.InScope = sc.Allowed
	out := Reduce(events, opt)
	if out.Endpoints+out.Omitted["duplicates"]+out.Omitted["out_of_scope"] != len(events) {
		t.Errorf("every event is kept, a duplicate or out of scope: %d events, %+v", len(events), out)
	}
	for _, e := range events {
		if !sc.Allowed(e.Host) {
			continue
		}
		loc := Base(e)
		if e.Host == "multi.example.com" {
			loc += " [" + e.IP + "]"
		}
		kind := "cert"
		if !e.ProbeStatus {
			kind = "failed"
		}
		found := false
		for _, g := range out.Groups {
			for _, l := range g.Locations {
				found = found || strings.HasPrefix(g.ID, kind+"-") && (l == loc || l == loc+" ["+e.IP+"]")
			}
		}
		if !found {
			t.Errorf("%s is not in a %s group", loc, kind)
		}
	}
}
