package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDerivableFieldsAreLeftOut(t *testing.T) {
	res := Result{
		Tool:     "raijin-tls",
		Findings: []Finding{{ID: "expired-cert", Title: "Expired certificate", Severity: "high", Locations: []string{"a:443", "b:443"}, Count: 2, Fingerprint: "fp"}},
		Groups:   []Group{{ID: "failed-ab12cd34", Error: "port closed or filtered", Locations: []string{"c:443"}, Count: 1}},
		Omitted:  map[string]int{},
		Errors:   []Error{},
		Next:     []string{},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000},
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"fingerprint", "count", "confidence", "cipher", "versions", "ciphers", "cert", "client_cert", "jarm", "ja3s", "ip", "new", "omitted", "errors", "next", "raw", "budget"} {
		if strings.Contains(string(b), `"`+k+`"`) {
			t.Errorf("%s should be left out: %s", k, b)
		}
	}
	if strings.Contains(string(b), "null") {
		t.Errorf("no null values: %s", b)
	}
}

func TestGroupFieldsInOrder(t *testing.T) {
	g := Group{ID: "tls-x", Version: "tls13", Cipher: "TLS_AES_128_GCM_SHA256", Versions: []string{"tls12", "tls13"},
		Ciphers: map[string][]string{"tls12": {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}}, IP: "10.0.0.1", Locations: []string{"a:443"}, Count: 1}
	b, _ := json.Marshal(g)
	want := `{"id":"tls-x","version":"tls13","cipher":"TLS_AES_128_GCM_SHA256","versions":["tls12","tls13"],"ciphers":{"tls12":["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]},"ip":"10.0.0.1","locations":["a:443"]}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
	c := Group{ID: "cert-ab", Cert: &Cert{SHA256: "ab", Subject: "CN=a", Issuer: "CN=CA", NotAfter: "2027-01-01T00:00:00Z"}, Locations: []string{"a:443"}}
	b, _ = json.Marshal(c)
	want = `{"id":"cert-ab","cert":{"sha256":"ab","subject":"CN=a","issuer":"CN=CA","not_after":"2027-01-01T00:00:00Z"},"locations":["a:443"]}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}

func TestCountAndBudgetAppearWhenSomethingIsCut(t *testing.T) {
	res := Result{
		Findings: []Finding{{ID: "old-tls", Locations: []string{"a:443"}, Count: 7}},
		Groups:   []Group{{ID: "cert-y", Count: 4}},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000, Truncated: true},
	}
	b, _ := json.Marshal(res)
	s := string(b)
	if !strings.Contains(s, `"locations":["a:443"],"count":7`) || !strings.Contains(s, `{"id":"cert-y","count":4}`) {
		t.Errorf("count must be written when locations were cut: %s", s)
	}
	if !strings.Contains(s, `"budget":{"max_items":20,"max_bytes":8000,"truncated":true}`) || strings.Count(s, "budget") != 1 {
		t.Errorf("budget must be written once when something was cut: %s", s)
	}
}
