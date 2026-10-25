package tlsx

import (
	"strings"
	"testing"
)

func TestParseAcceptsStringAndNumberPorts(t *testing.T) {
	in := `{"host":"a.example.com","port":"443","probe_status":true}
not json
{"ip":"10.0.0.1","port":8443}
{"port":"1"}
`
	events, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Port != "443" || events[1].Port != "8443" || events[1].Host != "10.0.0.1" {
		t.Errorf("events: %+v", events)
	}
}

func TestArgs(t *testing.T) {
	got := strings.Join(Args("list.txt", Options{Ports: "443,8443", Timeout: 3, Threads: 20, Extra: []string{"-jarm"}}), " ")
	want := "-l list.txt -json -silent -nc -duc -ex -ss -mm -wc -tps -ve -ce -p 443,8443 -timeout 3 -c 20 -jarm"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	if got := strings.Join(Args("l", Options{NoEnum: true}), " "); strings.Contains(got, "-ve") {
		t.Errorf("--no-enum: %s", got)
	}
}

func TestParseVersion(t *testing.T) {
	// tlsx 1.2.2 `-version -duc`, stdout and stderr together: the banner, then the version line
	sample := "  _____ _    _____  __\n |_   _| |  / __\\ \\/ /\n   | | | |__\\__ \\>  < \n   |_| |____|___/_/\\_\\\tv1.2.2\n\n\t\tprojectdiscovery.io\n\n[\x1b[34mINF\x1b[0m] Current version: v1.2.2\n"
	for in, want := range map[string]string{
		sample:                          "1.2.2",
		"[INF] Current version: v1.1.6": "1.1.6",
		"flag provided but not defined": "",
		"":                              "",
	} {
		if got := ParseVersion(in); got != want {
			t.Errorf("ParseVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUntested(t *testing.T) {
	for _, c := range []struct {
		installed string
		want      bool
	}{
		{"1.2.2", false}, {"1.2.3", false}, {"1.9.0", false},
		{"1.2.1", true}, {"1.1.9", true}, {"0.9.9", true}, {"2.0.0", true},
		{"", false}, {"garbage", false},
	} {
		if got := Untested(c.installed, "1.2.2"); got != c.want {
			t.Errorf("Untested(%q, 1.2.2) = %v, want %v", c.installed, got, c.want)
		}
	}
}

func TestFormatCheckRenamedField(t *testing.T) {
	// tls_version renamed to version: the answered line no longer has the essential fields
	in := `{"host":"a.example.com","port":"443","probe_status":true,"version":"tls13","cipher":"TLS_AES_128_GCM_SHA256"}
{"host":"b.example.com","port":"443","probe_status":false,"error":"port closed"}
{"host":"c.example.com","port":"443","probe_status":true,"tls_version":"tls12"}
[INF] not json
`
	events, st, err := ParseCount(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 || st.Lines != 4 || st.Unparsed != 1 || st.Incomplete != 2 {
		t.Errorf("events %d, stats %+v", len(events), st)
	}
	hint := st.FormatHint("raw.jsonl")
	if !strings.HasPrefix(hint, "2 of 4 tlsx results had no host, port and (tls_version or error)") || !strings.HasSuffix(hint, "Read raw.jsonl for the full output") {
		t.Errorf("hint: %s", hint)
	}
	if (Stats{Lines: 3}).FormatHint("x") != "" {
		t.Error("hint without incomplete lines")
	}
}
