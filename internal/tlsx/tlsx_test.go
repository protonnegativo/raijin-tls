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
