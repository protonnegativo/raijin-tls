package raijintls

import "testing"

func TestEnginesHasEveryEngine(t *testing.T) {
	m, err := Engines()
	if err != nil {
		t.Fatal(err)
	}
	// raijin-tls runs one engine: tlsx
	e, ok := m["tlsx"]
	if !ok || e.Version == "" || e.Go == "" {
		t.Fatalf("tlsx entry: %+v", m)
	}
	if got, want := e.Install(), "go install github.com/projectdiscovery/tlsx/cmd/tlsx@v"+e.Version; got != want {
		t.Errorf("install: %s", got)
	}
}
