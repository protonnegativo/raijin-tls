// Package raijintls holds the engine versions raijin-tls was tested with (engines.json), embedded in
// the binary so a run can warn when the installed engine differs.
package raijintls

import (
	_ "embed"
	"encoding/json"
)

//go:embed engines.json
var enginesJSON []byte

// Engine is one entry of engines.json: the tested version and where to install it from (one of Go, Pip,
// System).
type Engine struct {
	Version string `json:"version"`
	Go      string `json:"go,omitempty"`
	Pip     string `json:"pip,omitempty"`
	System  string `json:"system,omitempty"`
}

// Install is the command that installs the tested version.
func (e Engine) Install() string {
	switch {
	case e.Go != "":
		return "go install " + e.Go + "@v" + e.Version
	case e.Pip != "":
		return "pipx install " + e.Pip + "==" + e.Version
	case e.System != "":
		return "install " + e.System + " " + e.Version + " with the system package manager"
	}
	return ""
}

// Engines parses the embedded engines.json.
func Engines() (map[string]Engine, error) {
	var m map[string]Engine
	err := json.Unmarshal(enginesJSON, &m)
	return m, err
}
