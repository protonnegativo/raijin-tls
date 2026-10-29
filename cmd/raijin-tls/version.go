package main

import (
	"runtime/debug"
	"sort"
	"strings"

	raijintls "github.com/protonnegativo/raijin-tls"
)

// releaseVersion is set by the release build (-ldflags "-X main.releaseVersion=vX.Y.Z"); it is empty
// for go install and for a local go build.
var releaseVersion string

// version is the release this binary was built as: releaseVersion, else the module version of
// go install ...@vX.Y.Z or @latest, else "dev" with the VCS revision for a local go build.
var version = buildVersion(debug.ReadBuildInfo())

// buildVersion is releaseVersion when set, else Main.Version when it is a module version, else
// "dev-<revision>[+dirty]" from the build settings ("dev" alone when there is no revision).
func buildVersion(info *debug.BuildInfo, ok bool) string {
	if releaseVersion != "" {
		return releaseVersion
	}
	if !ok || info == nil {
		return "dev"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "dev"
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	v := "dev-" + rev
	if dirty {
		v += "+dirty"
	}
	return v
}

// versionLine is what --version prints: the release and the engine versions it was tested with.
func versionLine() string {
	line := "raijin-tls " + version
	engines, err := raijintls.Engines()
	if err != nil || len(engines) == 0 {
		return line
	}
	names := make([]string, 0, len(engines))
	for n := range engines {
		names = append(names, n)
	}
	sort.Strings(names)
	tested := make([]string, len(names))
	for i, n := range names {
		tested[i] = n + " " + engines[n].Version
	}
	return line + " (tested with " + strings.Join(tested, ", ") + ")"
}
