package main

import (
	"bytes"
	"regexp"
	"runtime/debug"
	"testing"
)

func TestBuildVersion(t *testing.T) {
	rev := []debug.BuildSetting{{Key: "vcs.revision", Value: "0123456789abcdef0123"}}
	for _, c := range []struct {
		info *debug.BuildInfo
		ok   bool
		want string
	}{
		{nil, false, "dev"},
		{&debug.BuildInfo{Main: debug.Module{Version: "v0.1.3"}}, true, "v0.1.3"},
		{&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, true, "dev"},
		{&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: rev}, true, "dev-0123456789ab"},
		{&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: append(rev, debug.BuildSetting{Key: "vcs.modified", Value: "true"})}, true, "dev-0123456789ab+dirty"},
	} {
		if got := buildVersion(c.info, c.ok); got != c.want {
			t.Errorf("buildVersion(%+v) = %q, want %q", c.info, got, c.want)
		}
	}
}

func TestVersionLine(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--version"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	want := "raijin-tls " + regexp.QuoteMeta(version) + ` \(tested with tlsx ` + regexp.QuoteMeta(testedTLSX(t)) + `\)\n$`
	if !regexp.MustCompile("^" + want).MatchString(out.String()) {
		t.Errorf("--version = %q", out.String())
	}
}
