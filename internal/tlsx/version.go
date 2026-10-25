package tlsx

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"time"
)

var versionRE = regexp.MustCompile(`v?(\d+)\.(\d+)\.(\d+)`)

// Version runs `tlsx -version -duc` (3s at most) and returns the version it prints, or "" when it
// cannot be read. tlsx writes its banner and "[INF] Current version: v1.2.2" to stderr.
func Version(ctx context.Context, bin string) string {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, bin, "-version", "-duc").CombinedOutput()
	return ParseVersion(string(out))
}

// ParseVersion returns the first X.Y.Z in s, without the v, or "".
func ParseVersion(s string) string {
	m := versionRE.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1] + "." + m[2] + "." + m[3]
}

// Untested is true when installed has another major version than tested, or is older. Newer minor and
// patch versions of the same major are not flagged (the weekly drift job tests those), and neither is
// a version that cannot be read.
func Untested(installed, tested string) bool {
	a, b := parts(installed), parts(tested)
	if a == nil || b == nil {
		return false
	}
	if a[0] != b[0] {
		return true
	}
	for i := 1; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func parts(v string) []int {
	m := versionRE.FindStringSubmatch(v)
	if m == nil {
		return nil
	}
	out := make([]int, 3)
	for i := range out {
		out[i], _ = strconv.Atoi(m[i+1])
	}
	return out
}
