package images

import (
	"testing"

	"emberboot/internal/iscsisrv"
)

// The images package mirrors iscsisrv's suffix sanitizer to avoid an import
// cycle; this test keeps the two implementations in lock step.
func TestTargetSuffixMatchesISCSISanitizer(t *testing.T) {
	for _, name := range []string{
		"ubuntu-24.04-live-server-amd64.iso",
		"Win11_24H2 English x64.ISO",
		"debian-12.5.0-amd64-netinst.iso",
		"WEIRD  (copy) [1].iso",
	} {
		if a, b := TargetSuffix(name), iscsisrv.SanitizeSuffix(name); a != b {
			t.Errorf("sanitizers diverged for %q: images=%q iscsisrv=%q", name, a, b)
		}
	}
}
