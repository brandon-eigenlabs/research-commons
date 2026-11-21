package smartcard

import (
	"os"
	"regexp"
	"slices"
	"testing"
)

// TestPCSCBindingsInStep: every function pcsc_imports_darwin.go imports has an address variable and a trampoline in
// each architecture's assembly, in the same order (as internal/ledger's IOKit bindings are checked).
func TestPCSCBindingsInStep(t *testing.T) {
	read := func(n string) string {
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	all := func(re, s string) []string {
		var out []string
		for _, m := range regexp.MustCompile(re).FindAllStringSubmatch(s, -1) {
			out = append(out, m[1])
		}
		return out
	}
	imp := read("pcsc_imports_darwin.go")
	fns := all(`(?m)^//go:cgo_import_dynamic pcsc_(\w+) (?:\w+) "/System/Library/Frameworks/PCSC\.framework/PCSC"$`, imp)
	if len(fns) != 6 {
		t.Fatalf("%d imports", len(fns))
	}
	if v := all(`(?m)^\tfn(\w+) +uintptr$`, imp); !slices.Equal(v, fns) {
		t.Errorf("variables %v", v)
	}
	for _, a := range []string{"arm64", "amd64"} {
		s := read("pcsc_darwin_" + a + ".s")
		if got := all(`(?m)^TEXT pcsc_(\w+)_trampoline<>\(SB\),NOSPLIT,\$0-0$`, s); !slices.Equal(got, fns) {
			t.Errorf("%s trampolines %v", a, got)
		}
		if got := all(`(?m)^DATA\t·fn(\w+)\(SB\)/8, \$pcsc_\w+_trampoline<>\(SB\)$`, s); !slices.Equal(got, fns) {
			t.Errorf("%s data %v", a, got)
		}
	}
}
