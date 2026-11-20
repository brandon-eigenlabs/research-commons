package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/ledger"
	"github.com/research-common/research-commons/internal/ledger/ledgertest"
	"github.com/research-common/research-commons/internal/wire"
)

// signRequests counts the personal-sign requests (CLA 0xE0, INS 0x08) the fake received: a review on the device.
func signRequests(dev *ledgertest.App) int {
	n := 0
	for _, a := range dev.Received {
		if len(a) > 1 && a[0] == 0xe0 && a[1] == 0x08 && len(a) > 2 && a[2] == 0x00 {
			n++ // the first chunk of each request
		}
	}
	return n
}

// copyStore copies a store directory, so one history can be signed twice: once on the device, once by its key file.
func copyStore(t *testing.T, from string) string {
	t.Helper()
	to := filepath.Join(t.TempDir(), "store")
	if err := os.CopyFS(to, os.DirFS(from)); err != nil {
		t.Fatal(err)
	}
	return to
}

// TestRevokeLedger (#266, L-22): an identity whose root is the device's key revokes the root on the device. A dry
// run asks the device nothing; a refusal on the device is exit 1 with nothing appended; an approval commits the
// revoke_key, and the committed line is byte-identical to the one the root's key file signs for the same history.
func TestRevokeLedger(t *testing.T) {
	dev := ledgertest.New("revoke")
	h := newLedgerHome(t, dev)
	inc := runIn(h.store, nil, "identity", "new", "--key", h.keyF, "--json")
	if inc.code != ExitOK {
		t.Fatalf("inception: %d %s", inc.code, inc.stdout)
	}
	const ts = "2026-11-20T12:00:00Z"
	args := []string{"revoke", "--ledger", "--ledger-path", ledgerTestPath, "--reason", "key_compromise", "--last-good", "none", "--ts", ts, "--json"}
	twin := copyStore(t, h.store)
	before := storeBytes(t, h.store)

	// dry run: the plan, what the device would show, and no request to the device
	r := runLedger(h.store, dev.Opener(nil), nil, append(args, "--dry-run")...)
	o := jsonOf(t, r)
	if r.code != ExitOK || o.Members["dry_run"] != canon.Bool(true) || o.Members["committed"] != canon.Bool(false) || o.Members["device_shows"] == nil ||
		!strings.Contains(r.stdout, "nothing was sent to the device") ||
		signRequests(dev) != 0 || storeBytes(t, h.store) != before {
		t.Fatalf("dry run: %d %s (sign requests %d)", r.code, r.stdout, signRequests(dev))
	}
	// refused on the device: exit 1, nothing appended
	dev.Reject = true
	r = runLedger(h.store, dev.Opener(nil), nil, args...)
	if r.code != ExitWrong || !strings.Contains(r.stdout, ledger.Rejected) || storeBytes(t, h.store) != before || signRequests(dev) != 1 {
		t.Fatalf("rejected: %d %s", r.code, r.stdout)
	}
	// approved: the revocation is committed, and it is the line the key file signs
	dev.Reject = false
	r = runLedger(h.store, dev.Opener(nil), nil, args...)
	if r.code != ExitOK || !strings.Contains(r.stdout, `"committed":true`) || jsonOf(t, r).Members["device"] == nil {
		t.Fatalf("approved: %d %s", r.code, r.stdout)
	}
	id := firstID(t, jsonOf(t, r))
	k := runIn(twin, nil, "revoke", "--key", h.keyF, "--reason", "key_compromise", "--last-good", "none", "--ts", ts, "--json")
	if k.code != ExitOK {
		t.Fatalf("key file twin: %d %s", k.code, k.stdout)
	}
	if kid := firstID(t, jsonOf(t, k)); kid != id || lineOf(t, h.store, id) != lineOf(t, twin, kid) {
		t.Fatalf("the device's revocation differs from the key file's:\n%s\n%s", lineOf(t, h.store, id), lineOf(t, twin, kid))
	}
	if !strings.Contains(lineOf(t, h.store, id), `"kind":"revoke_key"`) {
		t.Fatalf("not a revoke_key: %s", lineOf(t, h.store, id))
	}
	// the store is sound after it
	if f := runIn(h.store, nil, "fsck", "--json"); f.code != ExitOK {
		t.Fatalf("fsck: %d %s", f.code, f.stdout)
	}
}

// TestRotateLedger: the device's key rotates to a successor on the device; the line equals the key file's; naming
// the device's own key as the successor is refused once the device's key is known (exit 2, nothing asked).
func TestRotateLedger(t *testing.T) {
	dev := ledgertest.New("rotate")
	h := newLedgerHome(t, dev)
	if r := runIn(h.store, nil, "publish", "--kind", "describes", "--of", strings.Repeat("a", 64), "--key", h.keyF, "--json"); r.code != ExitOK {
		// any first line of the device key's log will do; fall back to an inception when describes needs more
		if r2 := runIn(h.store, nil, "identity", "new", "--key", h.keyF, "--json"); r2.code != ExitOK {
			t.Fatalf("first line: %d %s / %d %s", r.code, r.stdout, r2.code, r2.stdout)
		}
	}
	succ, _ := newKeyFile(t, t.TempDir(), wire.AlgEd25519)
	const ts = "2026-11-20T12:00:00Z"
	twin := copyStore(t, h.store)
	r := runLedger(h.store, dev.Opener(nil), nil, "rotate", "--ledger", "--ledger-path", ledgerTestPath, "--successor-key", succ, "--ts", ts, "--json")
	if r.code != ExitOK || !strings.Contains(r.stdout, `"committed":true`) {
		t.Fatalf("rotate: %d %s", r.code, r.stdout)
	}
	id := firstID(t, jsonOf(t, r))
	k := runIn(twin, nil, "rotate", "--key", h.keyF, "--successor-key", succ, "--ts", ts, "--json")
	if k.code != ExitOK || lineOf(t, h.store, id) != lineOf(t, twin, firstID(t, jsonOf(t, k))) {
		t.Fatalf("the device's rotation differs from the key file's: %d %s", k.code, k.stdout)
	}
	// the device's own key as its successor
	asked := signRequests(dev)
	p, _ := ledger.ParsePath(ledgerTestPath)
	r = runLedger(h.store, dev.Opener(nil), nil, "rotate", "--ledger", "--ledger-path", ledgerTestPath, "--successor", dev.AddressAt(p), "--json")
	if r.code != ExitDidNotStart || !strings.Contains(r.stdout, "the successor is the signing key itself") || signRequests(dev) != asked {
		t.Fatalf("self successor: %d %s", r.code, r.stdout)
	}
}

// TestKeyEventLedgerOptions: --ledger and --key together, a device option without --ledger, --ledger without a path,
// and a build without the connector are refused before anything is signed.
func TestKeyEventLedgerOptions(t *testing.T) {
	dev := ledgertest.New("opts")
	h := newLedgerHome(t, dev)
	if r := runIn(h.store, nil, "identity", "new", "--key", h.keyF, "--json"); r.code != ExitOK {
		t.Fatal(r.stdout)
	}
	before := storeBytes(t, h.store)
	base := []string{"revoke", "--reason", "superseded", "--json"}
	for name, c := range map[string]struct {
		open LedgerOpener
		args []string
		code int
		want string
	}{
		"ledger and key": {dev.Opener(nil), []string{"--ledger", "--ledger-path", ledgerTestPath, "--key", h.keyF}, ExitDidNotStart, "two signers"},
		"path alone":     {dev.Opener(nil), []string{"--ledger-path", ledgerTestPath}, ExitDidNotStart, "goes with --ledger"},
		"no path":        {dev.Opener(nil), []string{"--ledger"}, ExitDidNotStart, "--ledger-path is missing"},
		"not built":      {nil, []string{"--ledger", "--ledger-path", ledgerTestPath}, ExitCouldNot, "not available in this build"},
	} {
		r := runLedger(h.store, c.open, nil, append(base, c.args...)...)
		if r.code != c.code || !strings.Contains(r.stdout, c.want) || storeBytes(t, h.store) != before {
			t.Errorf("%s: %d %s", name, r.code, r.stdout)
		}
	}
	if signRequests(dev) != 0 {
		t.Fatal("a refused invocation asked the device to sign")
	}
}
