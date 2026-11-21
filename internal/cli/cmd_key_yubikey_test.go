package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/smartcard"
	"github.com/research-common/research-commons/internal/yubikey"
	"github.com/research-common/research-commons/internal/yubikey/yubikeytest"
)

// runYubiKey runs args in wd with the fake card (nil: a build without the connector) and a PIN reader answering pin
// (nil: no terminal).
func runYubiKey(wd string, card *yubikeytest.Card, pin *string, args ...string) result {
	var o, e bytes.Buffer
	env := &Env{Stdout: &o, Stderr: &e, Getenv: func(string) string { return "" }, Getwd: func() (string, error) { return wd, nil },
		Build: Build{Version: "test", Commit: "0000000"}}
	if card != nil {
		env.YubiKey = func(reader string) (smartcard.Card, string, error) {
			if reader != "" && reader != "Fake YubiKey" {
				return nil, "", &smartcard.Error{Slug: smartcard.NoReader, Detail: "no reader matches " + reader}
			}
			card.Reopen()
			return card, "Fake YubiKey", nil
		}
	}
	if pin != nil {
		env.ReadPIN = func(string) ([]byte, error) { return []byte(*pin), nil }
	}
	return result{Main(args, env), o.String(), e.String()}
}

func cardSigner(t *testing.T, card *yubikeytest.Card) string {
	t.Helper()
	r := runYubiKey(t.TempDir(), card, nil, "key", "show", "--yubikey", "--json")
	if r.code != ExitOK {
		t.Fatalf("key show: %d %s", r.code, r.stdout)
	}
	return string(jsonOf(t, r).Members["signer"].(canon.String))
}

// TestYubiKeyShow: the card's signer, algorithm and policies, with the warnings the conditions ask for (#270: touch
// off or cached, PIN once, secp256k1 before firmware 5.7).
func TestYubiKeyShow(t *testing.T) {
	card := yubikeytest.New("show")
	r := runYubiKey(t.TempDir(), card, nil, "key", "show", "--yubikey", "--json")
	o := jsonOf(t, r)
	if r.code != ExitOK || !strings.HasPrefix(string(o.Members["signer"].(canon.String)), "ed25519:") || o.Members["alg"] != canon.String("ed25519") {
		t.Fatalf("%d %s", r.code, r.stdout)
	}
	if !strings.Contains(r.stdout, "touch is off") || !strings.Contains(r.stdout, "PIN policy is once") || strings.Contains(r.stdout, "YSA-2024-03") {
		t.Fatalf("ed25519 warnings: %s", r.stdout)
	}
	card = yubikeytest.New("k1")
	card.Alg, card.Touch, card.PINAlways = yubikey.AlgSecp256k1, 3, true
	r = runYubiKey(t.TempDir(), card, nil, "key", "show", "--yubikey", "--json")
	if r.code != ExitOK || !strings.HasPrefix(r.stdout, `{"alg":"eip191-secp256k1"`) || !strings.Contains(r.stdout, "touch is cached") ||
		!strings.Contains(r.stdout, "YSA-2024-03") || strings.Contains(r.stdout, "PIN policy is once") {
		t.Fatalf("secp256k1 cached: %s", r.stdout)
	}
	card.Firmware, card.Touch = [3]byte{5, 7, 2}, 1
	if r = runYubiKey(t.TempDir(), card, nil, "key", "show", "--yubikey", "--json"); strings.Contains(r.stdout, "warnings") {
		t.Fatalf("firmware 5.7, touch on, PIN always: no warning expected: %s", r.stdout)
	}
	// option conflicts and a build without the connector
	for name, c := range map[string]struct {
		card *yubikeytest.Card
		args []string
		code int
	}{
		"with a file":    {card, []string{"key", "show", "some.key", "--yubikey"}, ExitDidNotStart},
		"reader alone":   {card, []string{"key", "show", "--yubikey-reader", "x"}, ExitDidNotStart},
		"with ledger":    {card, []string{"key", "show", "--yubikey", "--ledger", "--ledger-path", "m/44'/60'/0'/0/0"}, ExitDidNotStart},
		"not built":      {nil, []string{"key", "show", "--yubikey"}, ExitCouldNot},
		"no such reader": {card, []string{"key", "show", "--yubikey", "--yubikey-reader", "other"}, ExitCouldNot},
	} {
		if r := runYubiKey(t.TempDir(), c.card, nil, append(c.args, "--json")...); r.code != c.code {
			t.Errorf("%s: %d %s", name, r.code, r.stdout)
		}
	}
}

// TestYubiKeySignFlow: an inception prepared for the card's key is signed on the card and completed; the store's
// reader verifies it. Both algorithms.
func TestYubiKeySignFlow(t *testing.T) {
	for _, alg := range []string{yubikey.AlgEd25519, yubikey.AlgSecp256k1} {
		card := yubikeytest.New("flow-" + alg)
		card.Alg = alg
		signer := cardSigner(t, card)
		store := drillStore(t)
		dir := t.TempDir()
		pkg := filepath.Join(dir, "inc.pkg")
		if r := runIn(store, nil, "identity", "new", "--prepare", pkg, "--signer", signer, "--json"); r.code != ExitOK {
			t.Fatalf("%s prepare: %d %s", alg, r.code, r.stdout)
		}
		pin := "123456"
		sigF := filepath.Join(dir, "sig")
		// a dry run asks for no PIN and signs nothing
		r := runYubiKey(dir, card, nil, "key", "sign", "--package", pkg, "--yubikey", "--dry-run", "--json")
		if r.code != ExitOK || card.Asked != 0 || !strings.Contains(r.stdout, `"signed":false`) {
			t.Fatalf("%s dry run: %d %s", alg, r.code, r.stdout)
		}
		r = runYubiKey(dir, card, &pin, "key", "sign", "--package", pkg, "--yubikey", "--out", sigF, "--json")
		if r.code != ExitOK || card.Signed != 1 || !strings.Contains(r.stderr, "commons: warning: touch is off") {
			t.Fatalf("%s sign: %d %s %s", alg, r.code, r.stdout, r.stderr)
		}
		if c := runIn(store, nil, "identity", "new", "--complete", pkg, "--signature", sigF, "--json"); c.code != ExitOK || !strings.Contains(c.stdout, `"committed":true`) {
			t.Fatalf("%s complete: %d %s", alg, c.code, c.stdout)
		}
		if f := runIn(store, nil, "fsck", "--json"); f.code != ExitOK {
			t.Fatalf("%s fsck: %d %s", alg, f.code, f.stdout)
		}
	}
}

// TestYubiKeySignRefusals: every refusal writes nothing; a refused PIN is exit 1, a device failure exit 3, a request
// that cannot start exit 2.
func TestYubiKeySignRefusals(t *testing.T) {
	card := yubikeytest.New("refuse")
	signer := cardSigner(t, card)
	store := drillStore(t)
	dir := t.TempDir()
	pkg := filepath.Join(dir, "inc.pkg")
	if r := runIn(store, nil, "identity", "new", "--prepare", pkg, "--signer", signer, "--json"); r.code != ExitOK {
		t.Fatal(r.stdout)
	}
	other := yubikeytest.New("another card")
	good, wrong := "123456", "000000"
	for name, c := range map[string]struct {
		card  *yubikeytest.Card
		pin   *string
		set   func(*yubikeytest.Card)
		code  int
		want  string
		extra []string
	}{
		"another card's key": {other, &good, nil, ExitDidNotStart, "key-not-signer", nil},
		"no terminal":        {card, nil, nil, ExitDidNotStart, "no-terminal", nil},
		"wrong PIN":          {card, &wrong, nil, ExitWrong, yubikey.PINWrong, nil},
		"no touch":           {card, &good, func(c *yubikeytest.Card) { c.Touch = 1 }, ExitCouldNot, yubikey.NoTouch, nil},
		"signs as another":   {card, &good, func(c *yubikeytest.Card) { c.Form = yubikeytest.OtherKey }, ExitCouldNot, yubikey.BadAnswer, nil},
		"card removed":       {card, &good, func(c *yubikeytest.Card) { c.Removed = true }, ExitCouldNot, "yubikey", nil},
		"with a key file":    {card, &good, nil, ExitDidNotStart, "two signers", []string{"--key", filepath.Join(dir, "k")}},
	} {
		c.card.Tries, c.card.Touch, c.card.Form, c.card.Removed = 3, 0, yubikeytest.Good, false
		if c.set != nil {
			c.set(c.card)
		}
		out := filepath.Join(t.TempDir(), "sig")
		r := runYubiKey(dir, c.card, c.pin, append([]string{"key", "sign", "--package", pkg, "--yubikey", "--out", out, "--json"}, c.extra...)...)
		if r.code != c.code || !strings.Contains(r.stdout, c.want) {
			t.Errorf("%s: %d %s", name, r.code, r.stdout)
		}
		if exists(out) {
			t.Errorf("%s: a signature file was written", name)
		}
	}
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return !errors.Is(err, os.ErrNotExist)
}
