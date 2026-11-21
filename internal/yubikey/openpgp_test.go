package yubikey_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/sig"
	"github.com/research-common/research-commons/internal/yubikey"
	"github.com/research-common/research-commons/internal/yubikey/yubikeytest"
)

func session(t *testing.T, c *yubikeytest.Card) (*yubikey.Session, *yubikey.State) {
	t.Helper()
	s, err := yubikey.NewSession(c)
	if err != nil {
		t.Fatal(err)
	}
	st, err := s.State()
	if err != nil {
		t.Fatal(err)
	}
	return s, st
}

// TestStateAndSignBothAlgorithms: the state reads the algorithm, the public key, the policies and the firmware; the
// signature over a multi-command PAE (command chaining) verifies as the card's key in the CLI's encoding.
func TestStateAndSignBothAlgorithms(t *testing.T) {
	pae := bytes.Repeat([]byte("DSSEv1 "), 150) // 1,050 bytes: five chained commands
	for _, alg := range []string{yubikey.AlgEd25519, yubikey.AlgSecp256k1} {
		c := yubikeytest.New("both")
		c.Alg = alg
		s, st := session(t, c)
		if st.Alg != alg || st.Firmware != [3]int{5, 4, 3} || st.Touch != yubikey.TouchOff || !st.PINOnce || st.PINTries != 3 {
			t.Fatalf("%s: state %+v", alg, st)
		}
		if err := s.VerifyPIN([]byte("123456")); err != nil {
			t.Fatal(err)
		}
		got, err := s.SignPAE(st, pae)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		signer, _ := st.Signer()
		switch alg {
		case yubikey.AlgEd25519:
			raw, _ := hex.DecodeString(got)
			if len(got) != 128 || !ed25519.Verify(c.Ed25519Public(), pae, raw) || signer != "ed25519:"+hex.EncodeToString(c.Ed25519Public()) {
				t.Fatalf("ed25519: %s %s", got, signer)
			}
		default:
			raw, _ := hex.DecodeString(got[2:])
			want, _ := hex.DecodeString(signer[2:])
			if !strings.HasPrefix(got, "0x") || len(got) != 132 {
				t.Fatalf("eip191 form: %s", got)
			}
			if canon, ok := sig.VerifyEIP191(pae, raw, want); !ok || !bytes.Equal(canon, raw) {
				t.Fatal("eip191: the signature does not verify as the card's address, or is not canonical")
			}
		}
	}
}

// TestRefusals: every failure is typed and nothing is returned as a signature.
func TestRefusals(t *testing.T) {
	pae := []byte("DSSEv1 short message")
	cases := map[string]struct {
		set  func(*yubikeytest.Card)
		pin  string
		slug string
	}{
		"no PIN":           {func(c *yubikeytest.Card) {}, "", yubikey.PINNeeded},
		"wrong PIN":        {func(c *yubikeytest.Card) {}, "654321", yubikey.PINWrong},
		"blocked":          {func(c *yubikeytest.Card) { c.Tries = 0 }, "123456", yubikey.PINBlocked},
		"no touch":         {func(c *yubikeytest.Card) { c.Touch = 1 }, "123456", yubikey.NoTouch},
		"another key":      {func(c *yubikeytest.Card) { c.Form = yubikeytest.OtherKey }, "123456", yubikey.BadAnswer},
		"garbage":          {func(c *yubikeytest.Card) { c.Form = yubikeytest.Garbage }, "123456", yubikey.BadAnswer},
		"short signature":  {func(c *yubikeytest.Card) { c.Form = yubikeytest.ShortSig }, "123456", yubikey.BadAnswer},
		"card buffer":      {func(c *yubikeytest.Card) { c.MaxMessage = 10 }, "123456", yubikey.TooLong},
		"another key k1":   {func(c *yubikeytest.Card) { c.Alg = yubikey.AlgSecp256k1; c.Form = yubikeytest.OtherKey }, "123456", yubikey.BadAnswer},
		"removed mid-sign": {func(c *yubikeytest.Card) { c.Removed = true }, "", yubikey.Transport},
	}
	for name, cs := range cases {
		c := yubikeytest.New("refuse")
		s, st := session(t, c)
		cs.set(c)
		if cs.pin != "" {
			if err := s.VerifyPIN([]byte(cs.pin)); err != nil {
				if yubikey.IsSlug(err, cs.slug) {
					continue
				}
				t.Errorf("%s: verify: %v", name, err)
				continue
			}
		}
		if c.Alg != st.Alg {
			_, st = session(t, c) // the algorithm changed: read the state again
			if cs.pin != "" {
				s, _ = yubikey.NewSession(c)
				s.VerifyPIN([]byte(cs.pin))
			}
		}
		got, err := s.SignPAE(st, pae)
		if !yubikey.IsSlug(err, cs.slug) || got != "" {
			t.Errorf("%s: %q %v, want %s", name, got, err, cs.slug)
		}
	}
	// a PIN outside 6..127 is refused without a try spent
	c := yubikeytest.New("short-pin")
	s, _ := session(t, c)
	if err := s.VerifyPIN([]byte("123")); !yubikey.IsSlug(err, yubikey.PINWrong) || c.Tries != 3 {
		t.Fatalf("short PIN: %v, tries %d", err, c.Tries)
	}
	// an Ed25519 PAE over the card's buffer is refused before the card is asked
	c = yubikeytest.New("long")
	s, st := session(t, c)
	s.VerifyPIN([]byte("123456"))
	if _, err := s.SignPAE(st, make([]byte, yubikey.MaxEd25519Message+1)); !yubikey.IsSlug(err, yubikey.TooLong) || c.Asked != 0 {
		t.Fatalf("long: %v, asked %d", err, c.Asked)
	}
	if _, err := s.SignPAE(st, bytes.Repeat([]byte("a"), yubikey.MaxEd25519Message)); err != nil || c.Signed != 1 {
		t.Fatalf("at the limit: %v", err)
	}
}

// TestStateErrors: an empty slot, no applet, an unsupported algorithm; the touch and PIN policies read back.
func TestStateErrors(t *testing.T) {
	c := yubikeytest.New("empty")
	c.Alg = ""
	s, err := yubikey.NewSession(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.State(); !yubikey.IsSlug(err, yubikey.NoKey) {
		t.Fatalf("empty slot: %v", err)
	}
	// a key with no fingerprint (generated or imported by Yubico's library, not gpg) is a key; one gpg fingerprinted is too
	for _, fp := range []bool{false, true} {
		c = yubikeytest.New("fingerprint")
		c.Fingerprinted = fp
		if _, st := session(t, c); st.Alg != yubikey.AlgEd25519 || len(st.PublicKey) != 32 {
			t.Fatalf("fingerprinted=%v: %+v", fp, st)
		}
	}
	c = yubikeytest.New("noapplet")
	c.NoApplet = true
	if _, err := yubikey.NewSession(c); !yubikey.IsSlug(err, yubikey.NoApplet) {
		t.Fatalf("no applet: %v", err)
	}
	for b, want := range map[byte]string{0: yubikey.TouchOff, 1: yubikey.TouchOn, 2: yubikey.TouchFixed, 3: yubikey.TouchCached, 4: yubikey.TouchCachedFixed} {
		c = yubikeytest.New("touch")
		c.Touch = b
		if _, st := session(t, c); st.Touch != want {
			t.Errorf("touch %d: %s", b, st.Touch)
		}
	}
	c = yubikeytest.New("always")
	c.PINAlways = true
	if _, st := session(t, c); st.PINOnce {
		t.Fatal("PIN policy always read as once")
	}
}
