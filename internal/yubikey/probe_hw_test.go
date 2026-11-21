//go:build yubikey_hardware

package yubikey_test

import (
	"encoding/hex"
	"testing"

	"github.com/research-common/research-commons/internal/smartcard"
	"github.com/research-common/research-commons/internal/yubikey"
)

// TestHardwareState reads a real card's state (read-only). go test -tags yubikey_hardware -run TestHardwareState -v
func TestHardwareState(t *testing.T) {
	card, reader, err := smartcard.Open("", "YubiKey")
	if err != nil {
		t.Skip(err)
	}
	defer card.Close()
	s, err := yubikey.NewSession(card)
	if err != nil {
		t.Fatal(err)
	}
	st, err := s.State()
	t.Logf("reader %q", reader)
	if err != nil {
		t.Logf("state: %v", err)
		return
	}
	t.Logf("firmware %v alg %s touch %s pinOnce %v tries %d pub %s", st.Firmware, st.Alg, st.Touch, st.PINOnce, st.PINTries, hex.EncodeToString(st.PublicKey))
}
