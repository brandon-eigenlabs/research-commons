package smartcard

import (
	"errors"
	"testing"
)

// TestPickReader: a named reader, the only match, none, several.
func TestPickReader(t *testing.T) {
	names := []string{"Yubico YubiKey OTP+FIDO+CCID", "Other Reader 0", "Yubico YubiKey CCID 01"}
	if r, err := PickReader(names[:2], "", "YubiKey"); err != nil || r != names[0] {
		t.Fatalf("only match: %q %v", r, err)
	}
	if _, err := PickReader(names, "", "YubiKey"); !IsSlug(err, Several) {
		t.Fatalf("several: %v", err)
	}
	if r, err := PickReader(names, "CCID 01", "YubiKey"); err != nil || r != names[2] {
		t.Fatalf("named part: %q %v", r, err)
	}
	if r, err := PickReader(names, names[1], "YubiKey"); err != nil || r != names[1] {
		t.Fatalf("named exactly: %q %v", r, err)
	}
	if _, err := PickReader(nil, "", "YubiKey"); !IsSlug(err, NoReader) {
		t.Fatalf("none: %v", err)
	}
	if _, err := PickReader(names[1:2], "", "YubiKey"); !IsSlug(err, NoReader) {
		t.Fatalf("no match: %v", err)
	}
}

// TestCollect: a response the card returns in parts (61 xx) is gathered with GET RESPONSE into one answer.
func TestCollect(t *testing.T) {
	var sent [][]byte
	parts := [][]byte{{1, 2, 0x61, 0x02}, {3, 4, 0x90, 0x00}}
	tx := func(a []byte) ([]byte, error) {
		sent = append(sent, a)
		if len(parts) == 0 {
			return nil, errors.New("no more")
		}
		p := parts[0]
		parts = parts[1:]
		return p, nil
	}
	r, err := collect(tx, []byte{0x00, 0xca, 0x00, 0x6e, 0x00})
	if err != nil || string(r) != string([]byte{1, 2, 3, 4, 0x90, 0x00}) || len(sent) != 2 || sent[1][1] != 0xc0 || sent[1][4] != 2 {
		t.Fatalf("%x %v %x", r, err, sent)
	}
}
