// Package yubikey is a connector to a YubiKey's OpenPGP applet for the signature the identity profile requires
// (identity note §8, "YubiKey 5, tested by hand"; #250, #270): the card's raw signature primitive, never an OpenPGP
// packet. It reads the signature key's algorithm, public key and touch policy and the PIN policy, verifies the user
// PIN, and asks the card to sign. For ed25519 the card signs the PAE itself; for eip191-secp256k1 the caller hands it
// the 32-byte EIP-191 digest. It signs nothing itself and trusts nothing the card returns: the caller verifies every
// signature with the reader's own rule before using it.
package yubikey

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/research-common/research-commons/internal/sig"
	"github.com/research-common/research-commons/internal/smartcard"
)

// Error is a typed connector failure. Slug is a stable token; SW is the status word when the card sent one.
type Error struct {
	Slug   string
	SW     uint16
	Detail string
}

func (e *Error) Error() string {
	s := e.Slug + ": " + e.Detail
	if e.SW != 0 {
		s += " (status word " + SWText(e.SW) + ")"
	}
	return s
}

// SWText is a status word as four hex digits.
func SWText(sw uint16) string {
	return hex.EncodeToString([]byte{byte(sw >> 8), byte(sw)})
}

// IsSlug reports whether err is an *Error with that slug.
func IsSlug(err error, slug string) bool {
	var e *Error
	return errors.As(err, &e) && e.Slug == slug
}

// Failure slugs.
const (
	NoApplet   = "yubikey-no-openpgp"   // the card has no OpenPGP applet (or it is disabled)
	NoKey      = "yubikey-no-key"       // the signature slot holds no key
	Unsupport  = "yubikey-unsupported"  // the signature key's algorithm is neither Ed25519 nor secp256k1
	PINNeeded  = "yubikey-pin-needed"   // the card wants the user PIN (6982)
	PINWrong   = "yubikey-pin-wrong"    // the PIN was refused; Detail says how many tries are left
	PINBlocked = "yubikey-pin-blocked"  // no PIN tries are left (6983): the card must be unblocked with ykman
	NoTouch    = "yubikey-no-touch"     // the card waited for a touch and got none (6600)
	TooLong    = "yubikey-message-long" // the card cannot hold the message (6700), or it is over the known limit
	BadAnswer  = "yubikey-bad-response" // the card's answer is malformed
	CardError  = "yubikey-card-error"   // any other status word
	Transport  = "yubikey-transport"    // the command could not be carried (a smartcard.Error is wrapped)
)

// Algorithms the profile accepts and the OpenPGP applet offers (#250).
const (
	AlgEd25519   = "ed25519"
	AlgSecp256k1 = "eip191-secp256k1"
)

// MaxEd25519Message is the largest message the card signs with Ed25519 (#270: 3,072 bytes with command chaining,
// refused at 3,073 with 6700, on firmware 5.4.3). A longer PAE is refused before the card is asked.
const MaxEd25519Message = 3072

var (
	aidOpenPGP   = []byte{0xd2, 0x76, 0x00, 0x01, 0x24, 0x01}
	oidEd25519   = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01}
	oidSecp256k1 = []byte{0x2b, 0x81, 0x04, 0x00, 0x0a}
)

// Touch policies (the first byte of the signature key's UIF data object, D6).
const (
	TouchOff         = "off"
	TouchOn          = "on"
	TouchFixed       = "fixed"
	TouchCached      = "cached"
	TouchCachedFixed = "cached-fixed"
)

// State is what the connector reads before it signs: the firmware, the signature key and the policies that decide
// the warnings (#270, conditions 2 and 4).
type State struct {
	Firmware  [3]int // the YubiKey firmware (major, minor, patch)
	Alg       string // AlgEd25519 or AlgSecp256k1
	PublicKey []byte // ed25519: 32 bytes; secp256k1: 65 bytes, uncompressed (04 ‖ x ‖ y)
	Touch     string
	PINOnce   bool // the user PIN is verified once per session for any number of signatures (the factory default)
	PINTries  int  // user PIN tries left
}

// Session is a connected card with the OpenPGP applet selected.
type Session struct {
	card smartcard.Card
}

// NewSession selects the OpenPGP applet on card.
func NewSession(card smartcard.Card) (*Session, error) {
	s := &Session{card: card}
	if _, err := s.cmd(0x00, 0xa4, 0x04, 0x00, aidOpenPGP, true); err != nil {
		if e, ok := err.(*Error); ok && e.SW != 0 {
			return nil, &Error{Slug: NoApplet, SW: e.SW, Detail: "the card has no OpenPGP applet, or it is disabled (ykman config usb --enable OPENPGP)"}
		}
		return nil, err
	}
	return s, nil
}

// cmd sends one APDU (with Le when wantData) and returns the data, or an *Error for any status word but 9000.
func (s *Session) cmd(cla, ins, p1, p2 byte, data []byte, wantData bool) ([]byte, error) {
	apdu := []byte{cla, ins, p1, p2}
	if len(data) > 0 {
		apdu = append(apdu, byte(len(data)))
		apdu = append(apdu, data...)
	}
	if wantData {
		apdu = append(apdu, 0x00)
	}
	r, err := s.card.Transmit(apdu)
	if err != nil {
		return nil, &Error{Slug: Transport, Detail: err.Error()}
	}
	if len(r) < 2 {
		return nil, &Error{Slug: BadAnswer, Detail: "the answer is shorter than a status word"}
	}
	sw := uint16(r[len(r)-2])<<8 | uint16(r[len(r)-1])
	if sw != 0x9000 {
		return nil, swError(sw)
	}
	return r[:len(r)-2], nil
}

func swError(sw uint16) *Error {
	switch {
	case sw == 0x6982:
		return &Error{Slug: PINNeeded, SW: sw, Detail: "the card wants the user PIN"}
	case sw == 0x6983:
		return &Error{Slug: PINBlocked, SW: sw, Detail: "the user PIN is blocked (no tries left): unblock it with ykman openpgp access unblock-pin"}
	case sw&0xfff0 == 0x63c0:
		return &Error{Slug: PINWrong, SW: sw, Detail: "the PIN was refused; " + strconv.Itoa(int(sw&0x0f)) + " tries left"}
	case sw == 0x6600:
		return &Error{Slug: NoTouch, SW: sw, Detail: "the card waited for a touch and got none (about 15 seconds)"}
	case sw == 0x6700:
		return &Error{Slug: TooLong, SW: sw, Detail: "the card cannot hold a message this long"}
	case sw == 0x6a88:
		return &Error{Slug: NoKey, SW: sw, Detail: "the card's OpenPGP signature slot holds no key (generate an Ed25519 key in it with ykman)"}
	}
	return &Error{Slug: CardError, SW: sw, Detail: "the card refused the command"}
}

// tlv finds the value of tag (one or two bytes) in a BER-TLV sequence, descending into constructed values.
func tlv(b []byte, tag uint16) ([]byte, bool) {
	for i := 0; i < len(b); {
		t := uint16(b[i])
		i++
		if t&0x1f == 0x1f { // two-byte tag
			if i >= len(b) {
				return nil, false
			}
			t = t<<8 | uint16(b[i])
			i++
		}
		if i >= len(b) {
			return nil, false
		}
		n := int(b[i])
		i++
		if n&0x80 != 0 {
			k := n & 0x7f
			if k == 0 || k > 2 || i+k > len(b) {
				return nil, false
			}
			n = 0
			for j := 0; j < k; j++ {
				n = n<<8 | int(b[i+j])
			}
			i += k
		}
		if i+n > len(b) {
			return nil, false
		}
		v := b[i : i+n]
		if t == tag {
			return v, true
		}
		constructed := (t>>8 == 0 && t&0x20 != 0) || (t>>8 != 0 && (t>>8)&0x20 != 0)
		if constructed {
			if w, ok := tlv(v, tag); ok {
				return w, true
			}
		}
		i += n
	}
	return nil, false
}

// State reads the firmware, the signature key's algorithm, public key and touch policy, and the PIN policy.
func (s *Session) State() (*State, error) {
	st := &State{}
	if v, err := s.cmd(0x00, 0xf1, 0x00, 0x00, nil, true); err == nil && len(v) >= 3 {
		st.Firmware = [3]int{int(v[0]), int(v[1]), int(v[2])}
	}
	ad, err := s.cmd(0x00, 0xca, 0x00, 0x6e, nil, true)
	if err != nil {
		return nil, err
	}
	// An empty slot is told by reading its public key (6581 on firmware 5.4.3, 6a88 on others), first: it keeps an
	// algorithm (RSA 2048 after a reset or a delete), and its fingerprint in C5 tells nothing, since only an OpenPGP
	// host program (gpg) writes one; a key Yubico's own library generated or imported has an all-zero fingerprint and is
	// still a key (both found in the hand drill on 5.4.3).
	pk, err := s.cmd(0x00, 0x47, 0x81, 0x00, []byte{0xb6, 0x00}, true)
	if err != nil {
		if e, ok := err.(*Error); ok && (e.SW == 0x6a88 || e.SW == 0x6581) {
			return nil, &Error{Slug: NoKey, SW: e.SW, Detail: "the card's OpenPGP signature slot holds no key (generate an Ed25519 key in it with ykman)"}
		}
		return nil, err
	}
	attr, ok := tlv(ad, 0xc1)
	if !ok || len(attr) < 2 {
		return nil, &Error{Slug: BadAnswer, Detail: "the application data has no signature key algorithm"}
	}
	switch oid := attr[1:]; {
	case attr[0] == 0x16 && bytes.HasPrefix(oid, oidEd25519):
		st.Alg = AlgEd25519
	case attr[0] == 0x13 && bytes.HasPrefix(oid, oidSecp256k1):
		st.Alg = AlgSecp256k1
	default:
		return nil, &Error{Slug: Unsupport, Detail: "the signature key's algorithm (" + hex.EncodeToString(attr) + ") is neither Ed25519 nor secp256k1; generate an Ed25519 key in the slot with ykman"}
	}
	pw, ok := tlv(ad, 0xc4)
	if !ok || len(pw) < 7 {
		return nil, &Error{Slug: BadAnswer, Detail: "the application data has no PIN status"}
	}
	st.PINOnce, st.PINTries = pw[0] == 0x01, int(pw[4])
	if uif, err := s.cmd(0x00, 0xca, 0x00, 0xd6, nil, true); err == nil && len(uif) >= 1 {
		st.Touch = map[byte]string{0: TouchOff, 1: TouchOn, 2: TouchFixed, 3: TouchCached, 4: TouchCachedFixed}[uif[0]]
		if st.Touch == "" {
			st.Touch = "unknown (" + hex.EncodeToString(uif[:1]) + ")"
		}
	}
	pt, ok := tlv(pk, 0x86)
	switch {
	case !ok:
		return nil, &Error{Slug: NoKey, Detail: "the card returned no public key for its signature slot"}
	case st.Alg == AlgEd25519 && len(pt) == 32:
	case st.Alg == AlgSecp256k1 && len(pt) == 65 && pt[0] == 0x04:
	default:
		return nil, &Error{Slug: BadAnswer, Detail: "the signature key's public key has an unexpected encoding (" + strconv.Itoa(len(pt)) + " bytes)"}
	}
	st.PublicKey = append([]byte(nil), pt...)
	return st, nil
}

// VerifyPIN presents the user PIN (PW1 for signing, P2 81).
func (s *Session) VerifyPIN(pin []byte) error {
	if len(pin) < 6 || len(pin) > 127 {
		return &Error{Slug: PINWrong, Detail: "a user PIN is 6 to 127 characters; nothing was sent to the card"}
	}
	_, err := s.cmd(0x00, 0x20, 0x00, 0x81, pin, false)
	return err
}

// Sign asks the card to sign data with the signature key (PSO: COMPUTE DIGITAL SIGNATURE), with command chaining so a
// message longer than one short command reaches the card whole. The answer is the raw signature: ed25519 R ‖ S (64
// bytes), secp256k1 r ‖ s (64 bytes).
func (s *Session) Sign(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, &Error{Slug: BadAnswer, Detail: "nothing to sign"}
	}
	for len(data) > 255 {
		if _, err := s.cmd(0x10, 0x2a, 0x9e, 0x9a, data[:255], false); err != nil {
			return nil, err
		}
		data = data[255:]
	}
	sig, err := s.cmd(0x00, 0x2a, 0x9e, 0x9a, data, true)
	if err != nil {
		return nil, err
	}
	if len(sig) != 64 {
		return nil, &Error{Slug: BadAnswer, Detail: "the signature is " + strconv.Itoa(len(sig)) + " bytes, not 64"}
	}
	return sig, nil
}

// Signer is the statement signer of the card's signature key: "ed25519:<hex>" or the "0x<address>" of a secp256k1 key.
func (st *State) Signer() (string, error) {
	switch st.Alg {
	case AlgEd25519:
		return "ed25519:" + hex.EncodeToString(st.PublicKey), nil
	case AlgSecp256k1:
		pub, err := secp256k1.ParsePubKey(st.PublicKey)
		if err != nil {
			return "", &Error{Slug: BadAnswer, Detail: "the card's secp256k1 public key does not parse: " + err.Error()}
		}
		return "0x" + hex.EncodeToString(sig.Address(pub)), nil
	}
	return "", &Error{Slug: Unsupport, Detail: "no signer for " + st.Alg}
}

// SignPAE asks the card for the statement signature over pae, in the encoding the CLI stores: ed25519 128 lowercase hex
// (R ‖ S over the PAE itself); eip191-secp256k1 "0x" + r ‖ s ‖ v over the EIP-191 digest of the PAE, with s made low
// and v recovered against the card's own public key. A signature that does not verify as the card's key is a failure,
// never returned. An Ed25519 PAE over the card's buffer is refused before the card is asked.
func (s *Session) SignPAE(st *State, pae []byte) (string, error) {
	switch st.Alg {
	case AlgEd25519:
		if len(pae) > MaxEd25519Message {
			return "", &Error{Slug: TooLong, Detail: "the PAE is " + strconv.Itoa(len(pae)) + " bytes; the card signs at most " + strconv.Itoa(MaxEd25519Message) + " with Ed25519 (about 22 members in an edition)"}
		}
		rs, err := s.Sign(pae)
		if err != nil {
			return "", err
		}
		if !ed25519.Verify(ed25519.PublicKey(st.PublicKey), pae, rs) {
			return "", &Error{Slug: BadAnswer, Detail: "the card's signature does not verify as its own Ed25519 key"}
		}
		return hex.EncodeToString(rs), nil
	case AlgSecp256k1:
		rs, err := s.Sign(sig.EIP191Hash(pae))
		if err != nil {
			return "", err
		}
		pub, err := secp256k1.ParsePubKey(st.PublicKey)
		if err != nil {
			return "", &Error{Slug: BadAnswer, Detail: "the card's secp256k1 public key does not parse: " + err.Error()}
		}
		want := sig.Address(pub)
		for _, v := range []byte{27, 28} {
			if canon, ok := sig.VerifyEIP191(pae, append(append([]byte{}, rs...), v), want); ok {
				return "0x" + hex.EncodeToString(canon), nil
			}
		}
		return "", &Error{Slug: BadAnswer, Detail: "the card's signature recovers to no key but its own under either v: it does not verify as the card's secp256k1 key"}
	}
	return "", &Error{Slug: Unsupport, Detail: "the card's key is " + st.Alg}
}
