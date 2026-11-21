// Package yubikeytest is an in-process fake of a YubiKey's OpenPGP applet, for tests (#270, condition 6): it answers
// the commands internal/yubikey sends the way the card does (measured in #250 and #270 on firmware 5.4.3), signs
// with a throwaway key, and can be told to hold a touch, refuse a PIN, return another key's signature, or go away.
package yubikeytest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"sync"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// SigForm is how the fake answers a signing request.
type SigForm int

const (
	Good     SigForm = iota // a signature by the slot's key over the data
	OtherKey                // a valid signature by another key
	Garbage                 // 64 bytes that are not a signature
	ShortSig                // 63 bytes
)

// Card is the fake. Use New.
type Card struct {
	mu sync.Mutex
	// Alg is "ed25519" or "eip191-secp256k1"; "" is an empty slot.
	Alg string
	// Seed derives the slot's key: sha256(seed).
	Seed string
	// Firmware is what the version command answers.
	Firmware [3]byte
	// Touch is the UIF policy byte: 0 off, 1 on, 2 fixed, 3 cached, 4 cached-fixed.
	Touch byte
	// Touched: the holder touches the card when it asks (false: a request under a touch policy fails with 6600).
	Touched bool
	// PINAlways: the PIN must be presented before every signature (PW1 status byte 00); else once per session.
	PINAlways bool
	// PIN is the user PIN; Tries the tries left.
	PIN   string
	Tries int
	// Form is how a signature request is answered.
	Form SigForm
	// MaxMessage is the card's buffer for an Ed25519 message (3,072 on 5.4.3).
	MaxMessage int
	// Removed: every command fails as a transport error.
	Removed bool
	// NoApplet: SELECT of the OpenPGP applet fails (6a82).
	NoApplet bool
	// Fingerprinted: the slot's fingerprint in C5 is set, as gpg writes it; false (the default) leaves it all zero,
	// as for a key Yubico's library generated or imported (5.4.3).
	Fingerprinted bool

	verified bool
	chain    []byte
	// Signed counts the signatures the card made; Asked the signing requests it received.
	Signed, Asked int
	closed        bool
}

// New is a card with an Ed25519 key from seed, touch off, the factory PIN policy (once) and PIN 123456.
func New(seed string) *Card {
	return &Card{Alg: "ed25519", Seed: seed, Firmware: [3]byte{5, 4, 3}, PIN: "123456", Tries: 3, MaxMessage: 3072}
}

func (c *Card) scalar() []byte {
	h := sha256.Sum256([]byte("yubikeytest " + c.Seed))
	return h[:]
}

// Ed25519Public is the slot's Ed25519 public key.
func (c *Card) Ed25519Public() ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(c.scalar()).Public().(ed25519.PublicKey)
}

// Secp256k1Public is the slot's secp256k1 public key, uncompressed.
func (c *Card) Secp256k1Public() []byte {
	return secp256k1.PrivKeyFromBytes(c.scalar()).PubKey().SerializeUncompressed()
}

func sw(b ...byte) []byte { return b }

func ok(data ...byte) []byte { return append(append([]byte{}, data...), 0x90, 0x00) }

// Transmit answers one APDU.
func (c *Card) Transmit(apdu []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Removed || c.closed {
		return nil, errors.New("the card went away")
	}
	if len(apdu) < 4 {
		return sw(0x67, 0x00), nil
	}
	cla, ins, p1, p2 := apdu[0], apdu[1], apdu[2], apdu[3]
	var data []byte
	if len(apdu) > 5 {
		n := int(apdu[4])
		if 5+n > len(apdu) {
			return sw(0x67, 0x00), nil
		}
		data = apdu[5 : 5+n]
	}
	switch {
	case ins == 0xa4: // SELECT
		if c.NoApplet || !bytes.Equal(data, []byte{0xd2, 0x76, 0x00, 0x01, 0x24, 0x01}) {
			return sw(0x6a, 0x82), nil
		}
		return ok(), nil
	case ins == 0xf1: // version
		return ok(c.Firmware[0], c.Firmware[1], c.Firmware[2]), nil
	case ins == 0xca && p1 == 0x00 && p2 == 0x6e: // application data
		return ok(c.appData()...), nil
	case ins == 0xca && p1 == 0x00 && p2 == 0xd6: // UIF
		return ok(c.Touch, 0x20), nil
	case ins == 0x47 && p1 == 0x81: // read the signature key's public key
		if c.Alg == "" {
			return sw(0x65, 0x81), nil // what 5.4.3 answers for an empty slot
		}
		pk := []byte(c.Ed25519Public())
		if c.Alg == "eip191-secp256k1" {
			pk = c.Secp256k1Public()
		}
		inner := append([]byte{0x86, byte(len(pk))}, pk...)
		return ok(append([]byte{0x7f, 0x49, byte(len(inner))}, inner...)...), nil
	case ins == 0x20 && p2 == 0x81: // VERIFY PW1
		if c.Tries == 0 {
			return sw(0x69, 0x83), nil
		}
		if string(data) != c.PIN {
			c.Tries--
			if c.Tries == 0 {
				return sw(0x69, 0x83), nil
			}
			return sw(0x63, 0xc0|byte(c.Tries)), nil
		}
		c.Tries, c.verified = 3, true
		return ok(), nil
	case ins == 0x2a && p1 == 0x9e && p2 == 0x9a: // PSO: COMPUTE DIGITAL SIGNATURE
		c.chain = append(c.chain, data...)
		if len(c.chain) > c.MaxMessage {
			c.chain = nil
			return sw(0x67, 0x00), nil
		}
		if cla&0x10 != 0 {
			return ok(), nil
		}
		msg := c.chain
		c.chain = nil
		c.Asked++
		if !c.verified {
			return sw(0x69, 0x82), nil // the PIN is checked before a touch is waited for (#270)
		}
		if c.Touch != 0 && !c.Touched {
			return sw(0x66, 0x00), nil
		}
		if c.Alg == "" {
			return sw(0x6a, 0x88), nil
		}
		if c.PINAlways {
			c.verified = false
		}
		return ok(c.sign(msg)...), nil
	}
	return sw(0x6d, 0x00), nil
}

func (c *Card) sign(msg []byte) []byte {
	c.Signed++
	key := c.scalar()
	if c.Form == OtherKey {
		h := sha256.Sum256(append(key, 'x'))
		key = h[:]
	}
	var sig []byte
	if c.Alg == "ed25519" {
		sig = ed25519.Sign(ed25519.NewKeyFromSeed(key), msg)
	} else {
		priv := secp256k1.PrivKeyFromBytes(key)
		compact := ecdsa.SignCompact(priv, msg, false) // v ‖ r ‖ s; the card answers r ‖ s
		sig = compact[1:]
	}
	switch c.Form {
	case Garbage:
		return bytes.Repeat([]byte{0x01}, 64)
	case ShortSig:
		return sig[:63]
	}
	return sig
}

func (c *Card) appData() []byte {
	attr := []byte{0x16, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01}
	if c.Alg == "eip191-secp256k1" {
		attr = []byte{0x13, 0x2b, 0x81, 0x04, 0x00, 0x0a}
	}
	if c.Alg == "" {
		attr = []byte{0x01, 0x08, 0x00, 0x00, 0x11, 0x00} // RSA 2048, the empty slot's default
	}
	pw := byte(0x01)
	if c.PINAlways {
		pw = 0x00
	}
	fp := make([]byte, 60)
	if c.Fingerprinted && c.Alg != "" {
		copy(fp, bytes.Repeat([]byte{0xab}, 20))
	}
	tl := func(tag byte, v []byte) []byte { return append([]byte{tag, byte(len(v))}, v...) }
	disc := append(append(tl(0xc1, attr), tl(0xc4, []byte{pw, 0x7f, 0x7f, 0x7f, byte(c.Tries), 0x00, 0x03})...), tl(0xc5, fp)...)
	return append([]byte{0x6e, 0x81, byte(len(disc) + 3), 0x73, 0x81, byte(len(disc))}, disc...)
}

// Close closes the card; it is idempotent.
func (c *Card) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

// Reopen lets a closed card be used again by the next test step (a fresh session).
func (c *Card) Reopen() {
	c.mu.Lock()
	c.closed, c.verified, c.chain = false, false, nil
	c.mu.Unlock()
}
