// Package smartcard is a minimal PC/SC client: it lists the readers the system's smart-card service sees, connects to
// one, and carries APDUs to the card in it. It is what the YubiKey connector (#270, KNOWN-LIMITS L-07) speaks to an
// OpenPGP applet over. There is no cgo: on macOS the PC/SC framework is bound with go:cgo_import_dynamic (as
// internal/ledger binds IOKit); other systems are not built yet and say so. The package trusts nothing the card
// returns: callers parse and verify every answer.
package smartcard

import (
	"errors"
	"strings"
)

// Card is a connected card: Transmit sends one command APDU and returns the whole response, data followed by the two
// status-word bytes. A response the card chains (61 xx) is collected here, so callers see one response per command.
type Card interface {
	Transmit(apdu []byte) ([]byte, error)
	Close() error
}

// Error is a typed transport failure. Slug is a stable token; Detail says what happened.
type Error struct {
	Slug   string
	Detail string
}

func (e *Error) Error() string { return e.Slug + ": " + e.Detail }

// Failure slugs.
const (
	NotBuilt  = "smartcard-not-built"  // no PC/SC binding for this system in this build
	NoService = "smartcard-no-service" // the system's smart-card service is not running or refused the context
	NoReader  = "smartcard-no-reader"  // no reader (or no matching reader) is present
	Several   = "smartcard-several"    // several matching readers and none named
	Connect   = "smartcard-connect"    // the card in the reader could not be connected (removed, in use, unpowered)
	Transmit  = "smartcard-transmit"   // a command could not be carried (the card went away, a reader error)
)

// IsSlug reports whether err is an *Error with that slug.
func IsSlug(err error, slug string) bool {
	var e *Error
	return errors.As(err, &e) && e.Slug == slug
}

// PickReader chooses the reader to connect to among names: the named one (exactly, or the only one containing it),
// else the only one whose name contains match. None or several is a failure naming what was found.
func PickReader(names []string, named, match string) (string, error) {
	want := match
	if named != "" {
		for _, n := range names {
			if n == named {
				return n, nil
			}
		}
		want = named
	}
	var hits []string
	for _, n := range names {
		if strings.Contains(n, want) {
			hits = append(hits, n)
		}
	}
	switch len(hits) {
	case 1:
		return hits[0], nil
	case 0:
		if len(names) == 0 {
			return "", &Error{Slug: NoReader, Detail: "no smart-card reader is present (is the card plugged in, with its CCID interface enabled?)"}
		}
		return "", &Error{Slug: NoReader, Detail: "no reader matches " + quote(want) + "; the readers present are " + strings.Join(quoteAll(names), ", ")}
	}
	return "", &Error{Slug: Several, Detail: "several readers match " + quote(want) + " (" + strings.Join(quoteAll(hits), ", ") + "); name one"}
}

func quote(s string) string { return "\"" + s + "\"" }

func quoteAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = quote(s)
	}
	return out
}

// collect sends apdu with tx and gathers a response the card returns in parts (SW 61 xx: GET RESPONSE for xx more
// bytes), so the caller sees the whole data and the final status word.
func collect(tx func([]byte) ([]byte, error), apdu []byte) ([]byte, error) {
	r, err := tx(apdu)
	if err != nil {
		return nil, err
	}
	var data []byte
	for i := 0; i < 64; i++ { // a bound: no card returns 64 parts of one answer
		if len(r) < 2 {
			return nil, &Error{Slug: Transmit, Detail: "the card's answer is shorter than a status word"}
		}
		sw1, sw2 := r[len(r)-2], r[len(r)-1]
		data = append(data, r[:len(r)-2]...)
		if sw1 != 0x61 {
			return append(data, sw1, sw2), nil
		}
		if r, err = tx([]byte{apdu[0] &^ 0x10, 0xc0, 0x00, 0x00, sw2}); err != nil {
			return nil, err
		}
	}
	return nil, &Error{Slug: Transmit, Detail: "the card kept answering 61 xx"}
}
