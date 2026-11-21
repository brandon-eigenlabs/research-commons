package cli

import (
	"encoding/hex"
	"errors"
	"io"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/ledger"
	"github.com/research-common/research-commons/internal/rctime"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

// Key events signed on a Ledger device (#266, KNOWN-LIMITS L-22). `revoke --ledger` and `rotate --ledger` sign the
// rc/1 key event on the device, as `key sign --ledger` signs a package's PAE: EIP-191 personal_sign over the exact
// PAE bytes (wire §4), the device's address at --ledger-path being the key whose log the event extends. Nothing
// about the statement changes: the line is the one a key file would sign, verified as every reader verifies it, and
// committed through the same path. The store and the device are on one machine for these two commands; a key event
// has no package route.

// ledgerKeyEventFlags are the device options revoke and rotate take (the confirm option is key show's), and
// --expect-signer, which guards the key a key event retires whatever signs it.
var ledgerKeyEventFlags = []Flag{ledgerFlag, ledgerPathFlag, ledgerDeviceFlag, ledgerTimeoutFlag,
	{Name: "expect-signer", Value: "key", Help: "refuse unless the signing key is this one (ed25519:<64 hex> or 0x<40 hex>): with --ledger, a wrong path or passphrase gives another key, and its key event would retire that key instead",
		Check: func(v string) error {
			if !reSuccessor.MatchString(v) {
				return errors.New("not a key (ed25519: + 64 lowercase hex, or 0x + 40 lowercase hex)")
			}
			return nil
		}},
}

// expectSigner refuses a key event signed by another key than --expect-signer names (exit 2, nothing asked or
// signed): the guard against a wrong device path or passphrase retiring an unrelated key.
func expectSigner(c *Ctx, k wire.Key) *Problem {
	want, ok := c.Flag("expect-signer")
	if !ok || want == k.Signer() {
		return nil
	}
	return &Problem{Slug: "unexpected-signer", Title: "the signing key is not the one --expect-signer names", Class: refusal.Intrinsic, Scope: "option --expect-signer",
		Detail: "the key event would be signed by " + k.Signer() + ", not " + want + "; nothing was signed or appended",
		Next:   "with --ledger, check the path and the device's passphrase (commons key show --ledger --ledger-path <path> prints a path's signer); else give the right key", Peer: want, Exit: ExitDidNotStart}
}

// unheldKeyWarning warns when the store holds no line of the key the event retires: a first-line key event is valid,
// but under --ledger it is the likely sign of a wrong path or passphrase (another key than the one meant).
func unheldKeyWarning(out *Obj, k wire.Key, held int) {
	if _, onDevice := k.(*deviceKey); onDevice {
		out.set("signer", refV(k.Signer()))
	}
	if held == 0 {
		out.set("warning_key_not_held", textV("this store holds no line of "+k.Signer()+": if that is not the key you meant to retire, check the device path and passphrase (or the key file), or give --expect-signer"))
	}
}

// deviceKey is a wire.Key whose signature is made by the device. Sign has no error return, so a device failure
// (a refusal, a timeout, an interrupt) is kept in err and the caller checks it before the line is used.
type deviceKey struct {
	c   *Ctx
	o   *ledgerOpts
	s   *ledgerSession
	err error
}

func (k *deviceKey) Alg() string    { return wire.AlgEIP191 }
func (k *deviceKey) Signer() string { return k.s.address }

// Sign asks the device to sign the PAE, after printing on standard error what the device will show.
func (k *deviceKey) Sign(ss []byte) string {
	if len(ss) > ledger.MaxMessage {
		k.err = &ledger.Error{Slug: ledger.TooLong, Detail: "the PAE is " + itoa(len(ss)) + " bytes; the Ethereum app's protocol carries at most " + itoa(ledger.MaxMessage)}
		return ""
	}
	if k.c.Env.Stderr != nil {
		io.WriteString(k.c.Env.Stderr, human(newObj().set("device", deviceObj(k.o, k.s)).set("device_shows", eip191Display(&wire.Statement{SignedString: ss}))))
		io.WriteString(k.c.Env.Stderr, "commons: review the message on the device now and approve it there; reject it if anything differs (waiting up to "+k.o.wait.String()+")\n")
	}
	var rsv []byte
	k.err = awaitHolder(k.c, k.s, func() error {
		var err error
		rsv, err = ledger.PersonalSignWait(k.s.dev, k.o.path, ss, k.o.wait)
		return err
	})
	if k.err != nil {
		return ""
	}
	return "0x" + hex.EncodeToString(rsv) // the stored encoding: PersonalSign canonicalises (low s, v 27/28)
}

// keyEventKey is the key a revoke or rotate signs with: the key file prepareCommon loaded, or, with --ledger, the
// device's key at the path (the device is opened here, since its address is the log the event extends). done
// closes the device; it is a no-op for a key file.
func keyEventKey(c *Ctx, p *pubPrep) (wire.Key, func(), *Problem) {
	if p.ledger == nil {
		return p.key.Key, func() {}, nil
	}
	s, prob := openLedger(c, p.ledger, false, "nothing was signed or appended")
	if prob != nil {
		return nil, nil, prob
	}
	return &deviceKey{c: c, o: p.ledger, s: s}, s.close, nil
}

// signKeyEvent signs d with k. A key file signs as before. A device signs the PAE on the device, unless this is a dry
// run: then nothing is sent to the device, and the statement (whose id does not depend on the signature) is returned
// with what the device would show, so the dry run lists the same plan without a review on the device.
func signKeyEvent(c *Ctx, d wire.Draft, k wire.Key) (signed, *Obj, error) {
	dk, onDevice := k.(*deviceKey)
	if !onDevice {
		st, err := wire.Write(d, k, Now())
		if err == nil && st.Status != wire.Valid {
			err = &refusal.Refusal{Class: refusal.Intrinsic, Reason: "not valid", Detail: "the signed line reads back as " + string(st.Status)}
		}
		if err != nil {
			return signed{}, nil, err
		}
		return signed{st, st.Line()}, nil, nil
	}
	if _, dry := c.Flag("dry-run"); dry {
		// the device was opened and its address read (it is the log the event extends); it is not asked to sign
		env := d.Envelope(k)
		ss := wire.PAE(wire.PayloadType(d.Kind, wire.Major), canon.Encode(env))
		ts, _ := rctime.ParseUTC(d.TS) // checked by prepareCommon
		st := &wire.Statement{ID: wire.ID(ss), RC: "rc/1", Kind: d.Kind, Signer: k.Signer(), Alg: k.Alg(), Seq: d.Seq, Prev: d.Prev,
			Merges: d.Merges, TS: ts, Body: d.Body, SignedString: ss, Status: wire.Valid}
		// the dry run's line is the unsigned envelope: commitUnit's dry run prints the statement and writes nothing
		return signed{st, canon.Encode(env)}, newObj().set("device", deviceObj(dk.o, dk.s)).set("device_shows", eip191Display(st)).
			set("would_sign", textV("on the device, after you approve it there; this dry run read the device's address and asked it to sign nothing")), nil
	}
	st, err := wire.Write(d, k, Now())
	if dk.err != nil {
		return signed{}, nil, ledgerProblem(dk.err, "nothing was signed or appended")
	}
	if err != nil || st.Status != wire.Valid {
		why := "not valid"
		if err != nil {
			why = err.Error()
		} else {
			why = string(st.Status)
		}
		// the reader's own check of the device's signature failed: the device is not the key it reported
		return signed{}, nil, &Problem{Slug: "ledger-bad-signature", Title: "the device's signature does not verify", Class: refusal.Operational, Scope: "ledger device",
			Detail: "the signature the device returned does not verify over the key event as " + k.Signer() + " (" + why + "); nothing was appended",
			Next:   "check that the device is the one holding " + k.Signer() + ", then run the command again", Exit: ExitCouldNot}
	}
	return signed{st, st.Line()}, newObj().set("device", deviceObj(dk.o, dk.s)), nil
}

// selfSuccessor is the refusal of a rotation naming the signing key as its own successor.
func selfSuccessor(succ string) *Problem {
	return usage("conflicting-options", "the successor is the signing key itself",
		"a key cannot succeed itself; nothing was done", "option --successor",
		"name another key as the successor (commons key new --out <file>, then --successor-key <file>)", succ)
}

// setKeyEventCut sets what the key event stops from counting (revokeCut) and, for a device, what it showed. A device
// dry run has no signed line to read, so the cut is not computed; the tips above already say what happens to each.
func setKeyEventCut(c *Ctx, out *Obj, k wire.Key, sts []signed, dev *Obj) {
	_, dry := c.Flag("dry-run")
	if _, onDevice := k.(*deviceKey); onDevice && dry {
		out.set("stop_counting", textV("not listed in a device dry run (nothing was signed to read back); the tips above say what happens to each, and the signed run lists the lines that stop counting"))
	} else if cut := revokeCut(c, k.Signer(), sts); len(cut) > 0 {
		out.set("stop_counting", cut)
	}
	if dev != nil {
		for _, key := range dev.keys {
			out.set(key, dev.vals[key])
		}
	}
}

// deviceDryNote replaces the dry run's note for a device: nothing was signed at all (a key file's dry run signs and
// discards), and the statement id does not depend on the signature.
func deviceDryNote(c *Ctx, k wire.Key, o *Obj) {
	if _, dry := c.Flag("dry-run"); dry && o != nil {
		if _, onDevice := k.(*deviceKey); onDevice {
			o.set("note", textV("dry run: the device's address was read and it was asked to sign nothing; nothing was written; the id above is the statement's (it does not depend on the signature)"))
		}
	}
}
