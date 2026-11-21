package cli

import (
	"errors"
	"io"
	"strconv"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/smartcard"
	"github.com/research-common/research-commons/internal/wire"
	"github.com/research-common/research-commons/internal/yubikey"
)

// The YubiKey connector (#270, KNOWN-LIMITS L-07): `key sign --package <file> --yubikey` and `key show --yubikey`
// drive a YubiKey's OpenPGP applet, beside --ledger. Like the Ledger connector it reads no store, signs only the PAE
// recomputed from a package the tool prepared, verifies the card's signature with the reader's own rule before
// anything is written, and leaves --complete as the only step that touches a store. The card has no screen and a key
// generated on it cannot be backed up: it fits a delegate (an agent's key, or a person's touch-gated key), not an
// identity's root (identity note §8).

// YubiKeyOpener connects to the card in the named reader ("" for the only YubiKey attached).
type YubiKeyOpener func(reader string) (smartcard.Card, string, error)

// PINReader reads a PIN from the terminal without echo, after printing prompt on standard error. nil, or an error,
// when no terminal is attached: the PIN is never taken from an argument, the environment or a file (#270, 3).
type PINReader func(prompt string) ([]byte, error)

var (
	yubikeyFlag       = Flag{Name: "yubikey", Help: "sign with a YubiKey's OpenPGP signature key (ed25519 or eip191-secp256k1) instead of a key file; the PIN is asked on the terminal"}
	yubikeyReaderFlag = Flag{Name: "yubikey-reader", Value: "name", Help: "with --yubikey: the smart-card reader to use (its name, or a part of it) when several cards are attached"}
)

var yubikeyHelp = " With --yubikey the key is the signature key of a YubiKey's OpenPGP applet (drilled by hand on a YubiKey 5C, firmware 5.4.3, macOS arm64, both algorithms; tested against an in-process fake of the applet), " +
	"reached through the system's smart-card service on macOS (other systems: not built yet). The card's touch policy and PIN policy are read before every signature, " +
	"and the command warns when touch is off or cached (any program on the host can then sign while the card is attached; touch proves presence, not review) " +
	"and when the PIN unlocks every signature until the card is unplugged. An eip191-secp256k1 key on firmware before 5.7 is warned about too (Yubico YSA-2024-03): " +
	"treat a card that was out of your hands as a disclosed key. An Ed25519 PAE over " + strconv.Itoa(yubikey.MaxEd25519Message) + " bytes (about 22 members in an edition) is refused before the card is asked. " +
	"The card has no screen: compare the PAE's sha256 (--expect-pae-sha256) before you touch it. --yubikey, --ledger and --key are exclusive."

// yubikeyOptions reads --yubikey; nil when it is not given. --yubikey-reader without --yubikey, or --yubikey with
// --ledger or --key, is exit 2.
func yubikeyOptions(c *Ctx) (on bool, reader string, prob *Problem) {
	_, on = c.Flag("yubikey")
	reader, hasReader := c.Flag("yubikey-reader")
	if !on {
		if hasReader {
			return false, "", conflicting("yubikey-reader", "--yubikey-reader goes with --yubikey", "it names the card's reader", "add --yubikey, or drop --yubikey-reader")
		}
		return false, "", nil
	}
	if _, ok := c.Flag("key"); ok {
		return false, "", conflicting("key", "--yubikey and --key are two signers", "give one of them", "drop --key to sign on the card, or drop --yubikey")
	}
	if _, ok := c.Flag("ledger"); ok {
		return false, "", conflicting("ledger", "--yubikey and --ledger are two signers", "give one of them", "drop one of the two")
	}
	return true, reader, nil
}

// yubikeySession is an open card with the OpenPGP applet selected and its state read.
type yubikeySession struct {
	card   smartcard.Card
	reader string
	s      *yubikey.Session
	st     *yubikey.State
	signer string
}

func (y *yubikeySession) close() { y.card.Close() }

func openYubiKey(c *Ctx, reader, what string) (*yubikeySession, *Problem) {
	if c.Env.YubiKey == nil {
		return nil, &Problem{Slug: "not-available", Title: "the YubiKey connector is not available in this build", Class: refusal.Operational, Scope: "invocation",
			Detail: "this build has no smart-card connector; " + what, Next: "sign the package's PAE bytes with your own tool and run --complete with the signature", Exit: ExitCouldNot}
	}
	card, name, err := c.Env.YubiKey(reader)
	if err != nil {
		return nil, yubikeyProblem(err, what)
	}
	y := &yubikeySession{card: card, reader: name}
	if y.s, err = yubikey.NewSession(card); err != nil {
		card.Close()
		return nil, yubikeyProblem(err, what)
	}
	if y.st, err = y.s.State(); err != nil {
		card.Close()
		return nil, yubikeyProblem(err, what)
	}
	if y.signer, err = y.st.Signer(); err != nil {
		card.Close()
		return nil, yubikeyProblem(err, what)
	}
	return y, nil
}

// yubikeyWarnings are the conditions the connector warns about and still signs under (#270, conditions 2 and 4).
func yubikeyWarnings(st *yubikey.State) []string {
	var w []string
	switch st.Touch {
	case yubikey.TouchOff:
		w = append(w, "touch is off: while the card is attached, any program on this host can sign with it; the card protects the key from being copied and nothing else")
	case yubikey.TouchCached, yubikey.TouchCachedFixed:
		w = append(w, "touch is cached: one touch covers every signing request for about 15 seconds, not only the message it was given for")
	}
	if st.PINOnce {
		w = append(w, "the PIN policy is once: one PIN entry unlocks every signature until the card is unplugged (ykman openpgp set-signature-policy always asks for it each time)")
	}
	if st.Alg == yubikey.AlgSecp256k1 && (st.Firmware[0] < 5 || (st.Firmware[0] == 5 && st.Firmware[1] < 7)) {
		w = append(w, "this is a secp256k1 (ECDSA) key on firmware "+firmwareText(st)+", before 5.7: Yubico's advisory YSA-2024-03 reports private-key recovery by a side channel with physical possession of the card; treat a card that was lost or out of your hands as a disclosed key (cut its grant), and prefer an Ed25519 key")
	}
	return w
}

func firmwareText(st *yubikey.State) string {
	return strconv.Itoa(st.Firmware[0]) + "." + strconv.Itoa(st.Firmware[1]) + "." + strconv.Itoa(st.Firmware[2])
}

func yubikeyObj(y *yubikeySession) *Obj {
	pin := "always (asked before every signature)"
	if y.st.PINOnce {
		pin = "once (until the card is unplugged)"
	}
	return newObj().set("reader", peerV(y.reader)).set("firmware", textV(firmwareText(y.st))).set("applet", textV("OpenPGP, signature key")).
		set("touch", textV(y.st.Touch)).set("pin_policy", textV(pin)).set("pin_tries_left", intV(int64(y.st.PINTries)))
}

// yubikeyProblem maps a connector failure: a wrong PIN is exit 1 (the request was checked and refused), anything else
// exit 3 (the signature could not be made). Nothing was signed or written in either case.
func yubikeyProblem(err error, what string) *Problem {
	var se *smartcard.Error
	if errors.As(err, &se) {
		p := &Problem{Slug: se.Slug, Title: "the card could not be reached", Class: refusal.Operational, Scope: "yubikey", Detail: se.Detail + "; " + what, Exit: ExitCouldNot,
			Next: "plug the YubiKey in (its CCID interface enabled), close programs holding it, then run the command again"}
		if se.Slug == smartcard.Several {
			p.Title, p.Next, p.Exit = "several cards are attached", "name one with --yubikey-reader", ExitDidNotStart
		}
		return p
	}
	var e *yubikey.Error
	if !errors.As(err, &e) {
		return failed(err, "yubikey", false, "run the command again")
	}
	p := &Problem{Slug: e.Slug, Class: refusal.Operational, Scope: "yubikey", Exit: ExitCouldNot, Detail: e.Detail + "; " + what}
	if e.SW != 0 {
		p.Detail += " (status word " + yubikey.SWText(e.SW) + ")"
	}
	switch e.Slug {
	case yubikey.PINWrong:
		p.Title, p.Next, p.Exit, p.Class = "the card refused the PIN", "run the command again with the right PIN; a blocked PIN needs ykman openpgp access unblock-pin", ExitWrong, refusal.Policy
	case yubikey.PINBlocked:
		p.Title, p.Next = "the PIN is blocked", "unblock it with ykman openpgp access unblock-pin, then run the command again"
	case yubikey.NoTouch:
		p.Title, p.Next = "the card was not touched", "run the command again and touch the card when it blinks (it waits about 15 seconds)"
	case yubikey.NoKey:
		p.Title, p.Next = "the card's signature slot holds no key", "generate an Ed25519 key in it (ykman), grant it as a delegate, then prepare the package for it"
	case yubikey.NoApplet:
		p.Title, p.Next = "the card has no OpenPGP applet", "enable it (ykman config usb --enable OPENPGP), then run the command again"
	case yubikey.Unsupport:
		p.Title, p.Next = "the card's key is not usable", "generate an Ed25519 key in the OpenPGP signature slot (ykman)"
	case yubikey.TooLong:
		p.Title, p.Next = "the card cannot sign a message this long", "this statement is too long for the card's Ed25519 buffer; split the edition, or sign it with a key file"
	default:
		p.Title, p.Next = "the card could not sign", "run the command again"
	}
	return p
}

// awaitCard runs exchange (a request that may wait for a touch) so that an interrupt closes the card and ends the
// command (exit 3), as awaitHolder does for the Ledger.
func awaitCard(c *Ctx, y *yubikeySession, exchange func() error) error {
	if c.Env.Interrupt == nil {
		return exchange()
	}
	signals, stop := c.Env.Interrupt()
	defer stop()
	done := make(chan error, 1)
	go func() { done <- exchange() }()
	select {
	case err := <-done:
		return err
	case name := <-signals:
		stop()
		y.close()
		select {
		case <-done:
		case <-time.After(interruptCloseWait):
		}
		return &yubikey.Error{Slug: "yubikey-interrupted", Detail: "the command was interrupted (" + name + ") while the card waited, and closed its connection to the card"}
	}
}

// keyShowYubiKey is key show --yubikey: the signature key's signer, read from the card, with what the card's policies
// mean for it.
func keyShowYubiKey(c *Ctx, reader string) (*Obj, int, error) {
	if c.Args["file"] != "" {
		return nil, 0, conflicting("yubikey", "--yubikey and a key file are two signers", "give one of them", "drop the file argument to read the card, or drop --yubikey")
	}
	y, prob := openYubiKey(c, reader, "nothing is shown as the signer")
	if prob != nil {
		return nil, 0, prob
	}
	defer y.close()
	out := newObj().set("signer", refV(y.signer)).set("alg", textV(y.st.Alg)).set("device", yubikeyObj(y))
	if w := yubikeyWarnings(y.st); len(w) > 0 {
		out.set("warnings", texts(w...))
	}
	return out, ExitOK, nil
}

// keySignYubiKey is key sign --yubikey, after the package and the options were checked.
func keySignYubiKey(c *Ctx, reader string, st *wire.Statement, path, out string, dry bool) (*Obj, int, error) {
	const none = "nothing was signed or written"
	y, prob := openYubiKey(c, reader, none)
	if prob != nil {
		return nil, 0, prob
	}
	defer y.close()
	if y.signer != st.Signer || y.st.Alg != st.Alg {
		return nil, 0, &Problem{Slug: "key-not-signer", Title: "the card's key is not the package's signer", Class: refusal.Intrinsic, Scope: "option --yubikey",
			Detail: "the package is prepared for " + st.Signer + " (" + st.Alg + "); the card's signature key is " + y.signer + " (" + y.st.Alg + "); " + none,
			Next:   "use the card holding " + st.Signer + ", or prepare the statement again with --signer " + y.signer, Exit: ExitDidNotStart}
	}
	if st.Alg == wire.AlgEd25519 && len(st.SignedString) > yubikey.MaxEd25519Message {
		return nil, 0, yubikeyProblem(&yubikey.Error{Slug: yubikey.TooLong,
			Detail: "the PAE is " + itoa(len(st.SignedString)) + " bytes; the card signs at most " + itoa(yubikey.MaxEd25519Message) + " with Ed25519"}, none)
	}
	warnings := yubikeyWarnings(y.st)
	if dry {
		o := packageObj(newObj(), path, st).set("device", yubikeyObj(y)).set("dry_run", boolV(true)).set("signed", boolV(false)).set("written", boolV(false)).
			set("would", textV("ask for the PIN, then ask the card to sign the "+itoa(len(st.SignedString))+" PAE bytes above as "+st.Signer+" and write the signature"))
		if len(warnings) > 0 {
			o.set("warnings", texts(warnings...))
		}
		return o, ExitOK, nil
	}
	if c.Env.ReadPIN == nil {
		return nil, 0, &Problem{Slug: "no-terminal", Title: "the PIN is read from a terminal only", Class: refusal.Operational, Scope: "invocation",
			Detail: "the card's PIN is asked on the terminal and never taken from an argument, the environment or a file; " + none,
			Next:   "run the command in a terminal", Exit: ExitDidNotStart}
	}
	res := newObj()
	if c.JSON {
		res = packageObj(res, path, st).set("device", yubikeyObj(y))
		if len(warnings) > 0 {
			res.set("warnings", texts(warnings...))
		}
	}
	if c.Env.Stderr != nil {
		pre := newObj()
		if !c.JSON {
			pre = packageObj(pre, path, st).set("device", yubikeyObj(y))
		}
		io.WriteString(c.Env.Stderr, human(pre))
		for _, w := range warnings {
			io.WriteString(c.Env.Stderr, "commons: warning: "+w+"\n")
		}
	}
	pin, err := c.Env.ReadPIN("commons: OpenPGP user PIN for the card in " + y.reader + " (" + strconv.Itoa(y.st.PINTries) + " tries left): ")
	if err != nil {
		return nil, 0, &Problem{Slug: "no-terminal", Title: "the PIN could not be read", Class: refusal.Operational, Scope: "invocation",
			Detail: err.Error() + "; " + none, Next: "run the command in a terminal", Exit: ExitDidNotStart}
	}
	verr := y.s.VerifyPIN(pin)
	clear(pin)
	if verr != nil {
		return nil, 0, yubikeyProblem(verr, none)
	}
	if c.Env.Stderr != nil && y.st.Touch != yubikey.TouchOff {
		io.WriteString(c.Env.Stderr, "commons: touch the card now if it blinks (it waits about 15 seconds)\n")
	}
	var signature string
	err = awaitCard(c, y, func() error {
		var err error
		signature, err = y.s.SignPAE(y.st, st.SignedString)
		return err
	})
	if err != nil {
		return nil, 0, yubikeyProblem(err, none)
	}
	// the reader's own check of the signed line, as for a key file or the Ledger
	env := envelopeOf(st).(*canon.Object)
	if why := verifyOver(env, st, signature); why != "" {
		return nil, 0, &Problem{Slug: "yubikey-bad-signature", Title: "the card's signature does not verify", Class: refusal.Operational, Scope: "yubikey",
			Detail: "the signature the card returned does not verify over the package as " + st.Signer + " (" + why + "); " + none,
			Next:   "check that the card is the one holding " + st.Signer + ", then run the command again", Exit: ExitCouldNot}
	}
	res.set("statement", refV(st.ID)).set("signature", refV(signature)).set("signed", boolV(true)).set("dry_run", boolV(false))
	return writeSignature(c, res, st, out, signature)
}
