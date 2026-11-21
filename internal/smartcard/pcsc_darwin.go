package smartcard

import (
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// Built reports whether this build can reach the system's smart-card service (PC/SC framework on macOS).
const Built = true

// syscall.syscall6 and syscall.syscall9 are the runtime's calls into a C function with up to six or nine integer
// arguments, the pattern golang.org/x/sys/unix uses on darwin. syscall6 is the one the runtime keeps linkname-open for
// packages outside the standard library (go.dev/issue/67401), as internal/ledger relies on; syscall9 carries a bare
// //go:linkname in syscall_darwin.go and x/sys/unix pulls it itself (unix/syscall_darwin_libSystem.go:
// //go:linkname syscall_syscall9 syscall.syscall9), so it stays open while x/sys builds. It is used here for
// SCardTransmit alone, which takes seven arguments. Checked against go1.27.2; if a Go release closes either linkname,
// the build fails here (CI cross-builds and vets darwin/amd64 and darwin/arm64), not at run time. See
// pcsc_darwin_arm64.s for the trampolines.
//
//go:linkname syscall_syscall6 syscall.syscall6
func syscall_syscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

//go:linkname syscall_syscall9 syscall.syscall9
func syscall_syscall9(fn, a1, a2, a3, a4, a5, a6, a7, a8, a9 uintptr) (r1, r2 uintptr, err syscall.Errno)

// call runs the C function at fn (at most six arguments). go:uintptrescapes makes every buffer or out-parameter
// passed as uintptr(unsafe.Pointer(&x)) escape to the heap, so a stack copy at call's prologue cannot leave C with a
// stale address (the #253 review, B1). macOS PC/SC returns a 32-bit LONG.
//
//go:uintptrescapes
func call(fn uintptr, args ...uintptr) uint32 {
	var a [6]uintptr
	copy(a[:], args)
	r, _, _ := syscall_syscall6(fn, a[0], a[1], a[2], a[3], a[4], a[5])
	return uint32(r)
}

// call7 is call for a seven-argument function (SCardTransmit).
//
//go:uintptrescapes
func call7(fn, a1, a2, a3, a4, a5, a6, a7 uintptr) uint32 {
	r, _, _ := syscall_syscall9(fn, a1, a2, a3, a4, a5, a6, a7, 0, 0)
	return uint32(r)
}

// macOS's PC/SC types are 32-bit (SCARDCONTEXT, SCARDHANDLE and DWORD are int32 or uint32, LONG is int32), unlike
// pcsc-lite on 64-bit Linux.
type ioRequest struct{ protocol, pciLength uint32 }

const (
	scopeSystem       = 2
	shareShared       = 2
	protocolT0T1      = 3
	leaveCard         = 0
	errNoService      = 0x8010001d
	errNoReaders      = 0x8010002e
	errNoSmartcard    = 0x8010000c
	errRemoved        = 0x80100069
	errSharing        = 0x8010000b
	errServiceStopped = 0x8010001e
)

func code(r uint32) string { return "0x" + strconv.FormatUint(uint64(r), 16) }

// Readers lists the readers the smart-card service sees.
func Readers() ([]string, error) {
	ctx, err := establish()
	if err != nil {
		return nil, err
	}
	defer call(fnSCardReleaseContext, uintptr(ctx))
	return listReaders(ctx)
}

func establish() (int32, error) {
	var ctx int32
	if r := call(fnSCardEstablishContext, scopeSystem, 0, 0, uintptr(unsafe.Pointer(&ctx))); r != 0 {
		return 0, &Error{Slug: NoService, Detail: "the system's smart-card service refused a context (" + code(r) + ")"}
	}
	return ctx, nil
}

func listReaders(ctx int32) ([]string, error) {
	var n uint32
	switch r := call(fnSCardListReaders, uintptr(ctx), 0, 0, uintptr(unsafe.Pointer(&n))); r {
	case 0:
	case errNoReaders:
		return nil, nil
	default:
		return nil, &Error{Slug: NoService, Detail: "the reader list could not be read (" + code(r) + ")"}
	}
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	if r := call(fnSCardListReaders, uintptr(ctx), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n))); r != 0 {
		if r == errNoReaders {
			return nil, nil
		}
		return nil, &Error{Slug: NoService, Detail: "the reader list could not be read (" + code(r) + ")"}
	}
	var out []string
	for _, s := range strings.Split(string(buf[:min(int(n), len(buf))]), "\x00") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out, nil
}

// Open connects to the card in the named reader, or in the only reader whose name contains match.
func Open(named, match string) (Card, string, error) {
	ctx, err := establish()
	if err != nil {
		return nil, "", err
	}
	names, err := listReaders(ctx)
	if err != nil {
		call(fnSCardReleaseContext, uintptr(ctx))
		return nil, "", err
	}
	reader, err := PickReader(names, named, match)
	if err != nil {
		call(fnSCardReleaseContext, uintptr(ctx))
		return nil, "", err
	}
	rb := append([]byte(reader), 0)
	var h int32
	var proto uint32
	if r := call(fnSCardConnect, uintptr(ctx), uintptr(unsafe.Pointer(&rb[0])), shareShared, protocolT0T1,
		uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(&proto))); r != 0 {
		call(fnSCardReleaseContext, uintptr(ctx))
		detail := "the card in " + quote(reader) + " could not be connected (" + code(r) + ")"
		switch r {
		case errNoSmartcard, errRemoved:
			detail = "no card is in " + quote(reader)
		case errSharing:
			detail = "another program holds the card in " + quote(reader) + " exclusively; close it (a password manager or gpg-agent may), then try again"
		}
		return nil, "", &Error{Slug: Connect, Detail: detail}
	}
	runtime.KeepAlive(rb)
	return &pcscCard{ctx: ctx, h: h, send: ioRequest{proto, 8}}, reader, nil
}

// pcscCard is a connected card. Transmit and Close are safe to call from several goroutines (an interrupt closes the
// card while a command waits for a touch).
type pcscCard struct {
	mu     sync.Mutex
	ctx, h int32
	send   ioRequest
	closed bool
}

func (c *pcscCard) Transmit(apdu []byte) ([]byte, error) {
	return collect(c.transmit, apdu)
}

func (c *pcscCard) transmit(apdu []byte) ([]byte, error) {
	if len(apdu) == 0 {
		return nil, &Error{Slug: Transmit, Detail: "an empty command"}
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, &Error{Slug: Transmit, Detail: "the card was closed"}
	}
	h, send := c.h, c.send
	c.mu.Unlock()
	resp := make([]byte, 65538)
	rl := uint32(len(resp))
	r := call7(fnSCardTransmit, uintptr(h), uintptr(unsafe.Pointer(&send)), uintptr(unsafe.Pointer(&apdu[0])), uintptr(len(apdu)), 0,
		uintptr(unsafe.Pointer(&resp[0])), uintptr(unsafe.Pointer(&rl)))
	runtime.KeepAlive(apdu)
	if r != 0 {
		detail := "the command could not be carried to the card (" + code(r) + ")"
		if r == errRemoved || r == errServiceStopped {
			detail = "the card went away"
		}
		return nil, &Error{Slug: Transmit, Detail: detail}
	}
	if int(rl) > len(resp) {
		return nil, &Error{Slug: Transmit, Detail: "the card's answer overran the buffer"}
	}
	return resp[:rl], nil
}

// Close disconnects the card and releases the context; it is idempotent.
func (c *pcscCard) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	call(fnSCardDisconnect, uintptr(c.h), leaveCard)
	call(fnSCardReleaseContext, uintptr(c.ctx))
	return nil
}
