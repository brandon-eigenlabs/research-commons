//go:build !darwin

package smartcard

import "runtime"

// Built reports whether this build can reach the system's smart-card service. Only macOS is built so far; the pcscd
// socket client for Linux is the next step (#270).
const Built = false

func notBuilt() error {
	return &Error{Slug: NotBuilt, Detail: "the smart-card connector is built for macOS only so far; on " + runtime.GOOS +
		" sign the package's PAE bytes with your own tool and run --complete with the signature"}
}

// Readers is not built on this system.
func Readers() ([]string, error) { return nil, notBuilt() }

// Open is not built on this system.
func Open(named, match string) (Card, string, error) { return nil, "", notBuilt() }
