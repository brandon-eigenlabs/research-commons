// The PC/SC framework functions pcsc_darwin.go calls, bound without cgo. Each has a trampoline in pcsc_darwin_arm64.s
// and pcsc_darwin_amd64.s, in the same order (TestPCSCBindingsInStep checks the three files agree).

package smartcard

import _ "unsafe" // for go:cgo_import_dynamic

//go:cgo_import_dynamic pcsc_SCardEstablishContext SCardEstablishContext "/System/Library/Frameworks/PCSC.framework/PCSC"
//go:cgo_import_dynamic pcsc_SCardReleaseContext SCardReleaseContext "/System/Library/Frameworks/PCSC.framework/PCSC"
//go:cgo_import_dynamic pcsc_SCardListReaders SCardListReaders "/System/Library/Frameworks/PCSC.framework/PCSC"
//go:cgo_import_dynamic pcsc_SCardConnect SCardConnect "/System/Library/Frameworks/PCSC.framework/PCSC"
//go:cgo_import_dynamic pcsc_SCardDisconnect SCardDisconnect "/System/Library/Frameworks/PCSC.framework/PCSC"
//go:cgo_import_dynamic pcsc_SCardTransmit SCardTransmit "/System/Library/Frameworks/PCSC.framework/PCSC"

// The trampoline addresses, filled in by the assembly files.
var (
	fnSCardEstablishContext uintptr
	fnSCardReleaseContext   uintptr
	fnSCardListReaders      uintptr
	fnSCardConnect          uintptr
	fnSCardDisconnect       uintptr
	fnSCardTransmit         uintptr
)
