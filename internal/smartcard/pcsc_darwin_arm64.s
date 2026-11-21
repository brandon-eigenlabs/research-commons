// Trampolines to the functions pcsc_imports_darwin.go imports, one per function, in the same order: the
// golang.org/x/sys/unix pattern for calling a system library without cgo (as internal/ledger binds IOKit).

#include "textflag.h"

TEXT pcsc_SCardEstablishContext_trampoline<>(SB),NOSPLIT,$0-0
	JMP	pcsc_SCardEstablishContext(SB)
GLOBL	·fnSCardEstablishContext(SB), RODATA, $8
DATA	·fnSCardEstablishContext(SB)/8, $pcsc_SCardEstablishContext_trampoline<>(SB)

TEXT pcsc_SCardReleaseContext_trampoline<>(SB),NOSPLIT,$0-0
	JMP	pcsc_SCardReleaseContext(SB)
GLOBL	·fnSCardReleaseContext(SB), RODATA, $8
DATA	·fnSCardReleaseContext(SB)/8, $pcsc_SCardReleaseContext_trampoline<>(SB)

TEXT pcsc_SCardListReaders_trampoline<>(SB),NOSPLIT,$0-0
	JMP	pcsc_SCardListReaders(SB)
GLOBL	·fnSCardListReaders(SB), RODATA, $8
DATA	·fnSCardListReaders(SB)/8, $pcsc_SCardListReaders_trampoline<>(SB)

TEXT pcsc_SCardConnect_trampoline<>(SB),NOSPLIT,$0-0
	JMP	pcsc_SCardConnect(SB)
GLOBL	·fnSCardConnect(SB), RODATA, $8
DATA	·fnSCardConnect(SB)/8, $pcsc_SCardConnect_trampoline<>(SB)

TEXT pcsc_SCardDisconnect_trampoline<>(SB),NOSPLIT,$0-0
	JMP	pcsc_SCardDisconnect(SB)
GLOBL	·fnSCardDisconnect(SB), RODATA, $8
DATA	·fnSCardDisconnect(SB)/8, $pcsc_SCardDisconnect_trampoline<>(SB)

TEXT pcsc_SCardTransmit_trampoline<>(SB),NOSPLIT,$0-0
	JMP	pcsc_SCardTransmit(SB)
GLOBL	·fnSCardTransmit(SB), RODATA, $8
DATA	·fnSCardTransmit(SB)/8, $pcsc_SCardTransmit_trampoline<>(SB)

