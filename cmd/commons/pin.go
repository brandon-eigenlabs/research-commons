//go:build darwin || linux

package main

import (
	"bufio"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

// errNotTerminal: the PIN is never taken from a pipe, an argument, the environment or a file (#270, condition 3).
var errNotTerminal = errors.New("the PIN is read from a terminal only: standard input is not a terminal")

// readPIN reads a line from the terminal with echo turned off (a card's PIN, #270 condition 3). Standard input must be
// a terminal; nothing is prompted otherwise. The terminal's mode is restored on every exit path: a return, and
// SIGINT, SIGTERM or SIGHUP while the PIN is being typed (restored, then the signal is delivered again with its
// default action, so the command ends as it would have).
func readPIN(prompt string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	old, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return nil, errNotTerminal
	}
	quiet := *old
	quiet.Lflag &^= unix.ECHO
	quiet.Lflag |= unix.ICANON | unix.ECHONL
	restore := func() { unix.IoctlSetTermios(fd, ioctlSetTermios, old) }

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		select {
		case s := <-sigs:
			restore()
			os.Stderr.WriteString("\n")
			signal.Reset(s)
			unix.Kill(os.Getpid(), s.(syscall.Signal))
		case <-done:
		}
	}()
	defer func() {
		close(done)
		<-finished
		signal.Stop(sigs)
		restore()
	}()

	if err := unix.IoctlSetTermios(fd, ioctlSetTermios, &quiet); err != nil {
		return nil, errors.New("the terminal's echo could not be turned off")
	}
	os.Stderr.WriteString(prompt)
	line, err := bufio.NewReaderSize(os.Stdin, 256).ReadSlice('\n')
	if err != nil {
		clear(line)
		return nil, errors.New("no PIN was entered")
	}
	pin := make([]byte, 0, len(line))
	for _, b := range line {
		if b != '\n' && b != '\r' {
			pin = append(pin, b)
		}
	}
	clear(line)
	return pin, nil
}
