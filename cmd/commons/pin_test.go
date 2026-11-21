//go:build darwin || linux

package main

import (
	"errors"
	"os"
	"testing"
)

// TestReadPINRefusesAPipe: with standard input a pipe, nothing is prompted and the PIN is not read (#270, condition 3:
// never from a pipe, an argument, the environment or a file).
func TestReadPINRefusesAPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	w.WriteString("123456\n")
	w.Close()
	saved := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = saved }()
	pin, err := readPIN("prompt: ")
	if !errors.Is(err, errNotTerminal) || pin != nil {
		t.Fatalf("a pipe was read as a terminal: %q %v", pin, err)
	}
}
