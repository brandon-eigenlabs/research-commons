//go:build !darwin && !linux

package main

import "errors"

// readPIN is not built on this system: the PIN can only be entered where echo can be turned off.
func readPIN(string) ([]byte, error) {
	return nil, errors.New("the PIN is read from a terminal only, and PIN entry with echo off is not built on this system")
}
