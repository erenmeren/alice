//go:build windows

// Command stdinhash is a test-only program of the WinRS real tests (R71 F25, F26, F29). It prints the hex
// SHA-256 of its stdin, sleeps the seconds of its optional second argument, and exits with its first.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Fprintln(os.Stderr, "usage: stdinhash <exit code> [sleep seconds]")
		os.Exit(100)
	}
	code, err := strconv.Atoi(os.Args[1])
	if err != nil {
		os.Exit(101)
	}
	h := sha256.New()
	if _, err := io.Copy(h, os.Stdin); err != nil {
		os.Exit(102)
	}
	fmt.Println(hex.EncodeToString(h.Sum(nil)))
	if len(os.Args) == 3 {
		s, err := strconv.Atoi(os.Args[2])
		if err != nil {
			os.Exit(103)
		}
		time.Sleep(time.Duration(s) * time.Second)
	}
	os.Exit(code)
}
