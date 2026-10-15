//go:build !yubikey

package main

// pcscTagged: this build has no PC/SC transport; the card commands refuse first.
const pcscTagged = false
