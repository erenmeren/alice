package main

import (
	"alice/internal/vconsole/sign/openpgp"
	"alice/internal/vconsole/sign/pcsc"
)

// openCard connects to the YubiKey in the named reader ("" = the one YubiKey connected). It is
// the only use of the PC/SC transport (architecture rule: only this command wires it); tests
// replace it with the card simulator. Without the yubikey build tag it returns pcsc.ErrNoPCSC.
var openCard func(reader string) (openpgp.Card, error) = pcsc.Connect

// errNoPCSC is the refusal of a build without the yubikey tag.
var errNoPCSC = pcsc.ErrNoPCSC
