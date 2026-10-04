package auth

import "time"

// SetCredentialSlotHook installs f, called with true right after a credential slot is
// taken and with false right before it is released.
func SetCredentialSlotHook(s *Service, f func(acquired bool)) { s.slotHook = f }

// CredentialSlots returns the number of credential slots.
func CredentialSlots(s *Service) int { return cap(s.credSlots) }

// SetLockTimeout overrides how long a credential check waits for the account row lock.
func SetLockTimeout(s *Service, d time.Duration) { s.lockTimeout = d }

// LoginNameLockNamespace is the first key of Login's per-name advisory lock.
const LoginNameLockNamespace = loginNameLockNamespace

// SetHashHook installs f, called with the operation (HashOpHash, HashOpVerify or HashOpDummy)
// at the start of every Argon2 run of h, while its hash slot is held; nil removes it.
func SetHashHook(h *Hasher, f func(op string)) { h.hook = f }

// Operations passed to the hash hook.
const (
	HashOpHash   = hashOpHash
	HashOpVerify = hashOpVerify
	HashOpDummy  = hashOpDummy
)
