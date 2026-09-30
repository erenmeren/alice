package auth

import "time"

// SetCredentialSlotHook installs f, called with true right after a credential slot is
// taken and with false right before it is released.
func SetCredentialSlotHook(s *Service, f func(acquired bool)) { s.slotHook = f }

// CredentialSlots returns the number of credential slots.
func CredentialSlots(s *Service) int { return cap(s.credSlots) }

// SetLockTimeout overrides how long a credential check waits for the account row lock.
func SetLockTimeout(s *Service, d time.Duration) { s.lockTimeout = d }
