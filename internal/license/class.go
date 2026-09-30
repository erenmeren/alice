package license

// Class says how lock mode treats a piece of work (spec §8.6, R9, R29). Every job type
// and every state-changing API route declares one; the zero value is refused by the
// gate (fail closed) and by tests of the route table and the job registry (X-01).
type Class int

// License classes.
const (
	ClassUnset Class = iota
	// ClassAlways runs in every state: sign-in, license upload, backup, audit, notifications
	// and the license evaluation itself.
	ClassAlways
	// ClassReadOnly is recurring read-only work on managed systems (discovery, Key Vault
	// polling): paused while locked, resumed automatically after a renewal (R29).
	ClassReadOnly
	// ClassChange changes managed systems or the managed inventory (deploy, add or remove a
	// key, import, add a target): refused while locked; after a renewal, work that was
	// paused needs an Admin's confirmation (R29).
	ClassChange
)

// Valid reports whether c is one of the three real classes.
func (c Class) Valid() bool { return c >= ClassAlways && c <= ClassChange }

func (c Class) String() string {
	switch c {
	case ClassAlways:
		return "always"
	case ClassReadOnly:
		return "read_only"
	case ClassChange:
		return "change"
	default:
		return "unset"
	}
}
