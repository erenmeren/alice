// Package ldapx holds the pure helpers of directory (LDAP and Active Directory) sign-in: filter and DN escaping,
// filter template expansion, the transliteration table and the derivation of user names and unique ids. It does no
// I/O and does not import an LDAP client; the network code in internal/auth/ldap builds on it.
//
// # Filter templates
//
// These are the rules administrators must be told (settings validation, the admin guide and the UI):
//
//   - The only placeholders are {login} and {dn}, written in lower case, and they may stand only where an assertion
//     value stands: (uid={login}) and (cn={login}*) are fine, ({login}=x) and (uid:{login}:=x) are refused.
//   - Literal braces cannot appear in a template; write them as \7b and \7d.
//   - No raw control characters (tab, line feed and so on); write them escaped, as \09.
//   - The template is one filter: balanced parentheses, at least one element inside & and |, no text around it, at
//     most 1024 bytes and 16 levels; a backslash only before two hex digits; "*" only in an equality value and never
//     two in a row (RFC 4515 has no empty substring).
//   - The extensible-match flag must be the lower-case ":dn". go-ldap recognises only that spelling; ":DN:" is read
//     as the name of a matching rule, so (uid:DN:=x) means the rule "DN", and (:DN:2.5.13.5:=x) is refused (two
//     matching rules).
//
// For callers: a sign-in name must pass ValidLoginName before ExpandFilter. ErrFilterValue then means a bad sign-in
// name (treat it like an unknown user), ErrFilterTemplate a bad setting. A value must contain at least one letter
// or digit: logins are user names, e-mail addresses or UPNs, and a DN always holds an attribute type, so this
// refuses only values that a directory server could prepare (RFC 4518) into an empty or all-space string, which in
// a substring filter would match every entry.
//
// # User names
//
// Username is a policy, not a reversible mapping:
//
//   - Letters of the explicit table (Turkish ç ğ ı İ ö ş ü and their capitals, the common Latin accents and
//     ligatures) become ASCII; then the name is case-folded; then everything but a-z 0-9 . _ - @ is dropped, so other
//     non-ASCII characters and spaces vanish. Look-alike letters of other scripts (Cyrillic а, Greek ο) are NOT
//     mapped to their Latin twins: they are dropped like any other non-ASCII character.
//   - A name that collapses to fewer than two characters falls back to "ldap-" and 12 hex digits of the unique id.
//   - Two directory users may derive the same name; making it unique (-2, -3) is the caller's job. The identity is
//     the unique id, never the name.
package ldapx
