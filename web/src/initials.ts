// initials are a person's avatar letters: the first character of the first two words of the display name,
// upper-cased in the reader's language. The avatar is decorative; the name is always written next to it.
export function initials(name: string, lang: string): string {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => [...w][0])
    .join('')
    .toLocaleUpperCase(lang);
}
