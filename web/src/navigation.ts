// goTo leaves the single-page app for another site (the identity provider's sign-in page). It is the one place that does
// so, and tests replace it.
export function goTo(url: string): void {
  window.location.assign(url);
}
