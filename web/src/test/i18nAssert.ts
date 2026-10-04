// A translation key rendered as text means a missing translation (spec §22.3).
// Any dotted lowercase token ("nav.home", "stepup.title") counts. The token must start after
// whitespace or an opening bracket, which leaves out e-mail addresses ("a@b.com") and URLs
// ("https://docs.example.com"); segments have two or more characters, which leaves out "e.g.".
const RAW_KEY = /(?:^|[\s(])[a-z][a-z0-9]+(?:\.[a-z][A-Za-z0-9_]+)+(?=$|[\s.,:;)!?])/;

// Technical data (host and domain names, paths, fingerprints, PEM text) is shown in <code> and is
// never translated (A-11); a domain name such as "www.example.test" looks like a key, so the text
// inside <code> is not checked.
// visibleText joins the text nodes outside <style>, <script> and <code> and the attributes that
// assistive technology or tooltips show, separated by spaces.
function visibleText(root: HTMLElement): string {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const parts: string[] = [];
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    const tag = n.parentElement?.tagName;
    if (tag !== 'STYLE' && tag !== 'SCRIPT' && !n.parentElement?.closest('code')) parts.push(n.textContent ?? '');
  }
  root.querySelectorAll('[aria-label],[placeholder],[title]').forEach((el) => {
    for (const attr of ['aria-label', 'placeholder', 'title']) {
      const v = el.getAttribute(attr);
      if (v) parts.push(v);
    }
  });
  return parts.join(' ');
}

export function expectNoRawKeys(root: HTMLElement = document.body): void {
  expect(visibleText(root)).not.toMatch(RAW_KEY);
}
