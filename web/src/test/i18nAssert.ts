// A translation key rendered as text means a missing translation (spec §22.3).
const RAW_KEY = /(?:^|\s)(?:home|language|nav|ui|login|setup|account|users|tokens|audit|errors|enum|validation)\.[a-z][A-Za-z_.]*/;

// visibleText joins the text nodes outside <style> and <script>, separated by spaces.
function visibleText(root: HTMLElement): string {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const parts: string[] = [];
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    const tag = n.parentElement?.tagName;
    if (tag !== 'STYLE' && tag !== 'SCRIPT') parts.push(n.textContent ?? '');
  }
  return parts.join(' ');
}

export function expectNoRawKeys(root: HTMLElement = document.body): void {
  expect(visibleText(root)).not.toMatch(RAW_KEY);
}
