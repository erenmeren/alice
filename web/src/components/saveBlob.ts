// saveBlob hands a Blob to the browser as a download through one temporary object URL, revoked on the next
// task (some browsers read it only after click() returns). Nothing keeps a reference to the Blob.
export function saveBlob(blob: Blob, fileName: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

// keyFileName is the name the browser saves a private key under: alice-<label>.key with the label reduced to lower-case
// ASCII letters, digits, '.', '_' and '-' (the server's own name differs only by a fingerprint suffix). Folding is by
// character code, not by locale.
export function keyFileName(label: string): string {
  let slug = '';
  for (const ch of label) {
    const c = ch.charCodeAt(0);
    if (c >= 65 && c <= 90) slug += String.fromCharCode(c + 32);
    else if ((c >= 97 && c <= 122) || (c >= 48 && c <= 57) || ch === '.' || ch === '_' || ch === '-') slug += ch;
    else slug += '-';
  }
  slug = slug.replace(/-{2,}/g, '-').replace(/^[-.]+|-+$/g, '').slice(0, 60);
  return `alice-${slug || 'key'}.key`;
}
