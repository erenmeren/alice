import { expectNoRawKeys } from './i18nAssert';

describe('expectNoRawKeys', () => {
  afterEach(() => document.body.replaceChildren());

  it('fails on a rendered translation key', () => {
    document.body.innerHTML = '<main><h1>nav.home</h1></main>';
    expect(() => expectNoRawKeys()).toThrow();
  });

  it('fails on keys of any namespace, including ones outside the old prefix list', () => {
    document.body.innerHTML = '<main><p>Hello, stepup.title</p></main>';
    expect(() => expectNoRawKeys()).toThrow();
  });

  it('fails on a key in aria-label, placeholder or title', () => {
    for (const attr of ['aria-label', 'placeholder', 'title']) {
      document.body.innerHTML = `<main><input ${attr}="ui.codeLabel"></main>`;
      expect(() => expectNoRawKeys()).toThrow();
    }
  });

  it('accepts translated text, e-mail addresses, URLs and styles', () => {
    document.body.innerHTML =
      '<style>.ui.x{}</style><main><h1>Ana sayfa</h1><p>admin@example.com</p><p>Hesabım</p>' +
      '<p>See https://docs.example.com/a.b for e.g. details. Version 1.2.3.</p><input aria-label="Language"></main>';
    expect(() => expectNoRawKeys()).not.toThrow();
  });

  it('does not check technical data shown in <code>, but still checks the text around it', () => {
    document.body.innerHTML = '<main><p>Used on <a><code>www.example.test</code></a>, <code>/etc/nginx/ssl/www.crt</code></p></main>';
    expect(() => expectNoRawKeys()).not.toThrow();
    document.body.innerHTML = '<main><p>nav.home <code>www.example.test</code></p></main>';
    expect(() => expectNoRawKeys()).toThrow();
  });
});
