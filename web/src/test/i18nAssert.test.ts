import { expectNoRawKeys } from './i18nAssert';

describe('expectNoRawKeys', () => {
  afterEach(() => document.body.replaceChildren());

  it('fails on a rendered translation key', () => {
    document.body.innerHTML = '<main><h1>nav.home</h1></main>';
    expect(() => expectNoRawKeys()).toThrow();
  });

  it('accepts translated text, e-mail addresses and styles', () => {
    document.body.innerHTML =
      '<style>.ui.x{}</style><main><h1>Ana sayfa</h1><p>admin@example.com</p><p>Hesabım</p></main>';
    expect(() => expectNoRawKeys()).not.toThrow();
  });
});
