import { keyTypeName } from './rotationText';

describe('keyTypeName', () => {
  it.each([
    ['ed25519', 'Ed25519'],
    ['rsa-3072', 'RSA 3072'],
    ['rsa-4096', 'RSA 4096'],
    ['ecdsa-p256', 'ECDSA P-256'],
  ])('names %s as the design writes it (%s)', (type, name) => {
    expect(keyTypeName(type)).toBe(name);
  });

  it('shows a type this version does not know as the server sent it', () => {
    expect(keyTypeName('from-the-future')).toBe('from-the-future');
    expect(keyTypeName('constructor')).toBe('constructor');
  });
});
