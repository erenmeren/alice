import { keyFileName, saveBlob } from './saveBlob';

describe('keyFileName', () => {
  it.each([
    ['Deploy Key', 'alice-deploy-key.key'],
    ['  CI/CD ~ prod  ', 'alice-ci-cd-prod.key'],
    ['İstanbul ğ', 'alice-stanbul.key'],
    ['...', 'alice-key.key'],
    ['a.b_c-d', 'alice-a.b_c-d.key'],
    ['../../etc/passwd', 'alice-etc-passwd.key'],
  ])('turns %j into %j', (label, name) => expect(keyFileName(label)).toBe(name));

  it('limits the length', () => expect(keyFileName('x'.repeat(200)).length).toBeLessThanOrEqual(70));
});

describe('saveBlob', () => {
  afterEach(() => vi.useRealTimers());

  it('clicks one temporary link and revokes its object URL on the next task', () => {
    vi.useFakeTimers();
    const create = vi.fn(() => 'blob:x');
    const revoke = vi.fn();
    Object.assign(URL, { createObjectURL: create, revokeObjectURL: revoke });
    const clicked: HTMLAnchorElement[] = [];
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      clicked.push(this);
    });
    saveBlob(new Blob(['x']), 'alice-k.key');
    expect(create).toHaveBeenCalledTimes(1);
    expect(clicked[0].download).toBe('alice-k.key');
    expect(clicked[0].isConnected).toBe(false);
    expect(revoke).not.toHaveBeenCalled();
    vi.runAllTimers();
    expect(revoke).toHaveBeenCalledWith('blob:x');
    click.mockRestore();
  });
});
