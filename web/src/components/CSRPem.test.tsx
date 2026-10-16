import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { csrFixture } from '../test/fixtures';
import { renderApp } from '../test/render';
import { CSRPem, csrFileName } from './CSRPem';

describe('CSRPem', () => {
  it('downloads the request under a safe file name and frees the link afterwards', async () => {
    const create = vi.fn(() => 'blob:csr');
    const revoke = vi.fn();
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      expect(this.download).toBe('wildcard.example.com.csr');
      expect(this.href).toBe('blob:csr');
    });
    Object.assign(URL, { createObjectURL: create, revokeObjectURL: revoke });
    await renderApp(<CSRPem csr={csrFixture({ common_name: '*.example.com' })} />);
    await userEvent.click(screen.getByRole('button', { name: 'Download request' }));
    expect(click).toHaveBeenCalledTimes(1);
    await vi.waitFor(() => expect(revoke).toHaveBeenCalledWith('blob:csr'));
    click.mockRestore();
  });

  it('never makes a file name with a path or a leading dot', () => {
    expect(csrFileName('../etc/passwd')).toBe('_etc_passwd.csr');
    expect(csrFileName('...')).toBe('request.csr');
  });
});
