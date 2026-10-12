import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderApp } from '../test/render';
import { RecoveryCodes } from './RecoveryCodes';
import auth from './auth/auth.module.css';

const codes = ['AAAA-BBBB-CCCC-DDDD', 'EEEE-FFFF-GGGG-HHHH'];

describe('RecoveryCodes', () => {
  it('lists the codes once and offers a copy and a download option', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    await renderApp(<RecoveryCodes codes={codes} onContinue={() => undefined} />);
    expect(screen.getAllByRole('code')).toHaveLength(2);
    await userEvent.click(screen.getByRole('button', { name: 'Copy codes' }));
    expect(writeText).toHaveBeenCalledWith(codes.join('\n'));
    expect(await screen.findByText('Copied')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Download codes' })).toBeInTheDocument();
  });

  it('releases the download link only after the browser started the download', async () => {
    const createObjectURL = vi.fn().mockReturnValue('blob:codes');
    const revokeObjectURL = vi.fn();
    vi.stubGlobal('URL', Object.assign(URL, { createObjectURL, revokeObjectURL }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
    try {
      await renderApp(<RecoveryCodes codes={codes} onContinue={() => undefined} />);
      vi.useFakeTimers();
      screen.getByRole('button', { name: 'Download codes' }).click();
      expect(click).toHaveBeenCalledTimes(1);
      expect(revokeObjectURL).not.toHaveBeenCalled();
      vi.runAllTimers();
      expect(revokeObjectURL).toHaveBeenCalledWith('blob:codes');
    } finally {
      vi.useRealTimers();
      click.mockRestore();
      vi.unstubAllGlobals();
    }
  });

  it('shows the ten codes in a mono grid and continues only after the codes are saved', async () => {
    const ten = Array.from({ length: 10 }, (_, i) => `AAAA-BBBB-CCCC-000${i}`);
    const onContinue = vi.fn();
    await renderApp(<RecoveryCodes codes={ten} onContinue={onContinue} />);
    const list = screen.getByTestId('recovery-codes');
    expect(list).toHaveClass(auth.codes);
    expect(within(list).getAllByRole('listitem')).toHaveLength(10);
    expect(list.textContent!.match(/[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}/g)).toEqual(ten);
    const next = screen.getByRole('button', { name: 'Continue' });
    expect(next).toBeDisabled();
    await userEvent.click(screen.getByLabelText('I saved these codes in a safe place'));
    expect(next).toBeEnabled();
    await userEvent.click(next);
    expect(onContinue).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('button', { name: 'Copy codes' }).querySelector('svg')).not.toBeNull();
    expect(screen.getByRole('button', { name: 'Download codes' }).querySelector('svg')).not.toBeNull();
  });
});
