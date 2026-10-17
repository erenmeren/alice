import type { Target } from '../api/types';
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Button } from '@mantine/core';
import { renderApp } from '../test/render';
import { DisabledFeature } from './DisabledFeature';

const withCap: Pick<Target, 'type' | 'capabilities'> = { type: 'nginx', capabilities: ['deploy_certificate'] };
const without: Pick<Target, 'type' | 'capabilities'> = { type: 'nginx', capabilities: [] };

describe('DisabledFeature', () => {
  it('leaves the control as it is when the server has the capability', async () => {
    await renderApp(
      <DisabledFeature target={withCap} capability="deploy_certificate">
        <Button>Deploy</Button>
      </DisabledFeature>,
    );
    const b = screen.getByRole('button', { name: 'Deploy' });
    expect(b).toBeEnabled();
    expect(b).not.toHaveAccessibleDescription();
    expect(screen.queryByTestId('disabled-feature')).not.toBeInTheDocument();
  });

  it('disables the control and describes it with the note', async () => {
    await renderApp(
      <DisabledFeature target={without} capability="deploy_certificate">
        <Button>Deploy</Button>
      </DisabledFeature>,
    );
    const b = screen.getByRole('button', { name: 'Deploy' });
    expect(b).toHaveAttribute('aria-disabled', 'true');
    expect(b).toHaveAccessibleDescription('Not available for Nginx servers yet');
  });

  it('shows the note as a tooltip on hover of the disabled control', async () => {
    await renderApp(
      <DisabledFeature target={without} capability="deploy_certificate">
        <Button>Deploy</Button>
      </DisabledFeature>,
    );
    await userEvent.hover(screen.getByTestId('disabled-feature'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('Not available for Nginx servers yet');
  });

  it('words the note in Turkish', async () => {
    await renderApp(
      <DisabledFeature target={without} capability="deploy_certificate">
        <Button>Deploy</Button>
      </DisabledFeature>,
      ['tr'],
    );
    expect(screen.getByRole('button', { name: 'Deploy' })).toHaveAccessibleDescription('Nginx sunucularında henüz kullanılamıyor');
  });

  it('stays focusable, ignores activation and shows the note on focus', async () => {
    const spy = vi.fn();
    await renderApp(
      <DisabledFeature target={without} capability="deploy_certificate">
        <Button onClick={spy}>Deploy</Button>
      </DisabledFeature>,
    );
    const b = screen.getByRole('button', { name: 'Deploy' });
    expect(b).toHaveAttribute('aria-disabled', 'true');
    expect(b).not.toBeDisabled();
    const note = 'Not available for Nginx servers yet';
    expect(document.getElementById(b.getAttribute('aria-describedby')!)).toHaveTextContent(note);
    await userEvent.tab();
    expect(b).toHaveFocus();
    expect(await screen.findByRole('tooltip')).toHaveTextContent(note);
    await userEvent.click(b);
    await userEvent.keyboard('{Enter}');
    await userEvent.keyboard(' ');
    expect(spy).not.toHaveBeenCalled();
  });

  it('with the capability sets no aria-disabled and calls the handler', async () => {
    const spy = vi.fn();
    await renderApp(
      <DisabledFeature target={withCap} capability="deploy_certificate">
        <Button onClick={spy}>Deploy</Button>
      </DisabledFeature>,
    );
    const b = screen.getByRole('button', { name: 'Deploy' });
    expect(b).not.toHaveAttribute('aria-disabled');
    await userEvent.click(b);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('prevents the default action of a link-styled control', async () => {
    await renderApp(
      <DisabledFeature target={without} capability="deploy_certificate">
        <Button component="a" href="/x">
          Go
        </Button>
      </DisabledFeature>,
    );
    const a = screen.getByRole('link', { name: 'Go' });
    const ev = new MouseEvent('click', { bubbles: true, cancelable: true });
    a.dispatchEvent(ev);
    expect(ev.defaultPrevented).toBe(true);
  });
});
