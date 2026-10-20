import { screen } from '@testing-library/react';
import type { Deployment, DeploymentVerification } from '../api/types';
import { deploymentFixture } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderApp } from '../test/render';
import { DeploymentOutcome } from './DeploymentView';

const trusted: DeploymentVerification = { level: 3, failure: '', trust: { status: 'trusted', error: '', port: null, store: 'acme_bundle', enforced: true } };

async function outcome(d: Deployment, headline: string): Promise<HTMLElement> {
  await renderApp(<DeploymentOutcome d={d} />);
  return (await screen.findByText(headline)).closest('.mantine-Alert-root') as HTMLElement;
}

// R51: the outcome claims what the verification proved, and a served chain that is not trusted is a visible warning.
describe('DeploymentOutcome and the trust of the served chain', () => {
  it('a trusted chain: a success that says the chain was verified', async () => {
    const alert = await outcome(deploymentFixture({ status: 'succeeded', verification: trusted }), 'The new certificate is live and verified.');
    expect(alert.getAttribute('style')).toContain('--alert-bg: var(--alice-success-soft)');
    expect(alert).toHaveTextContent("Alice also verified the website's certificate chain against a trusted root.");
    expectNoRawKeys();
  });

  it('an untrusted chain Alice could not hold against a known root: a warning with the reason, never "verified"', async () => {
    const d = deploymentFixture({
      status: 'succeeded',
      verification: { level: 2, failure: '', trust: { status: 'untrusted', error: 'unknown_authority', port: 8443, store: 'system', enforced: false } },
    });
    const alert = await outcome(d, "The new certificate is served, but the website's certificate chain is not trusted.");
    expect(alert.getAttribute('style')).toContain('--alert-bg: var(--alice-warning-soft)');
    expect(alert).toHaveTextContent('The chain leads to a root certificate Alice does not trust (port 8443).');
    expect(alert).not.toHaveTextContent('live and verified');
    expectNoRawKeys();
  });

  it('a name mismatch with a known root is a warning too, with its own headline', async () => {
    const d = deploymentFixture({
      status: 'succeeded',
      verification: { level: 2, failure: '', trust: { status: 'untrusted', error: 'name_mismatch', port: 443, store: 'system', enforced: true } },
    });
    const alert = await outcome(d, 'The new certificate is served, but it does not cover the name the website was checked with.');
    expect(alert.getAttribute('style')).toContain('--alert-bg: var(--alice-warning-soft)');
    expect(alert).toHaveTextContent('The certificate does not cover the name the website was checked with (port 443).');
  });

  it('an older helper did not report the chain: the success says the chain was not checked', async () => {
    const d = deploymentFixture({ status: 'succeeded', verified: 'local', verification: { level: 2, failure: '', trust: { status: 'unchecked', error: '', port: null, store: 'system', enforced: true } } });
    const alert = await outcome(d, 'The new certificate is live and verified.');
    expect(alert).toHaveTextContent("Alice did not check the certificate chain: the server's alice-helper is older than 1.10.0.");
  });
});
