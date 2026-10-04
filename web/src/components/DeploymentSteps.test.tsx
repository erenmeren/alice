import { screen, within } from '@testing-library/react';
import { stepFixture } from '../test/fixtures';
import { renderApp } from '../test/render';
import { DeploymentSteps, currentStep } from './DeploymentSteps';

function row(name: string): HTMLElement {
  return within(screen.getByRole('list', { name: 'Steps' })).getByText(name).closest('li') as HTMLElement;
}

describe('DeploymentSteps', () => {
  it('shows Write as done only when the key and the certificate are written, and failed when either failed', async () => {
    const view = await renderApp(<DeploymentSteps status="running" steps={[stepFixture(1, 'backup'), stepFixture(2, 'write_key')]} />);
    expect(row('Write')).toHaveTextContent('Running');
    view.unmount();
    const view2 = await renderApp(<DeploymentSteps status="running" steps={[stepFixture(1, 'write_key'), stepFixture(2, 'write_cert')]} />);
    expect(row('Write')).toHaveTextContent('Done');
    view2.unmount();
    await renderApp(<DeploymentSteps status="failed" steps={[stepFixture(1, 'write_key'), stepFixture(2, 'write_cert', 'failed')]} />);
    expect(row('Write')).toHaveTextContent('Failed');
  });

  it('uses the last event of a step and says "Not run" for steps an ended deployment never reached', async () => {
    await renderApp(
      <DeploymentSteps status="failed" steps={[stepFixture(1, 'backup', 'started'), stepFixture(2, 'backup', 'ok'), stepFixture(3, 'config_test', 'failed')]} />,
    );
    expect(row('Backup')).toHaveTextContent('Done');
    expect(row('Check')).toHaveTextContent('Failed');
    expect(row('Reload')).toHaveTextContent('Not run');
    expect(row('Verify')).toHaveTextContent('Not run');
  });

  it('shows the pre-check only in detail, and lists journal and an unknown step after the five', async () => {
    const steps = [stepFixture(1, 'verify_current'), stepFixture(2, 'backup'), stepFixture(3, 'journal', 'failed'), stepFixture(4, 'brand_new', 'ok')];
    const plain = await renderApp(<DeploymentSteps status="rolled_back" steps={steps} />);
    expect(within(screen.getByRole('list', { name: 'Steps' })).queryByText('Check the current certificate')).not.toBeInTheDocument();
    expect(row('Record the change')).toHaveTextContent('Failed');
    expect(row('Other step')).toHaveTextContent('brand_new');
    plain.unmount();
    await renderApp(<DeploymentSteps status="rolled_back" steps={steps} detailed />);
    const items = within(screen.getByRole('list', { name: 'Steps' })).getAllByRole('listitem');
    expect(items[0]).toHaveTextContent('Check the current certificate');
    expect(items[0]).toHaveTextContent('Done');
    expect(items[1]).toHaveTextContent('Backup');
  });

  it('gives a status it does not know the neutral text', async () => {
    await renderApp(<DeploymentSteps status="running" steps={[{ ...stepFixture(1, 'backup'), status: '' }]} />);
    expect(row('Backup')).toHaveTextContent('Unknown');
  });

  it('names the step reached last, Write for the key and the certificate', () => {
    expect(currentStep([])).toBeNull();
    expect(currentStep([stepFixture(1, 'backup'), stepFixture(2, 'write_cert')])).toBe('deployments.steps.write');
    expect(currentStep([stepFixture(2, 'reload'), stepFixture(1, 'backup')])).toBe('deployments.steps.reload');
    expect(currentStep([stepFixture(1, 'brand_new')])).toBe('deployments.steps.unknown');
  });
});
