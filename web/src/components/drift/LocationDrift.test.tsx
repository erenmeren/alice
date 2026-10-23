import { screen } from '@testing-library/react';
import { driftedObservationFixture, observationFixture, sessionFor, sessionHandlers } from '../../test/fixtures';
import { expectNoRawKeys } from '../../test/i18nAssert';
import { renderWithStepUp } from '../../test/render';
import { server } from '../../test/server';
import { DriftControls, ObservationFacts } from './LocationDrift';

beforeEach(() => server.use(...sessionHandlers(sessionFor('admin'))));

// R62, Ruling 20: a Windows binding's observation is worded for a binding, with the cause of its drift.
const CAUSES = [
  ['binding_repointed', 'en', 'Cause: the binding was changed to another certificate outside Alice.', 'tr', 'Neden: bağlama Alice dışında başka bir sertifikaya çevrildi.'],
  ['cert_removed', 'en', "Cause: the certificate was removed from the server's certificate store. Alice does not put it back; deploy a certificate to this binding.", 'tr', 'Neden: sertifika sunucunun sertifika deposundan kaldırıldı. Alice onu geri koymaz; bu bağlamaya bir sertifika dağıtın.'],
  ['key_unusable', 'en', 'Cause: Windows cannot use the private key of the certificate. Deploy a certificate to this binding.', 'tr', 'Neden: Windows sertifikanın özel anahtarını kullanamıyor. Bu bağlamaya bir sertifika dağıtın.'],
] as const;

describe('ObservationFacts of a Windows binding', () => {
  it('words the file fact as the binding at the last scan', async () => {
    await renderWithStepUp(<ObservationFacts observation={observationFixture()} windows />);
    expect(screen.getByTestId('fact-file')).toHaveTextContent(/^Binding \(last scan\): the right certificate/);
    expect(screen.queryByText(/The file held/)).not.toBeInTheDocument();
    expectNoRawKeys(document.body);
  });

  it('says so when no scan has read the binding', async () => {
    await renderWithStepUp(<ObservationFacts observation={observationFixture({ file: null })} windows />);
    expect(screen.getByTestId('fact-file')).toHaveTextContent('Binding (last scan): not read yet.');
  });

  it.each(CAUSES)('shows the cause %s in English and Turkish', async (cause, _en, enText, _tr, trText) => {
    const o = driftedObservationFixture({ drift_cause: cause });
    const en = await renderWithStepUp(<ObservationFacts observation={o} windows />);
    expect(screen.getByTestId('drift-cause')).toHaveTextContent(enText);
    en.unmount();
    await renderWithStepUp(<ObservationFacts observation={o} windows />, ['tr-TR']);
    expect(screen.getByTestId('drift-cause')).toHaveTextContent(trText);
    expectNoRawKeys(document.body);
  });

  it('shows the AutoCertRebind hint only when the server runs the task', async () => {
    const view = await renderWithStepUp(<ObservationFacts observation={driftedObservationFixture({ drift_cause: 'binding_repointed', autocertrebind: true })} windows />);
    expect(screen.getByTestId('drift-autocertrebind')).toHaveTextContent('This server runs the AutoCertRebind task, which can bind a certificate by itself and may undo a repair.');
    view.unmount();
    await renderWithStepUp(<ObservationFacts observation={driftedObservationFixture({ drift_cause: 'binding_repointed' })} windows />);
    expect(screen.queryByTestId('drift-autocertrebind')).not.toBeInTheDocument();
  });

  it('keeps the texts of a certificate file unchanged', async () => {
    await renderWithStepUp(<ObservationFacts observation={driftedObservationFixture()} />);
    expect(screen.getByTestId('fact-file')).toHaveTextContent('The file held the right certificate'.slice(0, 13));
    expect(screen.getByTestId('fact-file')).not.toHaveTextContent('Binding (last scan)');
    expect(screen.queryByTestId('drift-cause')).not.toBeInTheDocument();
    expect(screen.queryByTestId('drift-autocertrebind')).not.toBeInTheDocument();
  });
});

describe('DriftControls of a Windows binding', () => {
  const controls = (o: ReturnType<typeof driftedObservationFixture>) => (
    <DriftControls locationId="loc-w" label="www.example.test" observation={o} admin canOperate locked={false} onChanged={() => {}} />
  );
  it('offers Repair for a repointed binding and none for a removed certificate or an unusable key', async () => {
    const view = await renderWithStepUp(controls(driftedObservationFixture({ drift_cause: 'binding_repointed' })));
    expect(screen.getByRole('button', { name: 'Repair www.example.test' })).toBeInTheDocument();
    view.unmount();
    for (const cause of ['cert_removed', 'key_unusable'] as const) {
      const v = await renderWithStepUp(controls(driftedObservationFixture({ drift_cause: cause, repair_available: false })));
      expect(screen.queryByRole('button', { name: /^Repair/ })).not.toBeInTheDocument();
      v.unmount();
    }
  });
});
