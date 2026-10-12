import { useTranslation } from 'react-i18next';
import classes from '../../pages/Rotations.module.css';

// PHASE_OF is the design's four phases (generate, deploy and verify, overlap, retire) a moving run is in; a completed
// run has passed all four. Any other status (undoing, undone, needs attention, cancelled, unknown) has no place here.
const PHASE_OF: Record<string, number> = { dry_run_notified: 0, adding_new: 1, verifying_new: 1, overlap: 2, removing_old: 3, completed: 4 };
const PHASES = ['generate', 'deploy', 'overlap', 'retire'] as const;

// RotationPath is the design's rotation progress (.rotation-path): four phases, each with its number, name and state in
// words (the rule's color only repeats it). A run that stopped, is undoing or is not known is never drawn as progress:
// the component renders nothing and the page shows the status badge and the reason instead.
export function RotationPath({ status }: { status: string }) {
  const { t } = useTranslation();
  const at = PHASE_OF[status];
  if (at === undefined) return null;
  return (
    <ol className={classes.path} aria-label={t('rotation.page.path')}>
      {PHASES.map((p, i) => {
        const state = i < at ? 'done' : i === at ? 'current' : 'next';
        return (
          <li key={p} className={classes.phase} data-state={state}>
            <span className={classes.phaseName}>
              <span className={classes.phaseNumber}>{`0${i + 1}`}</span> · {t(`rotation.page.phase.${p}`)}
            </span>
            <span className={classes.phaseState}>{t(state === 'done' ? 'rotation.page.phaseDone' : state === 'current' ? 'rotation.page.phaseCurrent' : 'rotation.page.phaseNext')}</span>
          </li>
        );
      })}
    </ol>
  );
}
