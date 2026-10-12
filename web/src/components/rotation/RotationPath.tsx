import { useTranslation } from 'react-i18next';
import classes from '../../pages/Rotations.module.css';

// PHASE_OF is the design's four phases (generate, deploy and verify, overlap, retire) a moving run is in; a completed
// run has passed all four. Any other status (undoing, undone, needs attention, cancelled, unknown) has no place here.
const PHASE_OF: Record<string, number> = { dry_run_notified: 0, adding_new: 1, verifying_new: 1, overlap: 2, removing_old: 3, completed: 4 };
const PHASES = ['generate', 'deploy', 'overlap', 'retire'] as const;

// hasRotationPath says whether RotationPath draws a path for this status, so a page can leave out its empty frame.
export function hasRotationPath(status: string): boolean {
  return Object.hasOwn(PHASE_OF, status);
}

// RotationPath is the design's rotation progress (.rotation-path): four phases, each with its number, name and state in
// words (the rule's color only repeats it). A run that stopped, is undoing or is not known is never drawn as progress:
// the component renders nothing and the page shows the status badge and the reason instead. A run the license paused
// says Paused on its current phase, never In progress. `name` (the policy) tells several paths on one page apart.
export function RotationPath({ status, paused = false, name }: { status: string; paused?: boolean; name?: string }) {
  const { t } = useTranslation();
  if (!hasRotationPath(status)) return null;
  const at = PHASE_OF[status];
  const current = paused ? 'rotation.step.paused' : 'rotation.page.phaseCurrent';
  return (
    // role="list": list-style: none makes WebKit drop the list semantics (as OperationTimeline does).
    <ol role="list" className={classes.path} aria-label={name ? t('rotation.page.pathNamed', { name }) : t('rotation.page.path')}>
      {PHASES.map((p, i) => {
        const state = i < at ? 'done' : i === at ? 'current' : 'next';
        return (
          <li key={p} className={classes.phase} data-state={state} aria-current={state === 'current' ? 'step' : undefined}>
            <span className={classes.phaseName}>
              <span className={classes.phaseNumber}>{`0${i + 1}`}</span> · {t(`rotation.page.phase.${p}`)}
            </span>
            <span className={classes.phaseState}>{t(state === 'done' ? 'rotation.page.phaseDone' : state === 'current' ? current : 'rotation.page.phaseNext')}</span>
          </li>
        );
      })}
    </ol>
  );
}
