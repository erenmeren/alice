import { Loader } from '@mantine/core';
import type { ReactNode } from 'react';
import { Icon, type IconName } from '../../design/Icon';
import classes from './ui.module.css';

export type StepState = 'done' | 'failed' | 'running' | 'waiting' | 'skipped' | 'notRun' | 'unknown';

export interface TimelineStep {
  id: string;
  title: ReactNode;
  detail?: ReactNode;
  state: StepState;
  stateLabel: string;
  time?: ReactNode;
  dataAttrs?: Record<string, string>;
}

export interface OperationTimelineProps {
  steps: TimelineStep[];
  label: string;
}

const MARKER: Record<Exclude<StepState, 'running'>, IconName> = {
  done: 'Check',
  failed: 'CircleX',
  waiting: 'Clock3',
  skipped: 'CircleOff',
  notRun: 'Circle',
  unknown: 'CircleHelp',
};

// OperationTimeline is the design's step sequence. The state is always written out (stateLabel) next to its marker;
// the marker alone never carries the meaning. A step that was not run says so — never a green tick (IMPLEMENTATION §5).
export function OperationTimeline({ steps, label }: OperationTimelineProps) {
  return (
    <ol className={classes.timeline} aria-label={label}>
      {steps.map((s) => (
        <li key={s.id} className={classes.timelineStep} {...s.dataAttrs}>
          <span className={classes.stepMarker} data-state={s.state} aria-hidden="true">
            {s.state === 'running' ? <Loader size={12} /> : <Icon name={MARKER[s.state]} size={13} />}
          </span>
          <div className={classes.stepText}>
            <div className={classes.stepTitle}>{s.title}</div>
            <div className={classes.stepStatus} data-role="step-status">
              {s.stateLabel}
            </div>
            {s.detail && <div className={classes.stepDetail}>{s.detail}</div>}
          </div>
          {s.time && <span className={classes.stepTime}>{s.time}</span>}
        </li>
      ))}
    </ol>
  );
}
