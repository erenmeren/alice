import type { Incident } from '../api/incidents';
import type { Tone } from '../components/ui';
import type { IconName } from '../design/Icon';

// The badge of each incident state, shared by the incident page and the Incidents list.
export const STATE_TONE: Record<Incident['state'], Tone> = {
  awaiting_replacement: 'warning',
  ordering: 'info',
  deploying: 'info',
  revoking: 'info',
  needs_attention: 'danger',
  completed: 'success',
  closed: 'neutral',
};
export const STATE_ICON: Record<Incident['state'], IconName> = {
  awaiting_replacement: 'Clock3',
  ordering: 'RefreshCw',
  deploying: 'Rocket',
  revoking: 'ShieldAlert',
  needs_attention: 'CircleAlert',
  completed: 'CircleCheck',
  closed: 'CircleDot',
};
