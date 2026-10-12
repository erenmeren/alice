import { createElement } from 'react';
import { ICONS, type IconName } from './icons';

export type { IconName };

export interface IconProps {
  name: IconName;
  size?: number;
  className?: string;
}

// Icon draws one Lucide icon of the design (1.7 px stroke, round caps). It is decorative: the text next to it carries
// the meaning (design rule "Status = label + icon + color"), so it is hidden from assistive technology.
export function Icon({ name, size = 18, className }: IconProps) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {ICONS[name].map(([tag, attrs], i) => createElement(tag, { key: i, ...attrs }))}
    </svg>
  );
}
