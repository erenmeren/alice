import type { CSSProperties } from 'react';

// WRAP lets long technical strings (keys, fingerprints, paths, commands) break anywhere, so a
// screen never scrolls sideways at 375 px; the text itself (and what Copy copies) is unchanged.
export const WRAP: CSSProperties = { whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', wordBreak: 'break-word' };
