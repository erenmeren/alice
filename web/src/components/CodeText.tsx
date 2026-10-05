import { Code } from '@mantine/core';
import { Fragment, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';

// MARK stands in for the value while a translated sentence is rendered, so the sentence keeps its
// own word order (Turkish puts words after the value) and the value can still be shown in <Code>.
const MARK = '\u0001';

// CodeText renders one translated sentence whose {{param}} is technical data (an ID, a name, a role,
// a path): the data appears in <Code translate="no">, never translated or case-changed (A-11). It is
// always text, never markup. The sentence is ONE key, not assembled from pieces.
export function CodeText({ i18nKey, param, value, params = {} }: { i18nKey: string; param: string; value: string; params?: Record<string, string | number> }) {
  const { t } = useTranslation();
  const text = t(i18nKey, { ...params, [param]: MARK });
  const parts = text.split(MARK);
  const nodes: ReactNode[] = [];
  parts.forEach((part, i) => {
    if (i > 0) nodes.push(<Code key={`c${i}`} translate="no" style={{ overflowWrap: 'anywhere', wordBreak: 'break-word', whiteSpace: 'pre-wrap' }}>{value}</Code>);
    if (part) nodes.push(<Fragment key={`t${i}`}>{part}</Fragment>);
  });
  return <>{nodes}</>;
}
