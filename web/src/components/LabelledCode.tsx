import { Code, Text } from '@mantine/core';
import { WRAP } from './wrap';

// LabelledCode shows "Label: <data>": text is a translated "Label: {{value}}" string rendered with
// an empty value, and the data (a name, path or fingerprint) follows in <Code>, never translated or
// case-changed (A-11), so a name such as www.example.test is not mistaken for an untranslated key.
export function LabelledCode({ text, value, size = 'sm' }: { text: string; value: string; size?: 'xs' | 'sm' }) {
  return (
    <Text size={size} style={WRAP}>
      {text.replace(/\s*$/, ' ')}
      <Code translate="no">{value}</Code>
    </Text>
  );
}
