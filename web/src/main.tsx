import '@mantine/core/styles.css';
import './design/tokens.css';
import './theme.css';
import './design/base.css';
import { readCspNonce, shareCspNonce } from './csp';
import { applyDensity, readDensity } from './preferences';
import { startApp } from './start';

shareCspNonce(readCspNonce());
applyDensity(readDensity());

void startApp(document.getElementById('root')!);
