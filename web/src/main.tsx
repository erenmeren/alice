import '@mantine/core/styles.css';
import { readCspNonce, shareCspNonce } from './csp';
import { startApp } from './start';

shareCspNonce(readCspNonce());

void startApp(document.getElementById('root')!);
