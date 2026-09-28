// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
import { createRoot } from 'react-dom/client';
import '@fontsource/orbitron/700.css';
import { renduInitial } from '@sbx/tokens';
import './app.css';
import { App } from './App';

document.documentElement.dataset.rendu = renduInitial();
createRoot(document.getElementById('racine')!).render(<App />);
