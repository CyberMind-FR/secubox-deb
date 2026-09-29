// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
/**
 * AIGUILLAGE (#1616), sans React. Encadrée par le Hall SANS mega=1 (la carte
 * 420 px, chargée à chaque visite du Hall) → la CARTE LÉGÈRE ; sinon l'app.
 * Les deux sont des morceaux séparés : la carte ne télécharge jamais React.
 */
import { renduInitial } from '@sbx/tokens';

document.documentElement.dataset.rendu = renduInitial();
const q = new URLSearchParams(location.search);
let encadree = true;
try { encadree = window.top !== window; } catch { /* cadre d'une autre origine : encadrée */ }
if (encadree && q.get('mega') !== '1') import('./carte');
else import('./racine');
