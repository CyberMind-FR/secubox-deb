// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Vitrine du SDK : construite à part (dist-vitrine/), jamais dans le paquet.
import { defineConfig, mergeConfig } from 'vite';
import app from '../app/vite.config';
import { fileURLToPath } from 'node:url';
const ici = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const c = mergeConfig(app, defineConfig({ root: ici('.'), base: './', build: { outDir: ici('../dist-vitrine') } }));
// L'entrée REMPLACE celle de l'app (mergeConfig fusionnerait les deux).
c.build!.rollupOptions = { ...c.build!.rollupOptions, input: { vitrine: ici('index.html') } };
export default c;
