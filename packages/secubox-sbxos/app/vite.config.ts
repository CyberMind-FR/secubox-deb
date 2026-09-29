// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';

const ici = (p: string) => fileURLToPath(new URL(p, import.meta.url));

// Servi par le Hall sous /sbxos/ (même origine = même clé d'appareil).
// Aperçu : dist/aurora/index.html ; fichiers hachés : dist/assets/.
export default defineConfig({
  root: ici('.'),
  base: '/sbxos/',
  plugins: [react()],
  resolve: {
    alias: {
      '@sbx/tokens': ici('../sbx-sdk/tokens/index.ts'),
      '@sbx/icons': ici('../sbx-sdk/icons/index.tsx'),
      '@sbx/data': ici('../sbx-sdk/data/index.ts'),
      '@sbx/protocol': ici('../sbx-sdk/protocol/enfant.ts'),
      '@sbx/hote': ici('../sbx-sdk/protocol/hote.ts'),
      '@sbx/ui': ici('../sbx-sdk/ui'),
      '@sbx/art': ici('../sbx-sdk'),
    },
  },
  server: { fs: { allow: [ici('../..')] } },
  test: { include: ['sbx-sdk/**/tests/*.test.ts'], root: ici('..') },
  build: {
    outDir: ici('../dist'),
    emptyOutDir: true,
    target: 'es2022',
    sourcemap: false,
    assetsDir: 'assets',
    assetsInlineLimit: (f) => !/\.(woff2?|ttf|otf)$/.test(f) && undefined,
    rollupOptions: { input: { aurora: ici('aurora/index.html') } },
  },
});
