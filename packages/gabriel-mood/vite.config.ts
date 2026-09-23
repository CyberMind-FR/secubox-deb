// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

export default defineConfig({
  plugins: [svelte()],
  // BASE RELATIVE, ET C'EST CE QUI PERMET LES DEUX SERVICES À LA FOIS : la
  // même construction est servie à la racine de `mood.gk2.secubox.in` ET sous
  // `/gabriel-mood/` de l'admin. Une base absolue aurait forcé à choisir, ou à
  // construire deux fois.
  base: './',
  root: 'webui',
  build: {
    outDir: '../dist',
    emptyOutDir: true,
    sourcemap: false,
    target: 'es2022',
    rollupOptions: {
      // DEUX ENTRÉES : le cockpit (/mega) et la carte du Hall (/micro). Elles
      // partagent les composants, le style et surtout le lien de
      // synchronisation — les livrer séparément dupliquerait tout.
      input: {
        index: 'webui/index.html',
        micro: 'webui/micro.html',
      },
    },
  },
  server: {
    port: 5178,
    proxy: {
      '/api': 'http://localhost:8099',
      '/ws': { target: 'ws://localhost:8099', ws: true },
    },
  },
})
