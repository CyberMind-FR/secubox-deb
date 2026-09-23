// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte'

export default {
  preprocess: vitePreprocess(),
  compilerOptions: {
    // Svelte 5 : les runes, explicitement, pour que rien ne bascule en mode
    // de compatibilité sans qu'on l'ait décidé.
    runes: true,
  },
}
