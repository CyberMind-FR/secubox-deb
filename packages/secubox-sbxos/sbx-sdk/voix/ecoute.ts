// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
/**
 * ÉCOUTE (#1656) : on enregistre, et on COUPE 1 s après la fin de la parole
 * (détection d'activité vocale par le niveau RMS) — l'audio envoyé est aussi
 * court que la commande. Les commandes courantes sont reconnues SUR LA BOX
 * (Vosk, grammaire fermée) par /api/v1/voice/asr : la CSP d'Aurora reste
 * stricte (Vosk en WASM exigerait 'unsafe-eval').
 */
const SEUIL = 0.02, SILENCE_MS = 1000, SANS_PAROLE_MS = 5000, MAX_MS = 8000;

let arretManuel: () => void = () => {};
/** Arrêt anticipé (second clic sur le micro). */
export const arreteEcoute = () => arretManuel();

export async function ecoute(flux: MediaStream, onNiveau?: (n: number) => void): Promise<Blob> {
  const ctx = new AudioContext();
  const src = ctx.createMediaStreamSource(flux);
  const an = ctx.createAnalyser(); an.fftSize = 1024; src.connect(an);
  const morceaux: Blob[] = [];
  const rec = new MediaRecorder(flux);
  rec.ondataavailable = e => morceaux.push(e.data);
  const buf = new Float32Array(an.fftSize);
  const t0 = performance.now(); let parle = false, dernier = t0;
  await new Promise<void>((fini) => {
    rec.onstop = () => fini();
    rec.start();
    const tic = setInterval(() => {
      an.getFloatTimeDomainData(buf);
      let s = 0; for (const x of buf) s += x * x;
      const rms = Math.sqrt(s / buf.length); onNiveau?.(Math.min(1, rms * 10));
      const t = performance.now();
      if (rms > SEUIL) { parle = true; dernier = t; }
      if ((parle && t - dernier > SILENCE_MS) || (!parle && t - t0 > SANS_PAROLE_MS) || t - t0 > MAX_MS) {
        clearInterval(tic); if (rec.state === 'recording') rec.stop();
      }
    }, 50);
    arretManuel = () => { clearInterval(tic); if (rec.state === 'recording') rec.stop(); };
  });
  src.disconnect(); ctx.close().catch(() => {});
  flux.getTracks().forEach(t => t.stop());
  return new Blob(morceaux, { type: rec.mimeType });
}
