// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
/**
 * LIEU / THÉÂTRE (#1614) : un module s'ouvre SUR PLACE, plein écran, avec un
 * lien permanent « Ouvrir dans un onglet ». Cadre sandboxé, sans
 * allow-top-navigation : un service ne peut pas emporter Aurora.
 */
import { useEffect, useRef } from 'react';

export function Lieu({ titre, url, ferme }: { titre: string; url: string; ferme: () => void }) {
  const bouton = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const avant = document.activeElement as HTMLElement | null;
    bouton.current?.focus();
    const k = (e: KeyboardEvent) => { if (e.key === 'Escape') ferme(); };
    addEventListener('keydown', k);
    return () => { removeEventListener('keydown', k); avant?.focus(); };
  }, [ferme]);
  return (
    <div className="theatre" role="dialog" aria-modal="true" aria-label={titre}>
      <div className="theatre-barre">
        <b>{titre}</b>
        <a href={url} target="_blank" rel="noopener">Ouvrir dans un onglet ↗</a>
        <button ref={bouton} type="button" onClick={ferme}>Fermer (Échap)</button>
      </div>
      <iframe src={url} title={titre}
              sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-downloads"
              allow="autoplay; fullscreen" />
    </div>
  );
}
