// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
/** Réglages de l'appareil + « à propos » (#1614). Rien ne quitte l'appareil. */
import { useEffect, useState } from 'react';
import { sbxFetch, type Manifeste } from '@sbx/data';

const CLE = 'sbxos.v2.appareil';
type Prefs = { rendu?: 'complet' | 'leger'; densite?: 'normale' | 'compacte' };

export function lisPrefs(): Prefs {
  try { return JSON.parse(localStorage.getItem(CLE) || '{}') as Prefs; } catch { return {}; }
}
function ecris(p: Prefs) { try { localStorage.setItem(CLE, JSON.stringify(p)); } catch { /* stockage refusé */ } }

export function appliquePrefs(p: Prefs = lisPrefs()) {
  const r = document.documentElement;
  if (p.rendu) r.dataset.rendu = p.rendu;
  r.dataset.densite = p.densite ?? 'normale';
}

export function Reglages({ man, ferme }: { man: Manifeste | null; ferme: () => void }) {
  const [p, setP] = useState<Prefs>(lisPrefs);
  const [version, setVersion] = useState<string>('…');
  useEffect(() => { sbxFetch<{ version: string; canal: string }>('/sbxos/aurora/version.json')
    .then(v => setVersion(v ? `${v.version} (${v.canal})` : 'inconnue')); }, []);
  function change(n: Prefs) { const q = { ...p, ...n }; setP(q); ecris(q); appliquePrefs(q); }
  return (
    <div className="panneau" role="dialog" aria-label="Réglages">
      <div className="panneau-t"><h2>Réglages</h2><button type="button" onClick={ferme}>Fermer</button></div>
      <fieldset><legend>Rendu</legend>
        {(['complet', 'leger'] as const).map(r => (
          <label key={r}><input type="radio" name="rendu" checked={(p.rendu ?? document.documentElement.dataset.rendu) === r}
                 onChange={() => change({ rendu: r })} /> {r === 'complet' ? 'Complet' : 'Léger (moins d’animation)'}</label>))}
      </fieldset>
      <fieldset><legend>Densité</legend>
        {(['normale', 'compacte'] as const).map(d => (
          <label key={d}><input type="radio" name="densite" checked={(p.densite ?? 'normale') === d}
                 onChange={() => change({ densite: d })} /> {d === 'normale' ? 'Normale' : 'Compacte'}</label>))}
      </fieldset>
      <dl className="apropos">
        <dt>Version</dt><dd>{version}</dd>
        <dt>Rôle</dt><dd>{man?.role ?? '—'}</dd>
        <dt>Réseau local</dt><dd>{man ? (man.lan ? 'oui' : 'non') : '—'}</dd>
        <dt>Box</dt><dd>{man?.domaine ?? '—'}</dd>
      </dl>
      <a href="/sbxos/">Revenir au SBX OS classique</a>
    </div>
  );
}
