// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
/**
 * VITRINE du SDK Aurora (#1614) : chaque composant sur des FIXTURES SYNTHÉTIQUES
 * (aucune donnée réelle, aucun appel à la box). Jamais livrée dans le paquet.
 */
import { useState } from 'react';
import { createRoot } from 'react-dom/client';
import '@fontsource/orbitron/700.css';
import '@sbx/tokens';
import '../app/src/app.css';
import './vitrine.css';
import { SbxIcon, ICONES, baseArt, type Etat } from '@sbx/icons';
import { FluxHall, type EvenementFlux } from '@sbx/ui/FluxHall';
import lexie from '@sbx/art/characters/art/lexie.webp';

baseArt('./art/icons/', 128);

const MAINT = 1790700000;
const FLUX: EvenementFlux[] = [
  { id: '1', titre: 'Nœud « atelier » revenu en ligne', sous: 'Maillage · il y a 2 min', priorite: 5, at: MAINT, icone: 'maillage', etat: 'succes' },
  { id: '2', titre: 'Campagne de sondes bloquée', sous: 'Pare-feu · 42 tentatives', priorite: 9, at: MAINT - 300, icone: 'waf', etat: 'alerte' },
  { id: '3', titre: 'Réponse dans « Bistrot »', sous: 'BBS · Alice', priorite: 2, at: MAINT - 60, icone: 'bbs' },
  { id: '4', titre: 'Sauvegarde terminée', sous: 'Système · 1,2 Go', priorite: 1, at: MAINT - 900, icone: 'sauvegarde' },
];
const CATS = ['system', 'communication', 'security', 'media', 'cloud', 'iot'];
const COULEURS = ['--sbx-fond', '--sbx-surface', '--sbx-relief', '--sbx-trait', '--sbx-encre', '--sbx-doux', '--sbx-pale', '--sbx-cyan', '--sbx-vert', '--sbx-violet', '--sbx-ambre', '--sbx-alerte'];

function Vitrine() {
  const [etat, setEtat] = useState<Etat>('repos');
  const [cat, setCat] = useState('system');
  return (
    <main className="vitrine">
      <header><span className="kick">SDK Aurora · vitrine · fixtures synthétiques</span><h1>Vitrine Aurora</h1>
        <p>Chaque composant du SDK, rendu tel qu’Aurora l’affiche, sur des données d’exemple. Aucune donnée ne vient de la box.</p></header>

      <section><h2>Jetons</h2><div className="nuancier">
        {COULEURS.map(c => <div key={c}><i style={{ background: `var(${c})` }} /><code>{c}</code></div>)}</div></section>

      <section><h2>&lt;FluxHall&gt;</h2>
        <p className="note">Quatre événements en entrée : le Flux n’en garde que trois, le plus prioritaire d’abord.</p>
        <FluxHall evenements={FLUX} /></section>

      <section><h2>&lt;SbxIcon&gt;</h2>
        <div className="outils">
          {(['repos', 'alerte', 'succes'] as Etat[]).map(e => <button key={e} aria-pressed={etat === e} onClick={() => setEtat(e)}>{e}</button>)}
          <span className="sep" />
          {CATS.map(c => <button key={c} aria-pressed={cat === c} onClick={() => setCat(c)}>{c}</button>)}
        </div>
        {etat !== 'repos' && <p className="note">États calculés pour les icônes de l’accueil (priorité « hall »).</p>}
        <div className="cartes">
          {ICONES.filter(i => i.categorie === cat && (etat === 'repos' || i.priorite === 'hall')).map(i =>
            <span key={i.id} className="carte"><SbxIcon id={i.id} taille={64} etat={etat} /><span>{i.label}</span><code>{i.id}</code></span>)}
        </div></section>

      <section><h2>Guide</h2>
        <div className="guide"><img src={lexie} alt="Lexie" /><p><b>Lexie</b> — Bienvenue dans votre SBXOS.</p></div></section>
    </main>
  );
}
createRoot(document.getElementById('racine')!).render(<Vitrine />);
