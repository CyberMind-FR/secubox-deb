// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
/**
 * SBXOS Aurora — TRACEUR (#1611). Rail des 5 Espaces, scène du Hall, vrai
 * pseudo, entrée sans mot de passe. L'art est provisoire (découpes de la
 * maquette) sauf les icônes, qui sont les masters définitifs.
 */
import { useEffect, useState } from 'react';
import { LazyMotion, domAnimation, m, AnimatePresence } from 'framer-motion';
import { SbxIcon } from '@sbx/icons';
import { entrer, moi, type Entree } from '@sbx/data';
import hero from '@sbx/art/environments/art/hero.webp';
import lexie from '@sbx/art/characters/art/lexie.webp';
import neo from '@sbx/art/characters/art/neo.webp';
import actor from '@sbx/art/characters/art/actor.webp';
import lyrion from '@sbx/art/characters/art/lyrion.webp';
import zia from '@sbx/art/characters/art/zia.webp';

type Espace = 'hall' | 'atelier' | 'securite' | 'media' | 'maison';
const ESPACES: { id: Espace; nom: string; icone: string; guide: string; portrait: string; phrase: string }[] = [
  { id: 'hall', nom: 'Hall', icone: 'hall', guide: 'Lexie', portrait: lexie, phrase: 'Bienvenue dans votre SBXOS.' },
  { id: 'atelier', nom: 'Atelier', icone: 'toolbox', guide: 'Néo', portrait: neo, phrase: 'Vos projets et vos outils.' },
  { id: 'securite', nom: 'Sécurité', icone: 'securite', guide: 'Actor', portrait: actor, phrase: 'Qui frappe, et comment la box répond.' },
  { id: 'media', nom: 'Média', icone: 'radio', guide: 'Lyrión', portrait: lyrion, phrase: 'Radio, vidéos, direct.' },
  { id: 'maison', nom: 'Maison', icone: 'maison', guide: 'Zia', portrait: zia, phrase: 'Votre maison connectée.' },
];

function espaceInitial(): Espace {
  const e = new URLSearchParams(location.search).get('espace');
  return (ESPACES.some(x => x.id === e) ? e : 'hall') as Espace;
}

export function App() {
  const [espace, setEspace] = useState<Espace>(espaceInitial);
  const [etat, setEtat] = useState<Entree | null>(null);
  const [pseudo, setPseudo] = useState<string | null>(null);

  useEffect(() => {
    entrer().then(async (e) => {
      setEtat(e);
      if (e !== 'aucun') {
        const r = await moi();
        setPseudo(r?.identite?.pseudo ?? r?.sub ?? null);
      }
    });
  }, []);

  function aller(e: Espace) {
    setEspace(e);
    const u = new URL(location.href); u.searchParams.set('espace', e);
    history.replaceState(null, '', u);
  }

  const esp = ESPACES.find(x => x.id === espace)!;
  return (
    <LazyMotion features={domAnimation}>
      <div className="aurora">
        <header className="barre">
          <span className="logo">SBX<em>OS</em></span>
          <span className="apercu">Aperçu Aurora</span>
          <span className="moi">{etat === null ? '…' : etat === 'aucun'
            ? <a href="/acces/">Entrer avec cet appareil</a>
            : (pseudo ?? 'Session ouverte')}</span>
        </header>
        <nav className="rail" aria-label="Espaces">
          {ESPACES.map(x => (
            <button key={x.id} type="button" aria-current={x.id === espace ? 'page' : undefined}
                    onClick={() => aller(x.id)}>
              <SbxIcon id={x.icone} taille={40} label="" />
              <span>{x.nom}</span>
            </button>
          ))}
        </nav>
        <main className="scene">
          <AnimatePresence mode="wait">
            <m.section key={espace} className="lieu"
              initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -12 }}
              transition={{ duration: 0.35 }}>
              {espace === 'hall' && <img className="decor" src={hero} alt="" />}
              <div className="guide">
                <img src={esp.portrait} alt={esp.guide} />
                <p><b>{esp.guide}</b> — {esp.phrase}</p>
              </div>
              <h1>{esp.nom}</h1>
            </m.section>
          </AnimatePresence>
        </main>
      </div>
    </LazyMotion>
  );
}
