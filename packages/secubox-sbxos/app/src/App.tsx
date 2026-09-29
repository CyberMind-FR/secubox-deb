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
import { LazyMotion, MotionConfig, domAnimation, m, AnimatePresence } from 'framer-motion';
import { SbxIcon } from '@sbx/icons';
import { entrer, moi, manifeste, urlSure, radioCourante, activites, lienLocal, type Entree, type Manifeste, type Activite } from '@sbx/data';
import { ecoute } from '@sbx/protocol';
import { enregistreCadre, sbxExecuteAction } from '@sbx/hote';
import { demandeOuverture, estEncadre } from '@sbx/protocol';
import { Lieu } from './Lieu';
import { Palette } from './Palette';
import { FluxHall, type EvenementFlux } from '@sbx/ui/FluxHall';
import { Reglages, appliquePrefs } from './Reglages';
import hero from '@sbx/art/environments/art/hero.webp';
import lexie from '@sbx/art/characters/art/lexie.webp';
import neo from '@sbx/art/characters/art/neo.webp';
import actor from '@sbx/art/characters/art/actor.webp';
import lyrion from '@sbx/art/characters/art/lyrion.webp';
import zia from '@sbx/art/characters/art/zia.webp';

/** Libellés des activités sans titre propre. */
const GENRES: Record<string, string> = { file_shared: 'Fichier partagé', bbs_post: 'Message sur le BBS', billet_publie: 'Billet publié',
  avatar_changed: 'Portrait changé', mood_changed: 'Humeur partagée', node_joined: 'Nœud rejoint' };

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
  const [man, setMan] = useState<Manifeste | null>(null);
  const [titre, setTitre] = useState<string | null>(null);
  const [fil, setFil] = useState<Activite[]>([]);
  const [lieu, setLieu] = useState<{ titre: string; url: string } | null>(null);
  const [reglages, setReglages] = useState(false);
  const [palette, setPalette] = useState(false);
  useEffect(() => {
    const k = (e: KeyboardEvent) => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setPalette(true); } };
    addEventListener('keydown', k); return () => removeEventListener('keydown', k);
  }, []);
  useEffect(() => appliquePrefs(), []);
  const mega = new URLSearchParams(location.search).get('mega') === '1';

  function ouvre(ev: React.MouseEvent, id: string, titre: string, url: string) {
    if (ev.button !== 0 || ev.ctrlKey || ev.metaKey || ev.shiftKey) return;   // onglet : laisser faire
    ev.preventDefault();
    if (mega && estEncadre() && demandeOuverture(id)) return;                 // le Hall ouvre
    setLieu({ titre, url });
  }

  function clavierRail(ev: React.KeyboardEvent) {
    const i = ESPACES.findIndex(x => x.id === espace);
    const j = ev.key === 'ArrowDown' || ev.key === 'ArrowRight' ? i + 1 : ev.key === 'ArrowUp' || ev.key === 'ArrowLeft' ? i - 1 : null;
    if (j === null) return;
    ev.preventDefault();
    const n = ESPACES[(j + ESPACES.length) % ESPACES.length];
    aller(n.id);
    (ev.currentTarget.querySelectorAll('button')[ESPACES.indexOf(n)] as HTMLButtonElement)?.focus();
  }

  useEffect(() => ecoute({ relis: () => { activites().then(setFil); manifeste().then(setMan); } }), []);
  useEffect(() => {
    if (espace !== 'hall') return;
    const lis = () => { if (!document.hidden) activites().then(setFil); };
    lis(); const t = setInterval(lis, 60000);
    return () => clearInterval(t);
  }, [espace]);

  useEffect(() => {
    entrer().then(async (e) => {
      setEtat(e);
      if (e !== 'aucun') {
        const r = await moi();
        setPseudo(r?.identite?.pseudo ?? r?.sub ?? null);
      }
      setMan(await manifeste());        // APRÈS l'entrée : le rôle a pu changer
    });
  }, []);

  useEffect(() => {
    if (espace !== 'media') return;
    let fini = false;
    const lis = async () => {
      if (document.hidden) return;
      const r = await radioCourante();
      const p = r?.piste;
      if (!fini) setTitre(p ? [p.auteur, p.titre].filter(Boolean).join(' — ') || null : null);
    };
    lis(); const t = setInterval(lis, 20000);
    return () => { fini = true; clearInterval(t); };
  }, [espace]);

  function aller(e: Espace) {
    setEspace(e);
    const u = new URL(location.href); u.searchParams.set('espace', e);
    history.replaceState(null, '', u);
  }

  const esp = ESPACES.find(x => x.id === espace)!;
  return (
    <LazyMotion features={domAnimation}><MotionConfig reducedMotion={document.documentElement.dataset.rendu === 'leger' ? 'always' : 'user'}>
      <div className="aurora">
        <header className="barre">
          <span className="logo">SBX<em>OS</em></span>
          <span className="apercu">Aperçu Aurora</span>
          <button type="button" className="recherche" onClick={() => setPalette(true)}>
            Demander à Lexie… <kbd>{/Mac|iPhone|iPad/.test(navigator.platform) ? '⌘K' : 'Ctrl K'}</kbd></button>
          <span className="moi">{etat === null ? '…' : etat === 'aucun'
            ? <a href="/acces/">Entrer avec cet appareil</a>
            : (pseudo ?? 'Session ouverte')}</span>
          <button type="button" className="engrenage" aria-label="Réglages" onClick={() => setReglages(true)}>
            <SbxIcon id="reglages" taille={28} label="" /></button>
        </header>
        <nav className="rail" aria-label="Espaces" onKeyDown={clavierRail}>
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
              {espace === 'media' && titre && <p className="direct">📻 En ce moment : {titre}</p>}
              {espace === 'media' && man && (() => {
                const r = man.espaces.find(x => x.id === 'media')?.modules.find(x => x.id === 'radio');
                const u = r ? urlSure(r.url, man.domaine) : null;
                if (!u) return null;
                const micro = new URL('/micro', u).href;
                return (<div className="lecteur" data-aide="Radio">
                  <iframe ref={f => enregistreCadre('radio', f)} src={micro} title="Radio"
                          sandbox="allow-scripts allow-same-origin" allow="autoplay" />
                  <button type="button" onClick={() => sbxExecuteAction({ kind: 'sbx-action', service: 'radio', action: 'media.toggle' })}>
                    Lecture / pause</button>
                </div>);
              })()}
              {espace === 'hall' && <FluxHall apercu evenements={fil.map((a, i): EvenementFlux => ({
                id: a.activity_uuid, titre: a.context?.titre ?? GENRES[a.kind] ?? 'Nouvelle activité', priorite: 0, at: a.at,
                sous: `${a.qui ?? 'Quelqu’un'} · ${new Date(a.at * 1000).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' })}`,
                icone: a.kind.startsWith('bbs') ? 'bbs' : a.kind.includes('billet') ? 'billets' : 'activite',
                lien: lienLocal(a.context?.lien) }))} />}
              <div className="cartes">
                {(man?.espaces.find(x => x.id === espace)?.modules ?? []).map(md => {
                  const u = man ? urlSure(md.url, man.domaine) : null;
                  return u
                    ? <a key={md.id} className="carte" href={u} target="_blank" rel="noopener"
                         onClick={ev => ouvre(ev, md.id, md.label, u)}>
                        <SbxIcon id={md.id} taille={56} label="" /><span>{md.label}</span></a>
                    : <span key={md.id} className="carte"><SbxIcon id={md.id} taille={56} label="" /><span>{md.label}</span></span>;
                })}
                {man && !man.espaces.find(x => x.id === espace)?.modules.length &&
                  <p className="vide">{man.role === 'guest' ? 'Entrez avec votre appareil pour voir cet Espace.' : 'Rien ici pour l’instant.'}</p>}
              </div>
            </m.section>
          </AnimatePresence>
        </main>
      </div>
      {lieu && <Lieu titre={lieu.titre} url={lieu.url} ferme={() => setLieu(null)} />}
      {reglages && <Reglages man={man} ferme={() => setReglages(false)} />}
      {palette && <Palette espaces={ESPACES} aller={id => aller(id as Espace)} domaine={man?.domaine ?? ''}
                           ferme={() => setPalette(false)} voix={!!man?.capacites.voix && !estEncadre()} />}
    </MotionConfig></LazyMotion>
  );
}
