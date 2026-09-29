// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
/**
 * LEXIE — palette Ctrl K (#1615). Aucune décision ici : la navigation vers un
 * Espace se résout sur place ; tout le reste est demandé à ZIA, dont la
 * réponse est rendue en TEXTE. Une action média s'exécute ; toute autre
 * attend un clic, et la garde serveur s'applique de toute façon.
 */
import { useEffect, useRef, useState } from 'react';
import { demandeZia, sansClic, urlSure, transcrit, dit, type ReponseZia, type ActionZia } from '@sbx/data';
import { SbxIcon } from '@sbx/icons';
import { sbxExecuteAction } from '@sbx/hote';
import lexie from '@sbx/art/characters/art/lexie.webp';

type EspaceNom = { id: string; nom: string };

/** « ouvre atelier », « va dans média », « maison » → id d'Espace. */
export function espaceDemande(q: string, espaces: EspaceNom[]): string | null {
  const s = q.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/^(ouvre|va (dans|a|au|sur)|aller (a|au)|montre)\s+(l'|le |la )?/, '').trim();
  const e = espaces.find(x => x.id === s || x.nom.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '') === s);
  return e ? e.id : null;
}

/** **gras** → <b>, sans jamais interpréter de HTML. */
function Texte({ t }: { t: string }) {
  return <p className="zia-texte">{t.split(/(\*\*[^*]+\*\*)/g).map((b, i) =>
    b.startsWith('**') && b.endsWith('**') ? <b key={i}>{b.slice(2, -2)}</b> : <span key={i}>{b}</span>)}</p>;
}

export function Palette({ espaces, aller, domaine, ferme, voix = false }:
  { espaces: EspaceNom[]; aller: (id: string) => void; domaine: string; ferme: () => void; voix?: boolean }) {
  const [q, setQ] = useState('');
  const [attente, setAttente] = useState(false);
  const [rep, setRep] = useState<ReponseZia | null>(null);
  const [fait, setFait] = useState<string[]>([]);
  const champ = useRef<HTMLInputElement>(null);
  const [ecoute, setEcoute] = useState(false);
  const enreg = useRef<MediaRecorder | null>(null);
  const parleVoix = useRef(false);

  useEffect(() => {
    const avant = document.activeElement as HTMLElement | null;
    champ.current?.focus();
    const k = (e: KeyboardEvent) => { if (e.key === 'Escape') ferme(); };
    addEventListener('keydown', k);
    return () => { removeEventListener('keydown', k); avant?.focus(); };
  }, [ferme]);

  function execute(a: ActionZia) {
    const v = (a.params as { value?: unknown } | undefined)?.value;
    const ok = sbxExecuteAction({ kind: 'sbx-action', service: a.service, action: a.action, v });
    setFait(f => [...f, `${a.service} · ${a.action} : ${ok ? 'fait' : 'service non ouvert ici'}`]);
  }

  async function micro() {
    if (ecoute) { enreg.current?.stop(); return; }
    let flux: MediaStream;
    try { flux = await navigator.mediaDevices.getUserMedia({ audio: true }); }
    catch { setRep({ text: 'Micro refusé ou absent.', objects: [], actions: [] }); return; }
    const morceaux: Blob[] = [];
    const r = new MediaRecorder(flux);
    r.ondataavailable = e => morceaux.push(e.data);
    r.onstop = async () => {
      flux.getTracks().forEach(t => t.stop()); setEcoute(false);
      const texte = await transcrit(new Blob(morceaux, { type: r.mimeType }));
      if (!texte) { setRep({ text: 'Je n’ai rien entendu.', objects: [], actions: [] }); return; }
      setQ(texte); parleVoix.current = true; await demande(texte);
    };
    enreg.current = r; r.start(); setEcoute(true);
    setTimeout(() => { if (r.state === 'recording') r.stop(); }, 8000);   // une commande dure quelques secondes
  }

  async function envoie(ev: React.FormEvent) {
    ev.preventDefault();
    parleVoix.current = false;
    await demande(q);
  }

  async function demande(q: string) {
    const id = espaceDemande(q, espaces);
    if (id) { aller(id); ferme(); return; }
    setAttente(true); setRep(null); setFait([]);
    const r = await demandeZia(q);
    setAttente(false);
    setRep(r ?? { text: 'ZIA ne répond pas pour le moment.', objects: [], actions: [] });
    r?.actions.filter(sansClic).forEach(execute);
    if (r && parleVoix.current) {
      const son = await dit(r.text);
      if (son) { const a = new Audio(URL.createObjectURL(son)); a.play().catch(() => {}); }
    }
  }

  return (
    <div className="palette-fond" onMouseDown={e => { if (e.target === e.currentTarget) ferme(); }}>
      <div className="palette" role="dialog" aria-modal="true" aria-label="Lexie">
        <form onSubmit={envoie}>
          <img src={lexie} alt="" />
          <input ref={champ} value={q} onChange={e => setQ(e.target.value)} maxLength={500}
                 placeholder="Demandez à Lexie : « mets la radio en pause », « ouvre atelier »…" aria-label="Demande à Lexie" />
          {voix && <button type="button" className={ecoute ? 'micro ecoute' : 'micro'} onClick={micro}
                           aria-pressed={ecoute} aria-label={ecoute ? 'Arrêter l’écoute' : 'Parler à Lexie'}>
            <SbxIcon id="micro" taille={28} label="" /></button>}
        </form>
        <div className="palette-rep" aria-live="polite">
          {attente && <p className="zia-texte">Lexie réfléchit…</p>}
          {rep && <Texte t={rep.text} />}
          {rep?.actions.filter(a => !sansClic(a)).map((a, i) =>
            <button key={i} type="button" className="zia-action" onClick={() => execute(a)}>
              Confirmer : {a.service} · {a.action}</button>)}
          {fait.map((f, i) => <p key={i} className="zia-fait">{f}</p>)}
          {rep && rep.objects.length > 0 && <ul className="zia-objets">
            {rep.objects.slice(0, 8).map(o => {
              const u = urlSure(o.url ?? null, domaine);
              return <li key={o.id}>{u ? <a href={u} target="_blank" rel="noopener">{o.title ?? o.id}</a> : <b>{o.title ?? o.id}</b>}
                {o.summary && <small>{o.summary.slice(0, 160)}</small>}</li>;
            })}</ul>}
        </div>
        <p className="palette-pied"><kbd>Entrée</kbd> demander · <kbd>Échap</kbd> fermer</p>
      </div>
    </div>
  );
}
