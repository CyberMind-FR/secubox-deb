// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
/**
 * SDK Aurora :: <FluxHall> (#1597, #1614). Ce qui mérite l'attention MAINTENANT :
 * trois événements au plus, par priorité décroissante puis du plus récent.
 * Props seulement : la box calcule le flux (P14) ; en attendant, l'app lui
 * passe les activités, étiquetées « aperçu ».
 */
import { SbxIcon } from '@sbx/icons';

export type EvenementFlux = { id: string; titre: string; sous?: string; priorite: number; at: number;
                             icone?: string; lien?: string | null; etat?: 'repos' | 'alerte' | 'succes' };

export const FLUX_MAX = 3;

export function trieFlux(ev: EvenementFlux[]): EvenementFlux[] {
  return [...ev].sort((a, b) => b.priorite - a.priorite || b.at - a.at).slice(0, FLUX_MAX);
}

export function FluxHall({ evenements, apercu = false }: { evenements: EvenementFlux[]; apercu?: boolean }) {
  const e = trieFlux(evenements);
  return (
    <section className="flux" aria-label="Flux Hall" data-aide="Flux Hall : ce qui compte maintenant">
      <div className="flux-t"><h2>Flux Hall</h2>
        <span>{e.length ? `${e.length} élément${e.length > 1 ? 's' : ''} ${e.length > 1 ? 'méritent' : 'mérite'} votre attention` : 'Rien d’urgent'}</span>
        {apercu && <span className="badge">aperçu</span>}</div>
      <ol>
        {e.map(x => {
          const corps = <><SbxIcon id={x.icone ?? 'activite'} taille={40} etat={x.etat} label="" />
            <span className="flux-txt"><b>{x.titre}</b>{x.sous && <small>{x.sous}</small>}</span></>;
          return <li key={x.id} className={x.etat === 'alerte' ? 'alerte' : undefined}>
            {x.lien ? <a href={x.lien}>{corps}</a> : corps}</li>;
        })}
      </ol>
    </section>
  );
}
