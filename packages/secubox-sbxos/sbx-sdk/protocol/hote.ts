// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
/**
 * SDK Aurora :: protocole sbx, côté HÔTE (#1613). Portage de
 * sbxExecuteAction du Hall : une action {service, action, v?} est résolue par
 * les capacités DÉCLARÉES du service (capabilities.d, lues au build) et postée
 * au seul cadre enregistré pour ce service, à SON origine exacte — jamais '*'.
 */
import radio from '../../../secubox-radio/capabilities.d/radio.json';

type Capacite = { message: Record<string, unknown>; value?: { field: string; type: string } };
type Declaration = { service: string; actions: Record<string, Capacite> };

const DECLARATIONS: Record<string, Declaration> = { radio: radio as Declaration };
const cadres = new Map<string, HTMLIFrameElement>();

/** Un cadre de service s'enregistre ; l'origine est celle de son src. */
export function enregistreCadre(service: string, f: HTMLIFrameElement | null) {
  if (f) cadres.set(service, f); else cadres.delete(service);
}

export type Action = { kind: 'sbx-action'; service: string; action: string; v?: unknown };

/** Résout le message d'une action ; null si elle n'est pas déclarée. Pur (testé). */
export function resous(a: Action): Record<string, unknown> | null {
  const cap = DECLARATIONS[a.service]?.actions[a.action];
  if (!cap) return null;
  const msg = { ...cap.message };
  if (cap.value) {
    if (a.v === undefined || typeof a.v !== cap.value.type) return null;
    msg[cap.value.field] = a.v;
  }
  return msg;
}

export function sbxExecuteAction(a: Action): boolean {
  const msg = resous(a);
  const f = cadres.get(a.service);
  if (!msg || !f?.contentWindow) return false;
  let origine: string;
  try { origine = new URL(f.src).origin; } catch { return false; }
  f.contentWindow.postMessage(msg, origine);
  return true;
}
