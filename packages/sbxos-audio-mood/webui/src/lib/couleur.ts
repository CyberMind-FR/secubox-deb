// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// LA COULEUR D'UNE HUMEUR — et pourquoi elle vit ICI (#1331).
//
// Le Hall pilote la lampe, mais il ne décide pas de la couleur. Traduire un
// état en teinte est du SENS, et le sens appartient au module qui le produit :
// si le Hall en décidait, la table vivrait loin des affinités qui l'alimentent,
// et la première émotion ajoutée ici sortirait blanche là-bas sans que rien ne
// le signale.
//
// LA CONTRAINTE DU MODULE VAUT AUSSI POUR LA LUMIÈRE. « Ne jamais présenter
// les émotions comme des certitudes » ne s'arrête pas à l'écran : une lampe
// rouge vif affirme, et elle affirme à toute la pièce, à quelqu'un qui n'a pas
// lu la réserve ni le pourcentage. D'où deux règles qui ne sont pas
// décoratives :
//
//   1. UN INDÉTERMINÉ N'A PAS DE COULEUR. Il rend un blanc chaud — la lampe
//      redevient une lampe. Deviner une teinte « la plus probable » serait
//      précisément transformer une absence de mesure en affirmation.
//   2. LA CONFIANCE MODULE LA LUMINOSITÉ. Une lecture hésitante donne une
//      lampe basse, une lecture assurée une lampe franche. L'incertitude
//      devient ainsi VISIBLE dans le même geste que l'information, au lieu
//      d'être une note de bas de page que la pièce ne lit pas.

/** Blanc chaud : l'absence d'avis, pas une couleur de plus. */
export const NEUTRE = '#FFE9C8'

// Les teintes sont choisies pour se distinguer SUR UN MUR, pas sur un écran :
// une lampe ne rend ni les sombres ni les désaturés, et deux couleurs
// voisines y deviennent la même. D'où l'écart franc entre tension et colère,
// qui sont pourtant proches à l'écran.
// Les CLÉS sont celles que rend l'API (`calm`, `joy`, …), pas les noms
// français de l'interface : traduire ici ferait dépendre la lampe d'une
// deuxième table, et la première faute de frappe éteindrait une émotion sans
// bruit.
const TEINTES: Record<string, string> = {
  calm: '#2FD9C0',    // turquoise reposé
  joy: '#FFC233',     // ambre chaud
  stress: '#FF6A2B',  // orangé vif
  anger: '#F01E3C',   // rouge franc
  fatigue: '#8A6BFF', // violet doux
  focus: '#2E90FF',   // bleu net
}

// Bornes de luminosité, sur l'échelle Zigbee 1..254.
//
// Le plancher n'est pas zéro : une lampe éteinte ne dit pas « je doute », elle
// dit « il n'y a personne ». Le plafond n'est pas 254 : la lecture la plus
// assurée que ce module puisse produire vaut 0,72, et la lampe ne doit pas
// prétendre davantage que le nombre.
const LUM_MIN = 70
const LUM_MAX = 210
const PLAFOND_CONFIANCE = 0.72

export type Lumiere = { couleur: string; luminosite: number }

/**
 * La lumière que mérite une lecture.
 *
 * `etat` inconnu ou absent, réserve déclarée, confiance nulle : blanc chaud au
 * plancher. C'est le cas NORMAL quand personne ne parle, et il ne doit pas
 * ressembler à une panne.
 */
export function lumierePour(etat: string | undefined, confiance: number): Lumiere {
  const teinte = etat ? TEINTES[etat] : undefined
  if (!teinte) return { couleur: NEUTRE, luminosite: LUM_MIN }
  const c = Math.max(0, Math.min(confiance || 0, PLAFOND_CONFIANCE)) / PLAFOND_CONFIANCE
  return { couleur: teinte, luminosite: Math.round(LUM_MIN + c * (LUM_MAX - LUM_MIN)) }
}

/** La lumière au repos : ce qu'on laisse en quittant. */
export function lumiereNeutre(): Lumiere {
  return { couleur: NEUTRE, luminosite: LUM_MIN }
}

/**
 * Deux lumières sont-elles assez différentes pour valoir un ordre radio ?
 *
 * SANS CE FILTRE, ON ÉMETTRAIT VINGT FOIS PAR SECONDE. Le pont suivrait un
 * moment puis décrocherait, et la lampe clignoterait au rythme des micro-
 * variations de confiance — ce qui donnerait à voir du bruit de mesure en le
 * faisant passer pour de l'humeur.
 */
export function vautLaPeine(avant: Lumiere | null, apres: Lumiere): boolean {
  if (!avant) return true
  if (avant.couleur !== apres.couleur) return true
  return Math.abs(avant.luminosite - apres.luminosite) >= 25
}
