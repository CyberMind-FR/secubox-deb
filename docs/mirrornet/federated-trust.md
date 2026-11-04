<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Federated Trust — identités liées, niveaux, révocation, rotation (#3429, phase B)

CONCEPTION, non implémentée. Composants N2, N3, N4 (A21), N10 (A22). Marquage : EXISTANT / À ÉTENDRE / NOUVEAU.

## 1. Arbitrages appliqués

Niveaux TRUSTED / PARTNER / LIMITED / OBSERVER / REVOKED **calculés depuis le journal de l'annuaire**, distincts des
tiers commerciaux de `secubox-federation` (`internal/federation/config.go:60-87`, qui restent inchangés) ; promotion
TRUSTED par l'**administrateur seul** ; rotation = ré-adhésion en A21, objet de succession en A22 ; révocation
**effective sur le transport** (WireGuard, pilotage). A21 : niveaux **affichés sans effet**.

Vision du 2026-11-03 (`architecture.md` § 0) : la signature des sites par une personne est **reportée** (décision 3).
En A21, l'**authenticité d'une publication repose sur l'identité du nœud** : annonce signée Ed25519 par la box
(`did`), transport par un pair WireGuard enrôlé dont la clé concorde avec le `NodeRecord`. La liaison des identités
(§ 2) et la révocation effective (§ 4) deviennent donc le socle de confiance du contenu.

## 2. Liaison des identités d'un nœud (N2)

| Identité | Statut | Référence |
|---|---|---|
| `did:plc:` Ed25519 (racine) | EXISTANT | `secubox-annuaire/annuaire/model.py:194-215` |
| clé WG wg-mesh dans `NodeRecord.pubkey_wg`, adresse `mesh_ip` | EXISTANT | `model.py:505-532` |
| clé OpenPGP de box liée au `did` | EXISTANT | `model.py:979-1015` ; `verbs.py:2441` (`openpgp_bind`) |
| certificat SBX v2 (sujet = `did`) | EXISTANT, déploiement NON VÉRIFIÉ | `secubox-federation/internal/ca/renew.go:15-33` |
| **vérification** que la clé WG rendue par `mesh.py` est celle du `NodeRecord` signé | ABSENT | `secubox-p2p/api/mesh.py:164` (`render_wg_conf`) lit le registre local |

Conception (À ÉTENDRE) :

- `NodeRecord` gagne deux champs **optionnels** (rétrocompatibles, `extra="forbid"` impose une montée de schéma
  coordonnée) : `openpgp_empreinte`, `cert_sbx_serie`. L'empreinte doit correspondre à un `openpgp_bind` du même `did`.
- `secubox-p2p` : avant de rendre un pair dans `wg_mesh`, compare `pubkey_wg` du registre local au dernier `NodeRecord`
  signé de ce pair. Désaccord → pair non rendu en A22 ; **journalisé seulement** en A21 (niveaux sans effet, pas de
  coupure surprise du parc).
- Une identité est dite **liée** quand `did` ↔ WG concordent (et OpenPGP **de box** s'il est déclaré). Les niveaux >
  LIMITED exigent une identité liée. La clé OpenPGP de box (`openpgp_bind`) n'est pas une signature de site.

## 3. Niveaux de confiance (N3) — projection calculée, jamais stockée

```
                      RevocationNotice valide visant le did ? ──oui──▶ REVOKED
                                     │non
                      MemberState == OBSERVED ? ──oui──▶ OBSERVER
                                     │non (MEMBER)
                      identité liée ? ──non──▶ LIMITED
                                     │oui
          Grant « mirrornet.confiance » valide, émis par l'admin du maître ? ──oui──▶ TRUSTED
                                     │non
          Grant « mirrornet.partenaire » valide ? ──oui──▶ PARTNER
                                     │non
                                  LIMITED
```

- Briques EXISTANTES : `MemberState` (`model.py:40-49`), `RevocationNotice` (`model.py:361-391`, cascade bornée),
  `Grant` (`model.py:580` ; `verbs.py:1114` `grant_issue`, `:1186` `grant_revoke`).
- NOUVEAU : module `secubox-annuaire/annuaire/confiance.py` (fonction pure `niveau(journal, did, maintenant)` + cause
  textuelle) ; route `GET /api/v1/annuaire/confiance` (`require_lecture`) ; mise en cache incrémentale (recalcul sur
  nouvelles entrées seulement).
- Grants : durée bornée (proposé : 90 jours, renouvelés) ; `mirrornet.confiance` n'est **accepté** que signé par la box
  maître ancrée (`secubox-p2p/api/ancre.py:62`) **et** émis par une route `require_jwt` (administrateur réel) ;
  `mirrornet.partenaire` : idem en A21 ; en A22, éventuellement par vote ONE_NODE_ONE_VOICE (`verbs.py:677,733,793`).
- Réputation (A22) n'abaisse **jamais** un niveau seule : elle peut seulement proposer une révocation soumise à vote ou
  à l'administrateur (`node-reputation.md`).

### Capacités par niveau (effectives en A22 ; A21 : affichées)

| Capacité | OBSERVER | LIMITED | PARTNER | TRUSTED | REVOKED |
|---|---|---|---|---|---|
| recevoir les listes publiques, journal | oui | oui | oui | oui | non |
| publier un site diffusé (nom court), tenir une copie **statique** servie | non | oui | oui | oui | non |
| répliquer blog / microblog, voter un quorum de site | non | non | oui | oui | non |
| publier un ban fédéré pris en compte | non | non | oui (consensus) | oui | non |
| être écrivain d'un site à écriture répliquée (A22) | non | non | non | oui | non |
| arbitrer un conflit de nom court | — | — | — | administrateur du maître ancré seulement | — |
| canal pilotage | non | oui | oui | oui | **coupé** |

## 4. Révocation effective (N4, A21)

```
RevocationNotice (annuaire, EXISTANT) ──mesh_sync──▶ chaque box
        │
        ▼ minuterie secubox-p2p « revocations-appliquer » (30 s) — NOUVEAU, chemin root existant de p2p
   1. retire le pair de wg-mesh (wg set … remove) et de wg_mesh.json
   2. le retire de /var/lib/secubox/p2p-public/pairs-enroles.json  ─▶ pilotage : 403 (EXISTANT, README:21)
   3. demande à mirrornet de retirer ses cibles et de suspendre les noms courts dont il est source ─▶ sbxwaf
   4. audit « pair_revoque_applique » (did, nom, cause, délai depuis la notice)
```

- Différence avec l'oubli manuel (`secubox-p2p/api/oubli.py:186`, qui refuse un pair en ligne ou maître) : la révocation
  s'applique **même si le pair est en ligne** ; elle refuse seulement de s'appliquer au maître ancré et à soi-même
  (journalisé, alerte).
- Délai visé < 60 s après réception de la notice. Idempotent. Pas de ré-ajout : un `did` révoqué n'est jamais rendu
  (révocation jamais effacée, `model.py:40-49`).
- Si l'annuaire n'est pas joignable : rien n'est retiré (pas de coupure par panne), état affiché.

## 5. Rotation des clés

- **A21** : rotation = **ré-adhésion** : révocation SELF de l'ancien `did`, nouveau jeton de jonction
  (`secubox-p2p/api/jetons.py:97`), nouveau `did`, nouveaux Grants. Les copies sont re-placées automatiquement ; les
  noms courts dont la box était source restent attribués à l'ancien `did` (source absente) jusqu'à arbitrage
  (`distributed-hosting.md` § 6.5). Documenté comme procédure, aucun code de succession.
- **A22** : `KeySuccession {ancien_did, nouveau_did, nouvelle_cle_wg, chevauchement_jusqu_a (≤ 7 j), sig_ancienne,
  sig_nouvelle}` (NOUVEAU, N10) ; les niveaux et Grants suivent la succession ; l'ancien `did` devient REVOKED à la fin
  du chevauchement.

## 6. Correctif lié (A21)

Heartbeat masterlink non signé accepté (`secubox-p2p/api/masterlink.py`, `on_heartbeat`, audit § 4) : masterlink
restant désactivé, le correctif (refus de `sig` absente) est rangé en A22 avec le quorum ; un test A21 vérifie seulement
que la section est absente par défaut.

## 7. Tests

Projection : table de vérité (une entrée de journal par cas) ; Grant expiré → niveau inférieur ; Grant TRUSTED émis
par une autre box que le maître → ignoré ; identité non liée → LIMITED. Révocation : pair en ligne révoqué → hors
wg-mesh et 403 pilotage < 60 s (banc gk4) ; tentative de révoquer le maître → refus audité ; annuaire injoignable →
aucun retrait.
