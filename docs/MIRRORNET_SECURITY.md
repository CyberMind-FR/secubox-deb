<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# MirrorNet v1 — Sécurité

Issue #3643 · **CONCEPTION** · marquage EXISTANT / À ÉTENDRE / NOUVEAU (voir `MIRRORNET_ARCHITECTURE.md`).

Règles de code applicables : `.claude/RULES-CODE.md` et `.claude/MODULE-COMPLIANCE.md` ; chaque lot passe par la
relecture `relecteur-securite` avant fusion. Confiance fédérée détaillée : `docs/mirrornet/federated-trust.md`.

## 1. Modèle de menace

| Acteur | Capacité supposée | Ce qu'il ne doit pas pouvoir faire |
|---|---|---|
| Internet | joint gk2 (HAProxy → sbxwaf) | entrer au maillage, lire une API MirrorNet, forger une offre ou un relevé |
| Appareil du LAN d'un maître | joint l'écouteur 7331 | entrer au maillage hors fenêtre d'appairage, prendre l'identité d'une box |
| Pair malveillant (membre) | signe ses propres objets | usurper un autre did, gonfler son crédit sans contre-signature, lire le ledger d'un autre, imposer une donnée personnelle |
| Pair compromis puis révoqué | garde ses clés | rester actif après réception de la `RevocationNotice` |
| Compte de service `secubox` | écrit dans `/run/secubox`, `/var/lib/secubox` | obtenir root, déclencher des passes root en boucle |
| Conteneur LXC | réseau du pont | joindre les API MirrorNet, entrer au maillage |

## 2. Identités et authentification mutuelle

| Couche | Mécanisme | Statut |
|---|---|---|
| Transport | WireGuard wg-mesh : clé par pair, `AllowedIPs` /32 | EXISTANT |
| Enrôlement | jeton à usage unique (empreinte stockée), code, appairage (secret de l'écouteur 7331 + fenêtre + validation) | EXISTANT / À ÉTENDRE (#3640) |
| Identité applicative | `did:plc` + Ed25519 `node.key` ; `NodeRecord` lie did, clé WireGuard, mesh_ip | EXISTANT |
| Objet | signature Ed25519 sur `canonical_bytes(payload_sans_sig)` (offres, manifestes, relevés) | EXISTANT (annuaire), NOUVEAU pour manifestes et relevés |
| Liaison | un objet reçu d'un pair n'est accepté que si son `signer_did` est lié par un `NodeRecord` valide à la clé WireGuard de l'émetteur (adresse source wg-mesh) | NOUVEAU (patron Status Live jalon 2 : nom lié à la fiche) |

Authentification mutuelle = WireGuard (les deux clés) **et** signature des objets (les deux did) ; un relevé d'usage
porte les deux signatures.

## 3. Niveaux de confiance et autorisations

Niveaux calculés depuis le journal, jamais stockés (`docs/mirrornet/federated-trust.md` § 3) : OBSERVER, LIMITED,
PARTNER, TRUSTED, REVOKED. Capacités MirrorNet v1 (s'ajoutent au tableau A21) :

| Capacité | OBSERVER | LIMITED | PARTNER | TRUSTED | REVOKED |
|---|---|---|---|---|---|
| voir le catalogue | oui | oui | oui | oui | non |
| s'abonner à une offre `gratuit`/`public` | non | oui | oui | oui | non |
| s'abonner contre crédits, `communaute` | non | oui | oui | oui | non |
| publier une offre ou un jeu | non | oui (`public`, `communaute`) | oui | oui | non |
| servir de relais/cache crédité | non | non | oui | oui | non |
| `specialise` / `professionnel` | non | non | approbation du fournisseur | approbation du fournisseur | non |
| gagner des crédits | non | plafonné | oui | oui | non |

Autorisations d'API (règle § 3 de RULES-CODE, inchangée) : lecture `require_lecture`, toute écriture `require_jwt`
(administrateur réel), routes de pair par l'écoute maillée avec la garde `lecture_ou_pair` (EXISTANT, annuaire) ; aucune
route MirrorNet n'est jamais exposée à Internet (pas de vhost public, pas de `waf_bypass`).

## 4. Rejeu, débit, épuisement

| Objet | Anti-rejeu | Débit |
|---|---|---|
| jeton de jonction | usage unique, 5 min (autojoin) / 1 h | appairage : 5 jetons par fenêtre, 1 / 30 s par adresse |
| offre, manifeste | (auteur, identifiant, version) unique ; version croissante | publication : quota par nœud et par jour |
| relevé d'usage | (abonnement, sequence) persistant, fenêtre de dérive d'horloge | 1 relevé par abonnement et par période |
| écriture du ledger | id de transaction unique, chaîne | — |
| objets | empreinte BLAKE2b vérifiée, taille annoncée bornée | quota par jeu, par abonné, par copie |

## 5. Secrets et stockage

- `node.key` : `/etc/secubox/secrets/annuaire/` (0640 root:groupe dédié) ; jamais copié, jamais journalisé.
- Base `secubox-mirrornet` : 0640, compte dédié ; aucun secret dans le ledger (identifiants publics seulement).
- Configuration : `/etc/secubox/mirrornet.toml` 0640, aucun secret ; écriture par double tampon + retour arrière
  (`.claude/reference/CSPN.md`).
- Objets : `/data/mirrornet/objets/` 0640, jamais extraits par `secubox-mirrornet`.

## 6. Journalisation

Toute décision de sécurité dans `/var/log/secubox/audit.log` (ajout seul) : appairage ouvert/fermé, jonction, refus,
validation, publication, abonnement, approbation, résiliation, révocation appliquée, relevé refusé (signature, rejeu,
fraîcheur), transaction, litige ouvert/résolu, changement de règle de répartition. Les refus répétés sont échantillonnés
(au plus 1 par minute) pour ne pas remplir le disque.

## 7. Révocation

`RevocationNotice` (EXISTANT) appliquée en < 60 s (`docs/mirrornet/federated-trust.md` § 4) ; effets MirrorNet v1 :
offres du nœud retirées du catalogue local, abonnements `Resilie`, relevés postérieurs refusés, crédits non encore
réglés gelés (`en_attente`), noms relayés retirés. Un did révoqué ne revient jamais.

## 8. Isolation

- Un compte par service (`secubox-mirrornet`), AppArmor enforce, socle § 10 (NoNewPrivileges, ProtectSystem=strict,
  ReadWritePaths exacts) ; ctl root `mirrornetctl` à verbes exacts (routes sbxwaf, vhosts) ; rien de l'économie en root.
- Les modules consommateurs et producteurs restent dans leur LXC ou leur compte ; `secubox-mirrornet` ne lit jamais
  leur arbre, il passe par leur adaptateur.
- Les ponts de conteneurs (`br-lxc`) n'atteignent pas l'écoute maillée (`:8471`, `:8799`) : nftables par interface.

## 9. Migration et retour arrière

| Changement | Migration | Retour arrière |
|---|---|---|
| Champs facultatifs de `ServiceOffer`/`Subscription` | aucune (rétrocompatible) | version précédente de l'annuaire ignore les champs (test) |
| Nouveaux `Op` du journal | aucune | les anciens nœuds ignorent les `Op` inconnus (test de non-régression du pull) |
| Base `mirrornet.db` | schéma versionné, migrations idempotentes, sauvegarde avant | restauration de la sauvegarde ; le ledger n'est jamais réécrit |
| Paquet `secubox-mirrornet` | installation suggérée (méta) | suppression sans effet sur p2p/annuaire |

## 10. Contrôles par lot

Chaque lot : tests (dont fraude et rejeu), relecture `relecteur-securite` en deux passes au besoin, validation sur le
banc (gk4/gk5/gk6/gk12) avant gk2, gk1 et gk3 seulement avec accord.
