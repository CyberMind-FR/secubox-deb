# Détection des pixels de suivi (web + email) — Design

**Date :** 2026-07-23
**Statut :** validé (design), prêt pour le plan d'implémentation
**Portée :** neutralisation des pixels de suivi dans les emails entrants + réutilisation du filet MITM existant

---

## Objectif

Empêcher qu'un email puisse signaler son ouverture à un tiers, **sans jamais perdre ni corrompre
de courrier**, et sans remplacer le traceur tiers par un traceur maison.

## Contexte existant (vérifié sur gk2, 2026-07-23)

| Élément | État constaté |
|---|---|
| Stack mail | LXC `mail` (non privilégié), `10.100.0.10`, rootfs `/data/lxc/mail` |
| Postfix `content_filter` | **vide** — libre, aucun conflit |
| Postfix `smtpd_milters` | **vide** |
| rspamd | `active` mais **non câblé** dans Postfix → ne filtre rien (hors périmètre, issue séparée) |
| python3 dans le LXC | 3.11.2 |
| MITM web | `sbxmitm` détecte déjà par heuristique de chemin (`/pixel`, `/beacon`) et bloque `learned-trackers.txt` |
| Notion de pixel 1×1 | **inexistante** dans tout le dépôt |

## Décisions actées

1. **Deux couches** (défense en profondeur) : neutralisation à la réception + filet MITM à l'ouverture.
2. **Réécrire ET archiver le brut** : la copie livrée est neutralisée, le mail d'origine (DKIM intact)
   est conservé.
3. **Cible de réécriture : `data:` URI inline** — un GIF 1×1 transparent encodé dans le mail.
   Aucune requête réseau n'est émise, ni vers le tiers, ni vers la box. Fonctionne hors VPN, hors
   ligne, sur mobile. Ne crée aucun traceur first-party.
4. **Heuristique conservatrice** : on ne neutralise que l'invisible ou le connu (détail ci-dessous).

### Conséquence assumée

Modifier le corps **invalide la signature DKIM** de la copie livrée. C'est pourquoi le brut est
archivé : la pièce vérifiable reste disponible.

---

## Architecture

```
Postfix ──content_filter──► mailguard ──► sendmail (ré-injection) ──► Dovecot ──► boîte
                               │
                               ├─► archive du brut (DKIM intact)
                               └─► en-têtes de verdict

wg-toolbox ──► sbxmitm ──► filet existant, INCHANGÉ
                  ▲
        les deux couches lisent la MÊME liste de traceurs
```

**La couche 2 ne demande aucun développement.** `sbxmitm` bloque déjà les traceurs connus ; il suffit
que les deux couches partagent la définition de « traceur ». Le chantier réel est la couche mail.

## Composants

Découpage en unités à responsabilité unique, testables isolément.

| Fichier | Rôle | Dépendances |
|---|---|---|
| `pixelscan.py` | **Fonction pure** : `scan(html) -> (trackers, html_rewritten)`. Aucune I/O. | aucune |
| `trackers.py` | Graine de domaines + chargement de `learned-trackers.txt` | fichier |
| `archive.py` | Stockage du brut, rétention, purge | FS |
| `filter.py` | Entrée `content_filter` : stdin → MIME → scan → ré-injection | les 3 ci-dessus |

`pixelscan.py` étant pur, toute la logique délicate se teste avec de vrais `.eml`, sans Postfix ni
réseau.

### Interfaces

```python
# pixelscan.py
def scan(html: str, is_tracker: Callable[[str], bool]) -> tuple[list[Tracker], str]:
    """Retourne les traceurs détectés et le HTML réécrit. Pur : aucune I/O, aucun état."""

class Tracker(NamedTuple):
    host: str        # domaine du pixel
    url: str         # URL d'origine (archivée, jamais ré-émise)
    reason: str      # "1x1" | "hidden" | "known-domain" | "known-path"

# trackers.py
def is_tracker(host_or_url: str) -> bool: ...

# archive.py
def store(raw_bytes: bytes) -> str:   # retourne l'archive_id
def purge(older_than_days: int) -> int
```

## Règle de neutralisation

Une balise `<img>` est neutralisée si **au moins un** critère est vrai :

- **Invisible** : `width` ≤ 1 **ou** `height` ≤ 1 **ou** `0`, **ou** style `display:none`,
  `visibility:hidden`, ou dimensions CSS ≤ 1px
- **Domaine connu** : hôte ∈ `learned-trackers.txt` ∪ graine
- **Chemin connu** : chemin contenant `/open`, `/o/`, `/track`, `/beacon`, `/pixel`

Sinon **on ne touche à rien**. Les vraies images passent.

Neutraliser = remplacer l'attribut `src` par :
`data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7`
(GIF 1×1 transparent). Les attributs de dimension sont conservés → mise en page inchangée.

### Graine de domaines traceurs email

`list-manage.com`, `mailchimp.com`, `sendgrid.net`, `sendgrid.com`, `hubspot.com`, `hs-sites.com`,
`mailgun.org`, `sparkpostmail.com`, `klaviyomail.com`, `brevo.com`, `sendinblue.com`,
`exacttarget.com`, `marketo.net`, `mailjet.com`, `postmarkapp.com`, `customer.io`,
`intercom-mail.com`, `getresponse.com`, `constantcontact.com`, `awstrack.me`.

Extensible sans changement de code par `SECUBOX_MAIL_TRACKERS` (mirroir du pattern `NEVER_LEARN`
/ `NEVER_SPLICE` du toolbox).

## Emplacement du code et déploiement

Le filtre s'exécute **dans le LXC `mail`** (là où vit Postfix), pas sur l'hôte.

| Quoi | Où |
|---|---|
| Sources | `packages/secubox-mail/lib/mailguard/{pixelscan,trackers,archive,filter}.py` |
| Tests | `packages/secubox-mail/tests/test_mailguard_*.py` (exécutables sur l'hôte, sans LXC) |
| Installé (hôte) | `/usr/lib/secubox/mail/mailguard/` |
| Déployé (LXC) | `/usr/lib/secubox/mailguard/` via `lib/mail/install.sh` (même mécanisme que le reste du stack) |

Pas de nouveau paquet Debian : le code rejoint `secubox-mail`, dont c'est le domaine.

## Synchronisation de la liste de traceurs (hôte → LXC)

`learned-trackers.txt` est produit sur l'**hôte** par l'autolearn du toolbox
(`/var/lib/secubox/toolbox/learned-trackers.txt`). Le filtre, lui, tourne **dans le LXC** et n'a
aucun accès à ce chemin. Sans synchronisation, l'affirmation « les deux couches partagent la même
définition de traceur » serait fausse.

**Mécanisme retenu : copie périodique par timer sur l'hôte** vers
`/data/lxc/mail/rootfs/var/lib/secubox/mailguard/trackers-learned.txt`.

Pourquoi pas un bind-mount : il exigerait de modifier la config du conteneur et donc de le
redémarrer, et la config d'un LXC *en cours d'exécution* n'est pas touchée par les scripts
d'installation côté source (drift connu). Une copie est sans redémarrage, idempotente et
observable.

Le filtre lit **l'union** de la graine intégrée et du fichier synchronisé. Si le fichier est absent
ou illisible, il fonctionne sur la seule graine — jamais d'erreur bloquante.

## En-têtes ajoutés

```
X-SecuBox-Trackers: 3; mailchimp.com, sendgrid.net, track.exemple.fr
X-SecuBox-Archive: 7f3a9c21
```

Aucun en-tête n'est ajouté quand rien n'est détecté (pas de bruit sur le courrier propre).

## Flux de données

1. Postfix remet le message au `content_filter` sur stdin.
2. `filter.py` lit le brut **intégralement en mémoire** et l'archive **avant toute modification**.
3. Parse MIME ; pour chaque partie `text/html`, appelle `pixelscan.scan()`.
4. Si des traceurs sont trouvés : réécrit les parties concernées, ajoute les en-têtes.
5. Ré-injecte via `sendmail -G -i -f <expéditeur> -- <destinataires>` avec
   `-o content_filter=` **vide** (garde anti-boucle indispensable).
6. Sortie 0. Toute autre issue → voir « intégrité » ci-dessous.

## Intégrité du courrier — règle non négociable

**Toute exception, à n'importe quelle étape, entraîne la remise du message d'origine intact.**

- Le brut est archivé *avant* toute transformation ⇒ jamais de perte.
- Parse MIME impossible, encodage exotique, HTML malformé, disque plein ⇒ on remet l'original.
- Le filtre ne rejette **jamais** un message (pas de `EX_TEMPFAIL` sur erreur interne de scan :
  cela ferait boucler la file). Erreur ⇒ log + passe-plat.
- Un `.eml` qui fait planter le scanner est un **bug à corriger**, pas un mail à perdre.

## Archive

- Emplacement : `/var/lib/secubox/mailguard/archive/` (dans le LXC `mail`)
- Permissions : répertoire `0700`, fichiers `0600`, propriétaire dédié
- **Ne touche à aucun parent partagé** (`/etc/secubox`, `/var/log/secubox`, `/run/secubox`) —
  règle des parents partagés (#511 / #474)
- Rétention : 30 jours par défaut, configurable ; purge par timer
- Contenu : **mails bruts complets = données sensibles**. Rétention bornée et accès restreint sont
  des exigences, pas des options.

## Métriques et webui

**Aucune réconciliation entre les deux couches.** Le scanner mail fait foi pour l'email ; le MITM
reste web-only. Deux compteurs distincts, étiquetés par origine dans un même panneau. Les fusionner
produirait un double comptage inauditable.

Surface : nombre de mails scannés, mails contenant ≥ 1 traceur, top domaines traceurs, et pour un
mail donné la liste des traceurs neutralisés avec le lien vers son archive.

## Tests

- **`pixelscan` (le cœur)** : jeu de `.eml` réels — pixel 1×1 classique, pixel masqué en CSS, image
  légitime de newsletter (ne doit PAS être touchée), HTML malformé, multipart imbriqué,
  quoted-printable, charset non-UTF8, `<img>` sans dimensions sur domaine traceur connu.
- **Non-régression d'intégrité** : un `.eml` volontairement corrompu doit ressortir **identique**.
- **Anti-boucle** : vérifier que le message ré-injecté n'est pas re-filtré.
- **`archive`** : purge respecte la rétention, permissions correctes à la création.

## Hors périmètre (YAGNI)

- Dé-wrapping des liens traceurs (`click.exemple/r/abc` → URL réelle) — sujet distinct
- Blocage des images distantes légitimes
- Statistiques d'ouverture (on a choisi `data:` précisément pour n'en produire aucune)
- Câblage de rspamd dans Postfix — **anomalie réelle constatée**, à traiter en issue séparée
- Courrier sortant (on ne filtre que l'entrant)

## Risques connus

| Risque | Traitement |
|---|---|
| DKIM invalidé sur la copie livrée | Assumé ; brut archivé et vérifiable |
| Faux positif sur une image légitime | Heuristique conservatrice ; l'original reste dans l'archive |
| Boucle de ré-injection | `-o content_filter=` vide sur la ré-injection, testé |
| Archive = données sensibles | `0700`/`0600`, rétention bornée, propriétaire dédié |
| Pixel visible (16×16) sur domaine inconnu | Non couvert par choix ; l'autolearn web finira par le faire connaître, et la liste est partagée |
