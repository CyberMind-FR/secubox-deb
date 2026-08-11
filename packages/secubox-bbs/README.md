# secubox-bbs — BBS auto-hébergé

Forums, bibliothèque de fichiers, messagerie interne, et publication d'un fil
vers le module **billets**.

---

## Le principe : le disque fait foi

Chaque message est un **fichier Markdown** sous `content/`, précédé d'une
en-tête portant ses métadonnées. La base SQLite n'en est que l'**index**.

Cette contrainte paraît lourde jusqu'au jour où elle sert :

* **sauvegarde par simple `rsync`**, à chaud, sans arrêter le service ;
* messages lisibles avec `less` dans dix ans, sans ce logiciel ;
* base entièrement reconstructible — donc jetable, donc jamais un point de
  perte unique.

```bash
bbsctl integrity   # compare disque et index, sans rien modifier
bbsctl reindex     # rebâtit l'index depuis content/ seul
```

`reindex` conserve les identifiants : ils sont portés par les **noms de
fichiers**, pas par un compteur. Les permaliens survivent à une reconstruction.

---

## Visibilité : le cas difficile

La visibilité est portée par le fil **et** par le message. Un fil public peut
contenir une réponse locale.

| Fil | Message | Sort de la maison |
|-----|---------|-------------------|
| public | public | oui |
| public | local | **non** |
| local | public | **non** |
| local | local | non |

Un fil local n'expose **rien**, même un message marqué public : le contenant
prime. L'inverse rendrait un fil public par inadvertance, un message à la fois,
sans que personne ne l'ait décidé.

Un fil local répond **404**, pas 403 — un 403 confirmerait son existence.

---

## Inscription sur invitation

Un BBS auto-hébergé finit exposé sur internet ; une inscription ouverte, c'est
une file de comptes jetables à modérer chaque matin.

```bash
bbsctl invite      # le code n'est affiché QU'UNE FOIS
```

Seule l'empreinte du code est conservée. Ni un listing ultérieur, ni une
lecture de la base ne permettent de le retrouver.

**Les mots de passe ne sont pas dans la base.** Ils vivent dans
`/etc/secubox/secrets/bbs/`, `0600`, hors de l'arborescence de contenu — pour
qu'un `rsync` du contenu vers un disque externe ne les emporte jamais.
argon2id, sel **par compte**, comparaison à temps constant.

Désactiver, jamais supprimer : supprimer un compte emporterait l'attribution de
ses écrits et trouerait les fils.

---

## Publication vers billets

Le BBS est l'atelier, **billets** la vitrine.

```
écouter (podcast, PeerTube, dossier)
  → en parler (un fil s'ouvre)
    → écrire à plusieurs
      → publier (un billet référencé des deux côtés)
        → les réactions reviennent dans le fil
```

**La publication ne change aucune visibilité.** Elle ne reprend que ce qui était
déjà public. Un fil local n'a pas de bouton « publier » — il faut d'abord le
rendre public, explicitement.

Le BBS appelle billets, jamais l'inverse : un module arrêté n'emporte pas
l'autre. Le jeton de service est valable **60 secondes** — il ne sert qu'à un
appel ; un jeton valable des heures traîne dans les journaux bien après.

---

## Installation

Le service est **livré mais non activé**. Il n'a aucun compte au premier
jour : le démarrer ouvrirait un BBS où personne ne peut entrer.

```bash
apt install secubox-bbs

printf '%s' 'une phrase de passe assez longue' | bbsctl user-add gk2 sysop
bbsctl salon atelier 'Atelier' 'Ce qui se répare le samedi'
systemctl enable --now secubox-bbs
```

L'API d'administration et la publication nécessitent `api.jwt_secret`
(`/etc/secubox/secubox.conf` ou `SECUBOX_JWT_SECRET`). **Sans secret, elles
restent fermées** — l'absence de secret ne vaut jamais absence de vérification.

---

## Deux interfaces, deux publics

| Surface | Adresse | Charte |
|---------|---------|--------|
| Membres | `bbs.<domaine>/` | la maquette validée (`/usr/share/doc/secubox-bbs/maquette.html`) |
| Sysop | `admin.<domaine>/bbs/` | terminal cyan (`WEBUI-PANEL-GUIDELINES.md`) |

Les mélanger servirait mal les deux : un membre n'a pas à lire un tableau de
bord, et un sysop n'a pas besoin qu'on lui fasse joli pendant qu'il regarde
pourquoi l'index diverge.

La feuille de style membre est **extraite** de la maquette : toute divergence
est un défaut, la maquette ayant été validée, pas une réinterprétation.

---

## Sauvegarde

```bash
bbsctl backup /data/backup/bbs-$(date +%F).tar.gz
```

L'archive emporte `content/` et `files/`. **Ni la base, ni les secrets.**

* Pas la base : elle se reconstruit, et une base copiée à chaud est un fichier
  à moitié écrit. C'est précisément pour ne pas avoir à arrêter le service
  qu'on ne la sauvegarde pas.
* Pas les secrets : une archive de contenu **circule** — disque externe, autre
  machine, transmission pour dépannage.

Un test prouve la restauration : archive dépliée sur une machine neuve,
`reindex`, contenu et visibilités intacts.

---

## API

Toutes les routes exigent un JWT HS256 valide, **non expiré**, signé avec le
secret partagé. L'algorithme est imposé, jamais lu dans le jeton — faire
confiance au champ `alg` revient à demander à la serrure quelle clef elle
accepte.

| Méthode | Route | Effet |
|---------|-------|-------|
| GET | `/api/v1/bbs/status` | compteurs et modules actifs |
| GET | `/api/v1/bbs/integrity` | écart disque ↔ index |
| GET | `/api/v1/bbs/threads` | derniers fils (vue complète) |
| POST | `/api/v1/bbs/invite` | émet une invitation |
| POST | `/api/v1/bbs/backup` | archive transportable |
| POST | `/api/v1/bbs/reindex` | reconstruit l'index |

---

## État

Livré et testé : comptes, sessions, invitations, salons, fils, messages,
visibilité double, rendu Markdown sûr, sauvegarde, intégrité, pont billets,
API, panneau sysop, paquet Debian.

**Pas encore implémenté** : dépôt de fichiers (le schéma et les quotas
existent, la route non), messagerie interne, module média, réactions.
Les vues correspondantes annoncent ce qu'elles feront plutôt que de simuler un
fonctionnement qui n'existe pas — une page qui ment sur son état coûte plus
cher qu'une page qui l'avoue.

Suivi : <https://github.com/CyberMind-FR/secubox-deb/issues/1007>
