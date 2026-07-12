# Billets 📮

**[EN](Billets)** | **🟣 MIND** | 🔐 self-hosted

> Publie court, embarque, republie — *un micro-blog passerelle inter-médias,
> hébergé chez toi.*

Billets is a self-hosted micro-blog **gateway**: short posts with restricted
Markdown, inline **media galleries** (zoomable), social embeds (oEmbed), emoji
reactions, moderated comments, and Atom/JSON feeds. FastAPI + aiosqlite (WAL) +
Jinja2 on its own vhost (`billets.<board>.secubox.in`), behind nginx → sbxwaf →
HAProxy. Every billet is versioned in Gitea; every security decision is written
to an append-only BLAKE2b-chained event log.

- Public feed: `https://billets.<board>.secubox.in/`
- Author admin: `…/admin` · Operator panel: `admin.<board>.secubox.in/billets/`

---

## 🎯 Cas d'usage

### 1️⃣ Micro-blog souverain (short-form)
Publie des notes courtes en **Markdown restreint** (liens, gras, listes — pas de
HTML brut). Chaque billet a un permalien stable, un slug lisible, et entre dans
les flux **Atom/JSON**. Brouillon → publication → archivage, avec historique
complet des révisions dans Gitea (`git log --follow` sur `billets/<id>.md`).

> *« Je veux un journal public que je contrôle, sans plateforme tierce. »*

### 2️⃣ Galerie média avec vignette zoomable 🖼️
Joins **plusieurs images** à un billet (png · jpeg · webp · gif, ≤ 5 Mo).
Chaque upload est **entièrement ré-encodé** (Pillow) : EXIF/GPS supprimés,
polyglottes neutralisés, SVG refusé, garde anti-decompression-bomb. Le public
voit une **grille de vignettes** ; un clic ouvre une **lightbox zoomable** avec
navigation clavier ◀▶ (dégradation gracieuse : sans JS, le lien ouvre l'image).
La première image alimente `og:image` / `twitter:image` pour les aperçus de
partage.

> *« Je poste une photo en vignette, cliquable et agrandissable, à côté du texte. »*

### 3️⃣ Passerelle inter-médias sociaux (embed / republish)
Colle une URL YouTube / Vimeo / Mastodon / PeerTube / Bluesky… : billets résout
l'**oEmbed** (SSRF-gardé, HTML sanitizé, `frame-src` en allow-list) et intègre le
média inline. En sortie, un endpoint **oEmbed** + des **share intents** (Mastodon,
copie de lien) permettent de republier le billet ailleurs.

> *« J'embarque une vidéo externe, et je peux republier mon billet vers Mastodon. »*

### 4️⃣ Commentaires modérés + réactions emoji
Le public réagit (👍 ❤️ 😂 😮 😢 🔥) et commente ; les commentaires passent par
une file de **modération** (anti-spam honeypot + jeton temporel + rate-limit,
IP jamais stockée en clair — BLAKE2b). L'auteur approuve/rejette depuis l'admin.

### 5️⃣ Backup portable `.sbxsite` 💾
Un clic (`/admin/export.sbxsite`) produit **un seul fichier** contenant tous les
billets **et leurs médias en base64** — réimportable ailleurs. Le contenu voyage
avec le fichier ; pas de dossier média à trimballer séparément.

> *« J'exporte tout mon blog, images comprises, en un fichier réimportable. »*

### 6️⃣ Console opérateur + reset mot de passe 🔑
Le panneau `admin.<board>.secubox.in/billets/` (surface opérateur SecuBox) donne
accès à **toutes** les surfaces admin (tableau de bord, nouveau billet,
modération, backup, flux) et à un **override mot de passe** : si l'auteur oublie
son mot de passe, l'opérateur (root) déclenche `/admin/override`, gardé par le
secret module `/etc/secubox/secrets/billets`, qui **génère un mot de passe fort
affiché une seule fois** (journalisé, rate-limité).

---

## 🟢 Prise en main (ROOT)

```bash
# 1. Installer le paquet
apt install secubox-billets            # crée le venv + pip install (Pillow inclus)

# 2. Créer l'auteur admin
cd /usr/lib/secubox/billets
sudo -u secubox venv/bin/python -m api.manage create-author admin

# 3. Router le vhost par le WAF (jamais de bypass)
haproxyctl vhost add billets.<board>.secubox.in
# + route sbxwaf: /etc/secubox/waf/haproxy-routes.json  ->  ["127.0.0.1", 8910]
systemctl restart secubox-billets
```

Écrire un billet : `…/admin/billets/new` → texte Markdown + éventuelle URL
(référence ou embed) + images (champ 🖼️). Publier.

---

## 🔒 Posture sécurité

| Contrôle | Mise en œuvre |
|----------|---------------|
| Upload | ré-encodage from-pixels (EXIF/polyglot strip), SVG refusé, cap 5 Mo avant traitement, dimensions bornées |
| Média servi | `/media/` nginx statique, `img-src 'self'` — aucun tiers, aucune relaxation CSP |
| Auth | argon2id (hors boucle), session signée itsdangerous, TOTP optionnel, double-submit CSRF, rate-limit par vrai client (X-Forwarded-For) |
| Override | secret opérateur root-only, comparaison constant-time (bytes), mot de passe affiché une fois (jamais en URL), audité |
| Boucle partagée | tout le CPU/IO (Pillow, base64, export) **hors event-loop** (`asyncio.to_thread`) — pas de SPOF board-wide |
| Journal | event-log append-only chaîné BLAKE2b ; révisions Gitea par billet |

---

## See also

- [[MODULES-EN]] · [[Architecture]] · [[API-Reference]]
- [[ToolBox]] 👁️ (WAF transparent qui route le vhost)
- `.claude/WEBUI-PANEL-GUIDELINES.md` — look & feel des panneaux admin
