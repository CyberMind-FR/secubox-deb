<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-zia — ZIA Hall

**ZIA** est l'IA locale d'AletheiaVox / SBXOS : l'**interface humaine du bus d'objets**
du Hall. Elle ne possède pas les données — elle **interprète et orchestre** les objets déjà
exposés par SecuBox. Le Hall fournit le contexte, le bus reste la source de vérité, chaque
service garde son autonomie.

- Design de référence : [`docs/design/ZIA-HALL-POC.md`](../../docs/design/ZIA-HALL-POC.md)
  · visuel [`zia-hall.html`](../../docs/design/zia-hall.html) · cardlet [`zia-chat-cardlet.html`](../../docs/design/zia-chat-cardlet.html)
- Wiki : [ZIA-Hall](https://github.com/CyberMind-FR/secubox-deb/wiki/ZIA-Hall) · Suivi : **issue #1245**

> **Statut : POC — pas encore implémenté.** Ce README est le plan de la grosse session
> d'implémentation. Voir `.claude/TODO.md` (section ZIA) pour le découpage P0→P5.

## Trois niveaux

1. **ZIA Hall Lite** (🦊) — toujours locale : chat, intention, résumés, appels d'outils,
   recherche d'objets. Contexte court et borné.
2. **ZIA VHOST / Full** (🦝) — spécialisée par service : RAG + outils propres. Facultative.
3. **Remote / Cloud** (🐻) — escalade contrôlée, désactivée par défaut, mTLS/JWT, fallback local.

## Structure cible

```
secubox-zia/
  api/
    main.py       # FastAPI : POST /v1/chat, GET /health, GET /metrics
    runtime.py    # adaptateur modèle : llama.cpp (llama-server) OU repli heuristique
    bus.py        # client bus d'objets : normalise vers le contrat, applique la visibilité
    tools.py      # schémas + dispatch : search_objects, get_object, list_recent, open, delegate
    policy.py     # ACL / scope / remote autorisé / budgets
    rag.py        # (optionnel, niveau 2)
    adapters/     # PeerTube, Nextcloud, BBS, Radio, MetaNews… → objets sbx://
  www/zia/
    index.html    # cardlet Chat plein cadre (vhost)
    micro.html    # carte /micro du Hall
  conf/zia.toml   # modèle, contexte, remote, budgets
  systemd/secubox-zia.service   # User=secubox, socket /run/secubox/zia.sock
  nginx/zia.conf  # /zia/ (statics) + /api/v1/zia/ (proxy socket)
  menu.d/6xx-zia.json
  debian/{control,rules,changelog,postinst,prerm,source/format}
  tests/
```

## Contrat d'objet & outils

```json
{ "id":"radio:item:123", "type":"media.audio", "service":"radio",
  "title":"…", "summary":"…", "uri":"sbx://radio/item/123",
  "visibility":"guest|registered|member|admin", "actions":["open","play","discuss"] }
```

Outils POC (**lecture d'abord**) : `hall.search_objects()` · `hall.get_object()` ·
`hall.list_recent()` · `hall.open()` · `hall.delegate()`. Écriture après validation des
permissions.

## Interfaces HTTP

| Méthode | Route | Rôle |
|---|---|---|
| POST | `/api/v1/zia/v1/chat` | message → texte + objets référencés + actions + délégation |
| GET | `/api/v1/zia/health` | vivant, modèle chargé ? |
| GET | `/api/v1/zia/metrics` | tokens/s, RSS, latence, quota |

`/chat` renvoie `{ text, objects[], actions[], delegate?:{to,reason} }`.

## Runtime & modèle (ARM64)

llama.cpp + GGUF quantifié (`llama-server` local sur socket/port). Le modèle **final se
choisit après benchmark** sur la MOCHAbin de référence. Sans modèle chargé, `runtime.py`
retombe sur un répondeur **heuristique** (intention + appels d'outils) — utile pour P1/P2
et « QA sans inventer d'objet ».

| Profil | Ordre de grandeur | Usage | Priorité |
|---|---|---|---|
| Ultra-lite | ~0.5–1.5B Q4 | intent, aide, outils, résumé | prioritaire |
| Lite+ | ~1.5–3B Q4 | QA/RAG plus confortable | à tester |
| Full local | >3B | raisonnement plus riche | non prioritaire |
| Remote | externe | cas difficiles | optionnel |

```bash
# P0 — à benchmarker sur la MOCHAbin réelle
./llama-cli -m /data/models/model.gguf -t 4 -c 2048 -n 128 \
  -p "Tu es ZIA, assistant local du Hall. Réponds en une phrase."
```

## Sécurité

Le LLM n'est **jamais** une autorité. ACL hors modèle ; appels validés par schéma, liste
blanche, permissions. Contenus récupérés = **données**, jamais instructions. Remote :
politique explicite, rédaction des secrets, audit, timeout, budget, circuit breaker,
fallback local.

## Roadmap (voir `.claude/TODO.md`)

- **P0** llama.cpp ARM64 + GGUF sur MOCHAbin (RAM/CPU/tokens·s mesurés)
- **P1** daemon `/v1/chat` + 3 outils (répondeur heuristique + bus mock)
- **P2** 20–50 objets réels via adapters (QA sans inventer d'objet)
- **P3** cardlet Chat SBXOS (texte + ouverture `sbx://`)
- **P4** délégation VHOST (bascule explicite)
- **P5** remote optionnel (politique + fallback)

## P0 — brancher un modèle (sur la MOCHAbin)

Livré **turnkey** (le hook `llm_url` est déjà là ; les objets viennent toujours des outils) :

```bash
# 1) installer llama.cpp (ARM64, build) + un GGUF ULTRA-LITE Q4, brancher llama-server,
#    benchmarker, et pointer ZIA dessus. RAM serrée sur box chargée -> ultra-lite only.
sudo MODEL_URL="https://…/Qwen2.5-0.5B-Instruct-Q4_K_M.gguf" secubox-zia-p0-install
# 2) mesurer à part si besoin
secubox-zia-bench /data/models/model.gguf
```

- `secubox-zia-llm.service` — llama-server local (127.0.0.1:8091), `MemoryMax=1400M` pour
  protéger le parc ; ne démarre que si `/data/zia/llama-server` **et** un `/data/models/*.gguf`
  existent (sinon ZIA reste en répondeur heuristique).
- L'installateur écrit `llm_url` dans `/etc/secubox/zia.toml` et redémarre `secubox-zia`.
- **Contrainte réelle** (gk2, 30/08) : ~1 Go RAM dispo → un ~0.5 B Q4 seulement ; libérer de
  la RAM ou viser l'ultra-lite. À mesurer, jamais supposer.

> **✅ P0 RÉSOLU — off-box (gk2, 30/08).** Le **build** llama.cpp *sur la box* la saturait
> (OOM du parc, load 13). On l'a écarté : le paquet **`secubox-zia-llm`** livre un
> llama.cpp **arm64 STATIQUE cross-compilé hors box** (aucune dépendance glibc → tourne tel
> quel). `secubox-zia-getmodel <url.gguf>` télécharge **Qwen2.5-0.5B Q4** (469 Mo, *pas de
> build*) et démarre le serveur capé.
> **Résultat mesuré** : `llama-server` **~331 Mo RSS**, box **1429 Mo libres**, load qui
> **redescend**, parc intact — ZIA passe en `engine: llm`. Le *build* était le seul
> problème ; le *runtime* 0.5 B est léger. Voir `packages/secubox-zia-llm/`.

## Definition of Done

La MOCHAbin fait tourner la ZIA locale de façon stable, répond aux demandes simples,
retrouve les objets **sans contourner les ACL**, affiche leurs actions dans SBXOS, et délègue
proprement ce qu'elle ne sait pas traiter.

## Dépendances (prévues)

`secubox-core (>= 1.0)`, `python3`, `python3-uvicorn`, `python3-httpx`. Recommande :
`llama.cpp` (paquet séparé / build ARM64), un modèle GGUF sous `/data/models/`.
