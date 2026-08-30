<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# ZIA Hall — POC ARM64

**Design de référence — v0.1 · 30 août 2026 · SecuBox-Deb / SBXOS**

> Suivi : [issue #1245](https://github.com/CyberMind-FR/secubox-deb/issues/1245) · version visuelle : [`zia-hall.html`](zia-hall.html)

ZIA est l'IA locale d'**AletheiaVox / SBXOS** : l'**interface humaine du bus d'objets** du
Hall, connectée en ARM64, avec délégation vers les VHOST et recours remote optionnel.

## Principe directeur

**L'IA ne possède pas les données** : elle interprète et orchestre les objets déjà exposés
par SecuBox. Le Hall fournit le contexte, **le bus reste la source de vérité**, et chaque
service conserve son autonomie.

Cible POC : valider sur MOCHAbin / Linux ARM64 une conversation locale courte, la recherche
d'objets du Hall et une délégation explicite vers un service spécialisé. Les performances
seront **mesurées** sur le matériel réel plutôt que supposées.

## Trois niveaux

| Niveau | Rôle | Porte |
|---|---|---|
| **1 · ZIA Hall Lite** 🦊 | Toujours locale | Bus + objets + médias |
| **2 · ZIA VHOST / Full** 🦝 | Spécialisée par service | RAG + outils du service |
| **3 · Remote / Cloud** 🐻 | Escalade contrôlée (optionnel) | Modèle plus puissant · mTLS/JWT |

- **Lite** — chat, classification d'intention, reformulation, petits résumés, appels
  d'outils, recherche d'objets, aide contextuelle. Contexte court et borné.
- **VHOST/Full** — instance facultative par service ; plus de contexte, index RAG, outils
  propres.
- **Remote** — dernier recours, désactivé par défaut ou soumis à politique ; seul le
  contexte nécessaire est transmis. Le 100 % local reste possible.

La séparation évite qu'un gros modèle devienne à la fois moteur de chat, moteur de recherche,
ACL, indexeur et passerelle réseau.

## Flux d'une requête

1. **Hall** — message + session
2. **Policy** — scope, droits, remote autorisé ?
3. **ZIA Lite** — intention + choix d'outil
4. **Bus** — objets autorisés uniquement (ACL appliquées)
5. **ZIA Lite** — réponse + références
6. **Routeur** — VHOST puis remote si nécessaire
7. **Hall** — texte + cardlets / actions

_Exemple : « trouve la dernière vidéo sur le WAF ». ZIA appelle le bus, qui retourne les
objets PeerTube visibles ; le Hall affiche la réponse et la cardlet vidéo. Le modèle n'a
jamais eu à connaître l'API interne de PeerTube._

## Contrat ZIA / bus d'objets

Le LLM n'accède jamais aux bases ni aux VHOST. Le bus applique authentification, droits et
filtrage avant de retourner un objet.

```json
{
  "id": "radio:item:123",
  "type": "media.audio",
  "service": "radio",
  "title": "Émission du jour",
  "summary": "…",
  "uri": "sbx://radio/item/123",
  "visibility": "guest|registered|member|admin",
  "actions": ["open", "play", "discuss"]
}
```

**Outils POC (lecture d'abord)** : `hall.search_objects()` · `hall.get_object()` ·
`hall.list_recent()` · `hall.open()` · `hall.delegate()`. Les outils d'écriture viendront
après validation du modèle de permissions.

## Runtime ARM64 & choix du modèle

llama.cpp avec un modèle GGUF quantifié : exécution CPU ARM64, contrôle des threads, du
contexte et de la mémoire. Le modèle final est choisi **après benchmark** sur la MOCHAbin.

| Profil | Ordre de grandeur | Usage POC | Priorité |
|---|---|---|---|
| Ultra-lite | ~0.5–1.5B · Q4 | intent, aide, outils, résumé | **prioritaire** |
| Lite+ | ~1.5–3B · Q4 | QA / RAG plus confortable | à tester |
| Full local | > 3B | raisonnement plus riche | non prioritaire |
| Remote | externe | cas difficiles | optionnel |

Candidats : petites familles Qwen, Llama/TinyLlama, autres GGUF. Évaluer surtout le français,
les tool calls, la qualité en contexte court, la latence sur le SoC réel.

```bash
# à benchmarker sur la MOCHAbin réelle
./llama-cli -m /data/models/model.gguf -t 4 -c 2048 -n 128 \
  -p "Tu es ZIA, assistant local du Hall. Réponds en une phrase."
# mesurer : chargement, RSS, tokens/s (prompt+génération), CPU, °C, 1er token, qualité (30 Q)
```

## Sécurité & souveraineté

**Le LLM n'est jamais une autorité.** Les ACL vivent hors modèle ; les appels d'outils sont
validés par schéma, liste blanche et permissions. Les contenus récupérés sont traités comme
des **données**, jamais comme des instructions. Remote : politique explicite, rédaction des
secrets, audit, timeout, budget, circuit breaker, fallback local.

Piliers : **Local First** · **Privacy by Design** · **Modulaire** · **Ouvert & interopérable**.

## POC exécutable

| Étape | Livrable | Succès |
|---|---|---|
| P0 | llama.cpp ARM64 + GGUF | RAM / CPU / tokens·s mesurés |
| P1 | `/chat` + 3 outils | tool routing correct |
| P2 | 20–50 objets réels | QA sans inventer d'objet |
| P3 | Cardlet Chat SBXOS | texte + ouverture `sbx://` |
| P4 | délégation VHOST | bascule explicite |
| P5 | remote optionnel | politique + fallback local |

Interfaces minimales : `POST /v1/chat`, `GET /health`, `GET /metrics`. `/chat` renvoie
texte, objets référencés, actions et information de délégation.

## Structure de code suggérée

```
secubox-zia/
  daemon/     # API locale (/v1/chat, /health, /metrics)
  runtime/    # llama.cpp
  bus/        # client bus d'objets
  tools/      # schémas + validation
  policy/     # ACL / remote / budgets
  rag/        # optionnel
  adapters/   # PeerTube, Nextcloud, BBS…
  web/        # cardlet Hall (Chat)
  tests/
  packaging/
```

## Definition of Done

Le POC est validé lorsque la MOCHAbin fait tourner la ZIA locale de façon **stable**, répond
aux demandes simples, retrouve les objets **sans contourner les ACL**, affiche leurs actions
dans SBXOS et délègue proprement ce qu'elle ne sait pas traiter.

_Décision : architecture cohérente avec Hall/SBXOS — IA locale très légère comme interface du
bus, intelligence spécialisée dans les VHOST, remote seulement comme extension. On peut
commencer minuscule sans enfermer l'architecture._
