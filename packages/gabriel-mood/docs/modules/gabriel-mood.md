<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
     Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr> -->

# gabriel-mood

Détecteur d'**indices prosodiques**, entièrement local.

---

## Ce que ce module fait, et ce qu'il ne fait pas

Il mesure ce qu'une voix **fait entendre** : hauteur, énergie, débit,
irrégularité de période et d'amplitude, couleur spectrale.

**Il ne lit pas les émotions.** Cette phrase n'est pas une précaution
juridique ; c'est la description exacte de ce que permet l'état de l'art.

La littérature établit solidement que ces grandeurs suivent l'**activation** :
on parle plus haut, plus fort et plus vite quand on est activé, quelle qu'en
soit la cause. Elle n'établit **pas** la valence — rien dans le signal ne
distingue de façon fiable la joie de la colère, ni l'enthousiasme de la
panique. Deux personnes activées pour des raisons opposées sonnent pareil.

S'y ajoutent trois limites qu'aucun modèle ne lève :

| Limite | Conséquence |
|---|---|
| Tout est relatif à la **personne** | Une voix grave n'est pas une voix abattue. Seul l'écart à *son propre* ordinaire veut dire quelque chose. |
| Tout est relatif à la **situation** | Lire à voix haute, expliquer, plaisanter et se disputer ont des prosodies différentes sans changement d'humeur. |
| La **culture, la langue, l'âge, un rhume, un micro mal placé** | Déplacent ces grandeurs autant que n'importe quelle émotion. |

> **À n'utiliser ni pour évaluer quelqu'un, ni pour décider quoi que ce soit le
> concernant.** Ce module est fait pour qu'une personne observe sa propre voix,
> sur sa propre machine.

### Comment cette règle est tenue dans le code

Ce ne sont pas des intentions : chacune est vérifiée par un test qui échoue si
on la retire.

| Garantie | Où | Test |
|---|---|---|
| Confiance plafonnée à **0,72** | `ser.PlafondConfiance` | `TestAucuneLectureNeDepasseLePlafondDeConfiance` |
| Aucun état sans **étalon personnel** | `ser.Etalon.Pret()` | `TestSansEtalonOnNeRepondPas` |
| Aucun état sans **assez de voix** | `ser.MinTramesVoisees` | `TestSansAssezDeVoixOnNeRepondPas` |
| La **réserve** accompagne chaque réponse | `ser.Reserve` | `TestLaFormeDeLaReponseSuitLeContrat` |
| Les **justifications** voyagent avec le verdict | `Lecture.Pourquoi` | idem |
| Un **modèle externe** ne contourne rien | `ser.Externe` | `TestUnModeleTropSurDeLuiEstRabote` |
| Une **source fabriquée** se déclare | `audio.Description.Reelle` | `TestUneSourceFabriqueeSeVoitDansLImage` |

L'état `indetermine` est une **réponse normale**, pas une panne — c'est même la
réponse des premières minutes, le temps que l'étalon se constitue.

---

## Confidentialité

- **Aucun échantillon audio n'est écrit sur le disque.** Ce n'est pas un
  réglage : il n'existe dans `internal/store` aucune colonne, aucun chemin,
  aucune fonction qui accepte des échantillons. Un test relit le schéma et
  échoue si l'on ajoute une colonne qui pourrait en contenir
  (`TestAucuneColonneNePeutContenirDuSon`).
- **Rien ne sort de la board.** L'unité systemd porte
  `RestrictAddressFamilies=AF_UNIX` : le processus ne peut techniquement pas
  ouvrir une connexion réseau.
- **L'historique tient en quelques nombres par minute** — hauteur médiane,
  énergie, débit, état — dont on ne peut reconstituer ni parole ni voix.
- **Purge automatique** (14 jours par défaut, `--retention`) et geste
  d'effacement (`POST /api/mood/oubli`, bouton « Oublier »).
- **Sessions anonymes**, identifiant jeté à la fermeture.
- Le micro n'est demandé **qu'au clic**, et `arrete()` coupe réellement la
  piste — la pastille d'enregistrement du navigateur s'éteint.

---

## Architecture

```
navigateur                          board
┌──────────────┐   PCM Int16 48k   ┌────────────────────────────────┐
│ getUserMedia │ ────────────────► │ ws/mood                        │
│ AudioWorklet │                   │  └─ anneau 2048/512            │
│              │ ◄──────────────── │       ├─ fft   → spectre       │
│  cockpit     │   JSON 20 img/s   │       ├─ vad   → parole ?      │
└──────────────┘                   │       ├─ pitch → YIN, jitter   │
                                   │       ├─ mfcc  → centre, pente │
                                   │       └─ ser   → indices       │
                                   └────────────────────────────────┘
```

**Le micro est celui du navigateur.** La board n'a souvent aucune entrée son —
celle de gk2 n'a qu'un `timer` dans `/dev/snd` — et surtout, le micro utile est
celui de la machine devant laquelle on est assis. L'audio traverse le réseau
**local** et s'arrête sur la board.

*Pourquoi ne pas tout faire dans le navigateur ?* Parce que l'analyse doit
pouvoir durer, se comparer à un étalon constitué sur des heures, et survivre à
la fermeture d'un onglet. Un `AnalyserNode` donne un joli spectre et rien
d'autre.

### Choix de traitement du signal

| Décision | Pourquoi |
|---|---|
| Trame **2048** (42,7 ms) | Il faut deux périodes pour voir la fondamentale : à 55 Hz, 1024 plafonnerait la détection à 94 Hz, au-dessus de beaucoup de voix d'hommes. |
| Pas **512** (10,7 ms) | C'est la latence d'analyse : on ne peut rien dire avant d'avoir accumulé un pas. |
| **YIN** plutôt qu'autocorrélation | L'autocorrélation saute une octave sur une voix riche en harmoniques. Le seuil absolu de YIN prend le *premier* creux acceptable, pas le meilleur. |
| YIN par **intercorrélation FFT** | La forme naïve demande deux millions d'opérations par trame, cent fois par seconde — le budget entier du module pour une seule mesure. |
| **128 bandes** log à l'écran | 1025 raies à 20 img/s feraient 150 ko/s de JSON pour un affichage large de quelques centaines de pixels. |
| Pitch **une trame sur deux** | YIN coûte cinq fois une FFT, et une hauteur ne change pas en dix millisecondes. |

### Pourquoi pas WebRTC VAD, pas ONNX Runtime

Le dépôt se construit en `CGO_ENABLED=0` et se croise vers arm64. Lier une
bibliothèque C imposerait une chaîne croisée **et** une bibliothèque partagée à
l'exécution. Le VAD est donc réécrit en Go — on reprend la *démarche* de
WebRTC (sous-bandes vocales, plancher appris) sans prétendre en reproduire les
coefficients : quelqu'un qui lit « WebRTC VAD » s'attend aux performances
publiées de WebRTC.

ONNX Runtime, lui, demande aussi `MemoryDenyWriteExecute=no` (il compile à la
volée). Il vit donc dans **son propre processus**, joint par socket unix
(`--inference`), ce qui garde ce service-ci pur Go et durci. **Aucun modèle
n'est livré** : les corpus publics d'émotion vocale sont joués par des acteurs,
et un modèle entraîné dessus rend des probabilités élevées et bien séparées sur
de la parole spontanée où elles n'ont aucun fondement.

---

## API

### `GET /api/mood`

```json
{ "state": "calm", "confidence": 0.42, "pitch": 132.4,
  "energy": 0.61, "speech_rate": 145,
  "indices": { "calm": 0.41, "joy": 0.12, "stress": 0.18,
               "anger": 0.04, "fatigue": 0.09, "focus": 0.16 },
  "activation": -0.21, "calibration": 1, "signal_suffisant": true,
  "pourquoi": ["voix proche de votre ordinaire (activation -0.21)"],
  "reserve": "Indices acoustiques, pas un état intérieur constaté…",
  "session": "9f3a…", "emoji": "😌" }
```

Sans session ouverte : `state: "indetermine"`, `confidence: 0`, et un
`pourquoi` qui l'explique. **Jamais 404** — personne n'écoute, ce n'est pas une
panne.

| Route | Rôle |
|---|---|
| `GET /api/mood` | La lecture courante. |
| `GET /api/mood/traits` | Les mesures **brutes**, pour contester la lecture. |
| `GET /api/mood/historique?heures=24` | Les agrégats par minute. |
| `POST /api/mood/oubli[?session=…]` | Efface. Refuse le GET. |
| `GET /api/sante` | Version, sessions, plafond de confiance, réserve. |
| `WS /ws/mood` | Le flux. |

### `WS /ws/mood`

Bidirectionnel : le navigateur envoie des trames **binaires** (Int16 LE, 48 kHz
mono), la board renvoie une image JSON 20 fois par seconde.

```json
{ "timestamp": 12040, "fft": [ … 128 valeurs dB … ],
  "pitch": 132.4, "energy": 0.61,
  "calm": 0.82, "joy": 0.07, "stress": 0.09, "anger": 0.02,
  "fatigue": 0.05, "focus": 0.11,
  "state": "calm", "confidence": 0.42, "activation": -0.21,
  "vad": true, "speech_rate": 145, "jitter": 0.84, "shimmer": 0.51,
  "clarity": 0.93, "latency_ms": 12.4, "cpu": 0.031,
  "calibration": 1, "source_reelle": true, "reserve": "…" }
```

Un échantillonnage autre que 48 kHz est **refusé explicitement** : lu comme du
48, un flux à 44,1 kHz décalerait toutes les hauteurs de 8,8 % — presque un
demi-ton et demi — sans que rien ne le signale.

Seule une page servie par la box peut ouvrir le flux (contrôle d'`Origin`).

---

## Mesures

Relevées sur cette machine de développement (x86-64), `go test -bench` :

| Étape | Coût | Allocations |
|---|---|---|
| `fft.Spectre` (2048) | 33 µs | 0 |
| `pitch.Estime` (2048) | 188 µs | 0 |
| Chaîne complète, par trame | ~166 µs | — |

Une trame arrive toutes les 10,7 ms ; le budget de 8 % d'un cœur vaut donc
853 µs. **Sur x86-64 on est à ~1,6 % d'un cœur.** Sur l'ARM64 de la board, il
faut compter un facteur 4 à 6 : l'ordre de grandeur reste tenable, mais **le
chiffre annoncé (< 8 %) n'a pas été vérifié sur arm64** et doit l'être avant
d'être affirmé. Le cockpit affiche la charge réellement mesurée
(`cpu`) — c'est une mesure, pas une estimation.

Latence : pas d'analyse (10,7 ms) + file d'attente de la session, affichée en
continu. L'objectif « < 50 ms » est tenu tant que la board suit ; le champ
`latency_ms` dit la vérité quand elle ne suit plus.

---

## Exploitation

```bash
systemctl status gabriel-mood
journalctl -u gabriel-mood -f
curl --unix-socket /run/secubox/gabriel-mood.sock http://x/api/sante | jq
```

Cockpit : `https://<hôte>/gabriel-mood/`

| Option | Défaut | Rôle |
|---|---|---|
| `--socket` | `/run/secubox/gabriel-mood.sock` | Écoute. |
| `--db` | `/var/lib/secubox/gabriel-mood/mood.db` | Historique ; vide = aucun. |
| `--retention` | `14d` | **0 désactive tout historique.** |
| `--inference` | *(vide)* | Socket d'un moteur externe. |
| `--adresse` | *(vide)* | TCP, pour le développement. |

### Construire le cockpit

```bash
npm install && npm run build     # → dist/, repris par debian/rules
```

`dist/` absent, le service sert l'API seule et le **dit dans son journal**.

---

## Écarts assumés par rapport au brief

| Demandé | Livré | Pourquoi |
|---|---|---|
| Go 1.25 | **Go 1.22** | Version du dépôt et des dépendances de construction. Rien dans le code ne demande plus récent. |
| Debian Trixie | **paquet bookworm** | La board de test est en Debian 12. Le code n'a aucune dépendance propre à Trixie. |
| WebRTC VAD | **VAD en Go pur** | CGO incompatible avec la construction croisée du dépôt. |
| ONNX Runtime | **processus séparé** | CGO, et `MemoryDenyWriteExecute`. Aucun modèle livré : voir plus haut. |
| `ProtectHome=read-only` | **`ProtectHome=yes`** | Strictement plus fermé, et sans coût : ce service ne lit rien dans `/home`. |
| Entrée audio locale | **micro du navigateur** | Décision de conception : la board n'a pas de carte son, et le micro utile est celui de l'utilisateur. |
