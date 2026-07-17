# sbxwaf — mode `escalate` (observer, puis bannir un scanner récidiviste)

**Date** : 2026-07-17
**Statut** : conception validée, prête pour le plan d'implémentation
**Auteur** : Gérald Kerma <devel@cybermind.fr>

---

## Objectif

Qu'une catégorie de règles WAF **observe** les premières sondes d'une IP (comme `detect` : passe et
journalise), puis, une fois qu'elle a sondé **N** fois dans une fenêtre, la **banne** réellement
(cscli → drop nft). `escalate` = `detect` jusqu'à N, puis `block`.

## Pourquoi ce mode

Ce spec est la moitié « mécanisme » d'un besoin en deux moitiés :

| Sous-système | Ce spec | Ce que ça devient |
|---|---|---|
| **A — mode `escalate`** (Go) | **CE spec** | le mécanisme |
| **B — générateur Nuclei→règles** (Python) | spec séparé, ensuite | remplit une catégorie en `escalate` |

Le but final (spec B) : ficher les scanners qui sondent des exploits de produits **absents** de la box
(F5, PAN-OS, Ivanti…). Une requête `/mgmt/tm/util/bash` sur une box sans F5 est un signal pur, à zéro
faux positif possible *parce que le produit est absent*. Le mode `detect` (livré, PR #872) permet de
les regarder faire ; `escalate` ajoute : *un scanner qui insiste finit banni*.

Ce spec ne traite QUE le mécanisme. La génération et le filtre « produit absent » appartiennent au
spec B, qui produira des règles naissant en `detect` pur (voir §Sûreté).

### `escalate` n'affaiblit PAS l'autoban — il l'étend

Le mode `block` reste le défaut et **banne toujours les agressions immédiatement** (3 hits / 5 min →
cscli/nft). Les 17 catégories livrées n'ont pas de `mode` : elles restent en `block`. C'est le rôle
premier du WAF et ce spec n'y touche pas — il ne fait qu'*ajouter* un troisième comportement pour un
cas que le ban rapide manque : le scanner lent. Une IP qui sonde un exploit F5 aujourd'hui, un exploit
Ivanti demain, échappe à la fenêtre de 5 min du mode `block` ; `escalate` la compte sur une fenêtre
longue et finit par la bannir. C'est de l'autoban, réglé pour un adversaire patient — pas un recul sur
le blocage.

| Mode | Situation | Ban |
|---|---|---|
| `block` (défaut, inchangé) | agression réelle sur un produit présent | oui, immédiat |
| `escalate` | scanner insistant sur des produits absents | oui, après N sondes |
| `detect` | validation d'une règle avant de l'armer | non |

## Le réel mesuré (2026-07-17)

- sbxwaf a déjà **trois briques** qui composent `escalate` :
  - `Ban.Record(ip, now) → (count, banned)` : compteur glissant par IP, `banned` quand
    `count >= threshold` (`ban.go:60`). Instance de prod : `NewBan(300s, 3)` (`main.go:681`).
  - `CscliReporter` : ban nft réel via `cscli decisions add` (`crowdsec.go:204`).
  - les chemins `block` (403 + `crowdsec.Report`) et `detect` (log + passe) livrés (PR #872).
- **Le compteur du mode `block` est réglé sur 300 s / 3** — pensé pour une attaque active et rapide.
- Le mode `mode` par catégorie existe déjà : `block` | `detect`, absent ⇒ `block`, inconnu ⇒ `block`
  (fail-closed) — `rules.go`.
- Le WAF est en frontal de **tous les vhosts publics** (118 services, load courant ~27 en transcodage).

---

## Conception

### La troisième valeur de `mode`

`mode` accepte désormais `block` | `detect` | `escalate`. Les règles inchangées :

- **absent / `""` / `null` ⇒ `block`** — les 17 catégories livrées ne changent pas.
- **valeur inconnue ⇒ `block` + log bruyant** — fail-closed, un typo ne désarme jamais.

Ajout d'une constante `modeEscalate = "escalate"` à côté de `modeBlock` / `modeDetect`.

### Le compteur SÉPARÉ — le cœur du design

`escalate` n'utilise **pas** le `Ban` du mode `block`. Raisons :

1. **Fenêtre.** Un scanner peut sonder une fois par jour ; la fenêtre `block` de 5 min ne l'attrape
   jamais. `escalate` a besoin d'une fenêtre **longue** (heures/jours).
2. **Signal.** Mélanger « attaques bloquées » (block) et « sondes de produits absents » (escalate)
   dans un même compteur donnerait « 1 SQLi + 2 sondes F5 = ban » — deux signaux distincts confondus.

Le serveur porte donc une **deuxième instance `Ban`**, `escalateBan`, avec sa propre fenêtre et son
propre seuil, configurables :

```
--escalate-window   (Duration, défaut 24h)   fenêtre glissante du compteur escalate
--escalate-threshold (Int, défaut 3)          nombre de sondes avant ban
```

Défauts : **3 sondes de produits absents en 24 h → ban**. Une IP qui cherche trois exploits de
logiciels qu'on ne fait pas tourner, en un jour, est un scanner confirmé.

### Le chemin `escalate` dans `main.go`

À l'unique site d'appel (après `Match`, qui remonte déjà le `mode`) :

```
hit && mode == modeEscalate :
    count, banned := s.escalateBan.Record(ip, now)
    if banned :
        // Le Nième franchissement : bannir pour de vrai.
        // Réutilise le chemin block existant — 403, action="banned",
        // s.crowdsec.Report(ip, cat, sev). Ne PAS mettre hit=false.
    else :
        // Encore en observation : journaliser et laisser passer.
        // Réutilise le chemin detect — threatLog action="detect", hit=false.
```

Aucune logique nouvelle de ban ni de report : `escalate` **compose** les deux chemins existants,
gatés sur `escalateBan.Record`. Le journal reste honnête (PR #872) : les sondes observées portent
`action="detect"` (exclues du compteur « bloqué »), le ban porte `action="banned"` (compté).

### Interaction avec `escalateBan == nil`

Comme `crowdsec` est nil-able (`main.go`), `escalateBan` peut l'être en test. Si `escalateBan == nil`,
une catégorie `escalate` se comporte comme `detect` (observe, ne banne jamais) — jamais comme `block`.
Fail-**open côté ban** est correct ici : l'absence de compteur ne doit pas transformer l'observation
en blocage silencieux.

---

## Sûreté — deux limites posées franchement

1. **Scanner distribué.** Une IP par sonde n'atteint jamais N : `escalate` ne l'escalade pas (chaque
   sonde reste en `detect`, observée). C'est une limite assumée du modèle par-IP ; la corréler
   (par ASN, par empreinte JA4) est un autre système (C2 auto-learn existe déjà, hors périmètre).
2. **Le ban `escalate` = drop nft = tout le trafic de l'IP.** Une règle mal écrite qui matcherait du
   trafic légitime bannirait un vrai utilisateur au noyau. Donc (contrainte pour le spec B) : **une
   règle générée naît en `detect` pur**, l'opérateur vérifie zéro faux positif sur du trafic réel,
   **puis** la promeut en `escalate` à la main. Jamais de génération directe vers un mode qui banne.
   Ce spec ne fournit que le mode ; il n'arme rien tout seul.

---

## Tests

- **Défaut / fail-closed** : catégorie sans `mode` bloque ; valeur inconnue bloque + log (non-régression
  des 17, déjà couvert — étendre pour inclure `escalate` dans le switch).
- **Parsing** : `mode: "escalate"` → `modeEscalate` ; roundtrip.
- **Observe avant seuil** : sur une catégorie `escalate` (seuil 3), les sondes 1 et 2 d'une même IP
  **passent** (≠403), sont journalisées `action="detect"`, et **ne bannissent pas** (pas d'appel
  `crowdsec.Report`).
- **Ban au seuil** : la 3e sonde de la même IP **bloque** (403), journalise `action="banned"`, et
  appelle `crowdsec.Report` **une** fois.
- **Compteur séparé** : des hits en mode `block` n'avancent pas le compteur `escalate` et
  réciproquement (deux instances `Ban` distinctes).
- **Fenêtre** : deux sondes espacées au-delà de `--escalate-window` ne cumulent pas (réutilise la
  logique de fenêtre glissante de `Ban`, déjà testée).
- **`escalateBan == nil`** : une catégorie `escalate` se comporte comme `detect` (observe, ne banne
  jamais), pas comme `block`.
- **Fichier de règles réel** : la parité (`TestWAFParity/*`) reste verte contre les 149 patterns de
  prod (aucune catégorie n'est en `escalate`, donc aucun changement).

Chaque test comportemental doit pouvoir échouer : le prouver par mutation (casser, constater, restaurer).

---

## Découpage

| Phase | Contenu | Risque |
|---|---|---|
| 1 | `modeEscalate` dans le parsing + switch (fail-closed) | faible |
| 2 | `escalateBan` (2e instance) + flags + branche `escalate` composant detect/block | moyen — le cœur |
| 3 | Déploiement gk2 : build arm64, `mv` + `systemctl restart secubox-waf-ng`, preuve live sur une catégorie de test | moyen |

⚠️ Contraintes de déploiement établies : `cp` échoue (« text file busy ») → `mv` ; **jamais**
`kill -HUP` → `systemctl restart secubox-waf-ng`. Preuve live : basculer une catégorie de test en
`escalate` (seuil bas), envoyer N sondes depuis une IP forgée, vérifier passe→passe→ban, puis
restaurer. sbxwaf est en frontal de tout : juger par les codes HTTP (valides sous charge), avec retry.

Hors périmètre : la génération de règles (spec B), la corrélation par ASN/JA4 (C2 existant), la
promotion automatique `detect`→`escalate` (décision humaine).
