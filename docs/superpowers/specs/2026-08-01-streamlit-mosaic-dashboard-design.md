# Mur mosaïque des applis Streamlit — Design

**Date :** 2026-08-01 · **Statut :** design validé, prêt pour plan d'implémentation
**Lié :** #946 (charge chronique), #896 (scale-to-zero)

---

## 0. Résumé

Un mur d'écrans montrant les 64 applis Streamlit déclarées : vignette de chacune,
état éveillé/endormi, temps restant avant mise en veille, et lien qui fonctionne
dans les deux états.

Trois invariants gouvernent le design :

- **Aucune tuile n'ouvre de session vers une appli.** Le mur peut rester affiché
  en permanence sans jamais empêcher une mise en veille.
- **La capture est un événement, jamais une boucle.** Mesuré à ~60 s par appli
  sur cette board ; en faire un cycle réveillerait le parc en permanence.
- **Le compte à rebours tourne dans le navigateur**, pas sur le serveur.

---

## 1. Contexte

`secubox-streamlit` gère **64 applis déclarées**, dont **21 tournent en
permanence**. L'audit de charge (#946) a établi que ces 21 processus — ~130
threads, chacun à 0,8 % de CPU mais constamment *runnables* — sont la première
source du load chronique de gk2.

Le mécanisme d'inactivité existe déjà dans `streamlitctl` : `app_idle_check`
compare `_app_last_active` à `timeout_minutes` et appelle `app_stop`. Le réveil
existe aussi (`app_wake`, #896). Ce qui manque est une **surface** : rien ne
montre quelles applis dorment, depuis quand, ni ce qu'elles contiennent.

Sans vignette, un parc d'applis endormies est indiscernable d'un parc vide.

---

## 2. Mesures — pourquoi la capture ne peut pas être périodique

Prises sur gk2 le 2026-08-01, board sous charge (load 88, lot de transcodage en
cours — donc pessimistes sur la durée, mais pas sur l'échec de rendu).

| Tentative | Durée | Résultat |
|---|---|---|
| `chromium --headless --virtual-time-budget=8000 --screenshot` | **93,6 s** | PNG 6 082 o |
| `chromium --headless=new --timeout=60000 --screenshot` | **58 s** | PNG 4 714 o |

Un PNG de 1280×800 pesant 5 Ko est une image quasi uniforme : **page blanche**.
Un rendu Streamlit réel pèse 50 à 300 Ko.

**La cause est structurelle.** Streamlit ne sert qu'une coquille HTML ;
l'interface n'apparaît qu'après connexion websocket et push du serveur. Le mode
`--screenshot` de chromium capture à l'événement `load`, donc avant que
l'application ait peint quoi que ce soit. Aucun réglage de délai ne corrige ça —
il faut **attendre un sélecteur du DOM**.

Deux conclusions :

1. Il faut piloter chromium par **CDP** (naviguer → attendre
   `[data-testid="stAppViewContainer"]` → capturer).
2. À ~60 s par capture, **la capture périodique est exclue**. Elle doit être
   déclenchée par événement.

---

## 3. La capture

### 3.1 Trois déclencheurs, jamais un timer

1. **Première inscription** — l'appli n'a pas encore d'image. Cycle unique :
   réveil → attente du rendu → capture → relâchement, et le compteur
   d'inactivité l'endort normalement.
2. **Mise à jour de l'appli** — `deploy`, `update`, ou changement du `mtime` du
   fichier source. Seul moment où l'image devient périmée.
3. **Rafraîchissement manuel** — un bouton par tuile.

### 3.2 L'image vit avec les métadonnées

`<APPS_PATH>/<app>/screenshot.png`, accompagné d'un `screenshot.json` :

```text
captured_at    epoch de la capture
source_mtime   mtime du fichier source de l'appli au moment de la capture
source_size    taille de ce même fichier
ok             la capture a-t-elle réussi
```

`source_mtime` et `source_size` forment l'empreinte de version : si l'un des
deux diffère de l'état courant, l'image est périmée. Deux `stat` suffisent donc
à le savoir — **sans jamais interroger l'appli**.

### 3.3 Le captureur doit être invisible au compteur d'inactivité

`_app_active_conns` compte **toutes** les connexions établies au port, sans
filtrer la source :

```bash
lxc-attach -n "$LXC_NAME" -- ss -tn state established "sport = :$port" \
    | awk 'NR>1' | wc -l
```

Sans exclusion, chaque capture repousserait la mise en veille — et le premier
passage sur le parc rendrait le scale-to-zero inopérant.

Chromium tourne sur **l'hôte** et joint l'appli via le bridge `br-lxc` ; ses
connexions arrivent donc avec l'adresse de passerelle du bridge comme source.
Le filtre exclut cette adresse :

```bash
lxc-attach -n "$LXC_NAME" -- ss -tn state established "sport = :$port" \
    | awk -v gw="$BRIDGE_GW" 'NR>1 && $4 !~ gw' | wc -l
```

L'adresse est dérivée de la configuration, jamais codée en dur. Le filtre porte
sur l'adresse **distante** (colonne 4 de `ss`), qui est celle du client.

C'est le seul point où la fonctionnalité n'est pas purement additive : elle
modifie une fonction existante du chemin d'inactivité.

### 3.4 Le client CDP

Module Python d'environ 80 lignes, sans dépendance nouvelle — chromium est déjà
présent sur l'hôte, et le module a déjà `websockets`.

```text
lancer chromium --remote-debugging-port
  → Page.navigate
  → attendre [data-testid="stAppViewContainer"] (timeout borné)
  → Page.captureScreenshot
  → fermer
```

**Une capture à la fois, sérialisée.** Avec ~2 Go de RAM disponibles sur la
board, deux chromium concurrents ne passent pas.

Playwright a été écarté : il embarque ses propres binaires navigateur (plusieurs
centaines de Mo) et une pile supplémentaire, pour un gain limité au regard d'un
besoin aussi étroit.

### 3.5 Premier passage sur le parc

**Les 21 applis déjà éveillées d'abord** — elles ne coûtent aucun cycle de
réveil. Les 43 endormies sont capturées **paresseusement, à leur prochain
réveil naturel**. Réveiller tout le parc pour une photo serait exactement le
réveil de masse que ce design cherche à éviter.

### 3.6 Dégradation

- Pas d'image → tuile portant l'emoji et le nom de l'appli. Jamais une case vide.
- Capture en échec → l'image précédente est **conservée** et l'échec signalé.
  Effacer une vue valide parce qu'une capture a raté serait une régression.
- Image périmée → affichée et **marquée** comme telle. Mieux vaut une vue
  ancienne signalée qu'un trou.

---

## 4. Le mur

Grille responsive, une tuile par appli. Chaque tuile porte :

- le **screenshot** conservé, en fond ;
- un **bandeau d'état** — 🟢 éveillée · 😴 endormie · ⏳ réveil en cours ;
- le **tempo** — temps restant avant veille si éveillée, durée de sommeil sinon ;
- le **lien réel** vers l'appli ;
- **réveiller** (endormie) ou **recapturer** (éveillée).

**Invariant : aucune tuile n'ouvre de session vers l'appli.** Le mur ne lit que
l'API du module et des PNG servis en statique.

**Le rafraîchissement porte sur les métadonnées, pas sur les images.** Un `GET`
toutes les 30 s met à jour états et compteurs ; un PNG n'est rechargé que si son
`captured_at` a changé. Sur 64 tuiles, recharger les images à chaque tick serait
absurde.

**Mode TV** : plein écran, sans chrome, tuiles agrandies, tri par état —
éveillées d'abord.

Look & feel : `WEBUI-PANEL-GUIDELINES.md` (hybrid-dark, Courier Prime, cyan
`#00d4ff`, sidebar partagée, jamais réécrite à la main).

---

## 5. Le tempo de veille

La donnée existe : `_app_last_active` et `timeout_minutes`. Elle n'est
simplement pas exposée par appli — `/power/status` ne parle que du conteneur LXC
entier.

`GET /apps` s'enrichit de :

```text
state                 running | sleeping | waking
last_active           horodatage absolu (epoch)
idle_seconds          calculé au moment de la réponse
sleep_after_seconds   timeout_minutes × 60
```

**Le serveur ne décompte pas.** Il renvoie l'horodatage absolu et le délai ; le
navigateur fait tourner le compte à rebours localement. Un mur de 64 tuiles
égrenant les secondes ne génère alors aucun trafic.

---

## 6. Les vhosts réels

Aujourd'hui tout passe par un chemin — `/streamlit/<app>` — et le `domain` par
appli est commenté dans la configuration d'exemple.

Un vhost par appli (`<app>.gk2.secubox.in`) demanderait 64 entrées HAProxy, 64
blocs nginx et 64 certificats. Écarté.

**Forme retenue : un wildcard.** `*.streamlit.gk2.secubox.in` — **un**
certificat, **une** règle HAProxy, et un `map` nginx traduisant le sous-domaine
en port. Ajouter une appli ne demande alors aucune configuration.

### 6.1 Réveil par vhost

Une appli endormie n'écoute sur aucun port : son vhost renverrait 502. Sur échec
de connexion, nginx doit servir une **page de réveil** qui déclenche `wake` puis
redirige une fois le port ouvert.

Le mécanisme de réveil existe et a été prouvé (#896), **avec une lacune connue
sur la restauration des routes au réveil** (`wake.py` renvoie `routes={}`).
C'est cette lacune que cette section doit combler.

**Dépendance assumée** : si elle n'est pas levée, la partie vhost est livrable
en second temps — le mur reste utile avec les URL par chemin actuelles.

---

## 7. Hors périmètre

- Interaction dans la tuile (iframe) — écartée : elle ouvre une session et
  empêche la mise en veille, ce que tout le design cherche à éviter.
- Historique des captures — une image courante par appli suffit.
- Capture des applis non-Streamlit du parc.
- Réglage du `timeout_minutes` par appli depuis le mur — lecture seule pour
  l'instant.

---

## 8. Tests

- **Client CDP** : sur une appli Streamlit connue, la capture doit produire un
  PNG > 20 Ko. Le test qui compte est celui qui **échoue sur une page blanche** —
  c'est le défaut observé, et un test de non-régression naturel.
- **Exclusion du captureur** : après une capture, `_app_active_conns` doit
  renvoyer le même nombre qu'avant. C'est l'invariant central du design.
- **Événementiel** : aucun timer ne doit déclencher de capture. Un test vérifie
  qu'aucune unité systemd livrée n'appelle le captureur périodiquement.
- **Dégradation** : capture en échec → l'image précédente survit et l'échec est
  signalé.
- **Tempo** : `last_active` renvoyé est un horodatage absolu, pas un décompte.

Environnement : `.venv` du dépôt, exécution par répertoire (collision de
`pytest.ini`).

---

## 9. Découpage

1. **Exposition du tempo** — `GET /apps` enrichi. Indépendant, livrable seul,
   utile immédiatement.
2. **Client CDP + stockage de l'image** — avec l'exclusion du captureur dans
   `_app_active_conns`. C'est le cœur.
3. **Le mur** — panneau mosaïque, mode TV, boutons réveil et recapture.
4. **Vhost wildcard + page de réveil** — dépend de la lacune #896, livrable en
   dernier.
