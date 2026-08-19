# BBS média intégré souverain — plan d'implémentation (#1056)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** intégrer un média WAN (YouTube) dans le BBS avec souveraineté progressive — WAN à la première vue, puis cache ytsas, puis miroir PeerTube ; l'original reste failover + tags.

**Architecture:** ytsas gagne un endpoint `GET /resolve` qui rend la meilleure source locale (mirror/cache/pending) et enfile le rapatriement. Le BBS gagne un connecteur `youtube` (client HTTP ytsas) qui mappe l'état à un rendu (iframe PeerTube / `<video>` ytsas / iframe youtube-nocookie), branché sur la fiche média existante.

**Tech Stack:** Python 3.11 + FastAPI (secubox-ytsas), Go (secubox-bbs, net/http + regexp), pytest, `go test`.

**Spec:** `docs/superpowers/specs/2026-08-19-bbs-media-embed-souverain-design.md`

## Global Constraints

- En-tête SPDX `LicenseRef-CMSD-1.0` en tête de CHAQUE nouveau fichier (cf. fichiers voisins).
- ytsas : endpoints en `@app.get(API + "/...")`, `API` = préfixe existant ; `/resolve` NE bloque JAMAIS sur un téléchargement.
- BBS : tout connecteur embarque `gateway.Base` (sinon ne compile pas) ; join **par video_id, jamais par titre** ; l'URL d'origine (`SourceURL`) n'est jamais jetée.
- Le navigateur ne contacte le tiers QU'À la première vue (embed `youtube-nocookie`), jamais `youtube.com` scripté.
- Bump de version obligatoire des deux paquets (patch = correctif, médiane = fonctionnalité).
- Français dans le code/commentaires (cohérence dépôt).

---

## Package A — secubox-ytsas

### Task 1: extraction du `video_id` YouTube

**Files:**
- Create: `packages/secubox-ytsas/lxc/app/ytid.py`
- Test: `packages/secubox-ytsas/tests/test_ytid.py`

**Interfaces:**
- Produces: `ytid.video_id(url: str) -> str | None` — id canonique (11 car.) ou `None` si non YouTube.

- [ ] **Step 1: Write the failing test**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "lxc" / "app"))
from ytid import video_id

def test_watch():
    assert video_id("https://www.youtube.com/watch?v=dQw4w9WgXcQ") == "dQw4w9WgXcQ"

def test_youtu_be():
    assert video_id("https://youtu.be/dQw4w9WgXcQ?t=10") == "dQw4w9WgXcQ"

def test_shorts():
    assert video_id("https://www.youtube.com/shorts/dQw4w9WgXcQ") == "dQw4w9WgXcQ"

def test_non_youtube():
    assert video_id("https://vimeo.com/12345") is None

def test_garbage():
    assert video_id("pas une url") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-ytsas && python -m pytest tests/test_ytid.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ytid'`

- [ ] **Step 3: Write minimal implementation**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ytsas :: extraction de l'identifiant vidéo YouTube.

Le join du tuyau souverain se fait par CET identifiant, jamais par le titre :
deux URL de la même vidéo (watch, youtu.be, shorts) doivent rendre le même id.
"""
import re
from urllib.parse import urlparse, parse_qs

_ID = re.compile(r"^[A-Za-z0-9_-]{11}$")


def video_id(url: str) -> str | None:
    try:
        u = urlparse(url)
    except (ValueError, AttributeError):
        return None
    host = (u.hostname or "").lower().removeprefix("www.")
    if host in ("youtube.com", "m.youtube.com"):
        if u.path == "/watch":
            v = parse_qs(u.query).get("v", [""])[0]
            return v if _ID.match(v) else None
        for pfx in ("/shorts/", "/embed/", "/v/"):
            if u.path.startswith(pfx):
                v = u.path[len(pfx):].split("/")[0]
                return v if _ID.match(v) else None
        return None
    if host == "youtu.be":
        v = u.path.lstrip("/").split("/")[0]
        return v if _ID.match(v) else None
    return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-ytsas && python -m pytest tests/test_ytid.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-ytsas/lxc/app/ytid.py packages/secubox-ytsas/tests/test_ytid.py
git commit -m "feat(ytsas): extraction video_id YouTube (ref #1056)"
```

---

### Task 2: endpoint `GET /resolve`

**Files:**
- Modify: `packages/secubox-ytsas/lxc/app/main.py` (ajouter la route ; réutilise `library`, `engine`, `video_id`)
- Test: `packages/secubox-ytsas/tests/test_resolve.py`

**Interfaces:**
- Consumes: `ytid.video_id` (Task 1) ; `Library.list()` (lignes avec `id`, `complete`, `peertube_url`), `Engine.add(url)`.
- Produces: `GET /resolve?url=<u>` → JSON `{"video_id", "state", "peertube_url"?, "stream_url"?, "title"?}` avec `state ∈ {mirror,cache,pending,unsupported}`.

Logique (résolution + rebond, sans blocage) :
- `video_id(url)` absent → `{"state":"unsupported"}`.
- ligne en librairie avec `peertube_url` → `{"state":"mirror","peertube_url":...}`.
- ligne `complete=1` sans PeerTube → `{"state":"cache","stream_url":"/stream/<id>"}`.
- sinon → **enfile** `engine.add(url)` puis `conserve` best-effort, `{"state":"pending"}`. Idempotent : si l'id est déjà en librairie/queue, ne ré-enfile pas.

- [ ] **Step 1: Write the failing test** (fake library/engine injectés)

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from fastapi.testclient import TestClient
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "lxc" / "app"))
import main

class FakeLib:
    def __init__(self, rows): self._rows = rows
    def list(self): return self._rows

class FakeEngine:
    def __init__(self): self.added = []
    async def add(self, url): self.added.append(url); return {"id": "dQw4w9WgXcQ", "status": "queued"}

def _client(rows):
    main.library = FakeLib(rows)
    main.engine = FakeEngine()
    return TestClient(main.app), main.engine

def test_mirror():
    c, _ = _client([{"id": "dQw4w9WgXcQ", "complete": 1, "peertube_url": "https://peertube.gk2/w/xy"}])
    r = c.get("/api/v1/ytsas/resolve", params={"url": "https://youtu.be/dQw4w9WgXcQ"})
    assert r.json()["state"] == "mirror"
    assert r.json()["peertube_url"] == "https://peertube.gk2/w/xy"

def test_cache():
    c, _ = _client([{"id": "dQw4w9WgXcQ", "complete": 1, "peertube_url": None}])
    j = c.get("/api/v1/ytsas/resolve", params={"url": "https://youtu.be/dQw4w9WgXcQ"}).json()
    assert j["state"] == "cache" and j["stream_url"].endswith("/dQw4w9WgXcQ")

def test_pending_enqueues():
    c, eng = _client([])
    j = c.get("/api/v1/ytsas/resolve", params={"url": "https://youtu.be/dQw4w9WgXcQ"}).json()
    assert j["state"] == "pending"
    assert eng.added == ["https://youtu.be/dQw4w9WgXcQ"]

def test_unsupported():
    c, _ = _client([])
    assert c.get("/api/v1/ytsas/resolve", params={"url": "https://vimeo.com/1"}).json()["state"] == "unsupported"
```

Note d'exécution : confirmer le préfixe exact (`API`) en tête de `main.py` et l'ajuster dans le test/route si différent de `"/api/v1/ytsas"`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-ytsas && python -m pytest tests/test_resolve.py -v`
Expected: FAIL — 404 (route absente) sur chaque cas.

- [ ] **Step 3: Write minimal implementation** (ajouter dans `main.py`, après `/list`)

```python
from ytid import video_id as _video_id  # en tête avec les autres imports

@app.get(API + "/resolve")
async def resolve(url: str):
    """Rend la meilleure source LOCALE pour une URL YouTube, et enfile le
    rapatriement si rien n'est encore là. Ne bloque jamais sur un download."""
    vid = _video_id(url)
    if not vid:
        return {"video_id": None, "state": "unsupported"}
    for row in library.list():
        if row.get("id") == vid:
            if row.get("peertube_url"):
                return {"video_id": vid, "state": "mirror",
                        "peertube_url": row["peertube_url"], "title": row.get("title")}
            if row.get("complete"):
                return {"video_id": vid, "state": "cache",
                        "stream_url": API + "/stream/" + vid, "title": row.get("title")}
            return {"video_id": vid, "state": "pending", "title": row.get("title")}
    try:
        await engine.add(url)          # enfile fetch (asynchrone, non bloquant)
    except Exception:                  # noqa: BLE001 — 403/cookies (#1051) : reste pending
        pass
    return {"video_id": vid, "state": "pending"}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-ytsas && python -m pytest tests/test_resolve.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-ytsas/lxc/app/main.py packages/secubox-ytsas/tests/test_resolve.py
git commit -m "feat(ytsas): GET /resolve — meilleure source locale + enfilement (ref #1056)"
```

---

### Task 3: bump ytsas + copie app dans debian/

**Files:**
- Modify: `packages/secubox-ytsas/debian/changelog`
- Vérifier: l'app est copiée par `debian/rules` (les fichiers `lxc/app/*.py` doivent être embarqués — `ytid.py` inclus).

- [ ] **Step 1: Ajouter l'entrée changelog (0.2.0, fonctionnalité)**

```
secubox-ytsas (0.2.0-1~bookworm1) bookworm; urgency=medium

  * feat #1056 : endpoint GET /resolve — rend la meilleure source locale
    (mirror PeerTube / cache / pending) pour une URL YouTube et enfile le
    rapatriement (add+conserve). Brique du média intégré souverain du BBS.
  * ytid.py : extraction canonique du video_id (watch/youtu.be/shorts).

 -- Gerald KERMA <devel@cybermind.fr>  Wed, 19 Aug 2026 12:00:00 +0200
```

- [ ] **Step 2: Vérifier l'embarquement de l'app**

Run: `grep -nE "lxc/app|cp .*app" packages/secubox-ytsas/debian/rules`
Expected: une règle copie `lxc/app/` (donc `ytid.py` part avec). Si un glob liste les fichiers un par un, ajouter `ytid.py`.

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-ytsas/debian/changelog
git commit -m "chore(ytsas): 0.2.0 — /resolve + ytid (ref #1056)"
```

---

## Package B — secubox-bbs

### Task 4: client ytsas (Go)

**Files:**
- Create: `packages/secubox-bbs/internal/connectors/ytsas.go`
- Test: `packages/secubox-bbs/internal/connectors/ytsas_test.go`

**Interfaces:**
- Produces: type `ClientYtsas struct { Base string; HTTP *http.Client }` ; méthode `(c *ClientYtsas) Resoudre(url string) (Resolution, error)` ; type `Resolution struct { VideoID, Etat, PeertubeURL, StreamURL, Titre string }` (états `"mirror"|"cache"|"pending"|"unsupported"`).

- [ ] **Step 1: Write the failing test** (httptest simule ytsas)

```go
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
package connectors

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientYtsasResoudreMirror(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ytsas/resolve" {
			t.Fatalf("chemin %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"video_id":"dQw4w9WgXcQ","state":"mirror","peertube_url":"https://peertube.gk2/w/xy"}`))
	}))
	defer srv.Close()

	c := &ClientYtsas{Base: srv.URL, HTTP: &http.Client{Timeout: time.Second}}
	res, err := c.Resoudre("https://youtu.be/dQw4w9WgXcQ")
	if err != nil {
		t.Fatal(err)
	}
	if res.Etat != "mirror" || res.PeertubeURL != "https://peertube.gk2/w/xy" || res.VideoID != "dQw4w9WgXcQ" {
		t.Fatalf("résolution inattendue : %+v", res)
	}
}

func TestClientYtsasHorsService(t *testing.T) {
	c := &ClientYtsas{Base: "http://127.0.0.1:1", HTTP: &http.Client{Timeout: 200 * time.Millisecond}}
	if _, err := c.Resoudre("https://youtu.be/dQw4w9WgXcQ"); err == nil {
		t.Fatal("une panne ytsas doit remonter une erreur (le connecteur retombera sur WAN)")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-bbs && go test ./internal/connectors/ -run TestClientYtsas -v`
Expected: FAIL — `undefined: ClientYtsas`

- [ ] **Step 3: Write minimal implementation**

```go
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package connectors

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// Resolution : réponse de ytsas GET /resolve.
type Resolution struct {
	VideoID     string `json:"video_id"`
	Etat        string `json:"state"`
	PeertubeURL string `json:"peertube_url"`
	StreamURL   string `json:"stream_url"`
	Titre       string `json:"title"`
}

// ClientYtsas interroge la SAS ytsas. Base = origine (http://10.100.0.180:8091).
type ClientYtsas struct {
	Base string
	HTTP *http.Client
}

// Resoudre demande à ytsas la meilleure source locale pour une URL YouTube.
func (c *ClientYtsas) Resoudre(media string) (Resolution, error) {
	adr := c.Base + "/api/v1/ytsas/resolve?url=" + url.QueryEscape(media)
	resp, err := c.HTTP.Get(adr)
	if err != nil {
		return Resolution{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Resolution{}, fmt.Errorf("ytsas /resolve : code %d", resp.StatusCode)
	}
	var r Resolution
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return Resolution{}, err
	}
	return r, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-bbs && go test ./internal/connectors/ -run TestClientYtsas -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-bbs/internal/connectors/ytsas.go packages/secubox-bbs/internal/connectors/ytsas_test.go
git commit -m "feat(bbs): client ytsas /resolve (ref #1056)"
```

---

### Task 5: connecteur `youtube`

**Files:**
- Create: `packages/secubox-bbs/internal/connectors/youtube.go`
- Test: `packages/secubox-bbs/internal/connectors/youtube_test.go`

**Interfaces:**
- Consumes: `ClientYtsas.Resoudre` (Task 4) ; `gateway.Base`, `gateway.Contenu`, `gateway.Replique`, constantes `gateway.Genre*`, `gateway.ModeMiroir`, `gateway.Propriete*`.
- Produces: `NouveauYouTube(cl *ClientYtsas, noeud string) *YouTube` satisfaisant `gateway.Connecteur`. `Resoudre` mappe l'état → `Contenu` : `Metadonnees["etat"]`, `Metadonnees["video_id"]`, `Metadonnees["source"]="youtube"` (tags provenance) ; `SourceURL` = URL d'origine (failover) ; si mirror, un `gateway.Replique{Cible:"peertube", CibleURL:..., Mode:ModeMiroir}`.

- [ ] **Step 1: Write the failing test**

```go
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
package connectors

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/gateway"
)

func clientVers(t *testing.T, corps string) *ClientYtsas {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(corps))
	}))
	t.Cleanup(srv.Close)
	return &ClientYtsas{Base: srv.URL, HTTP: &http.Client{Timeout: time.Second}}
}

func TestYouTubeReconnaitEtGardeLOriginal(t *testing.T) {
	yt := NouveauYouTube(clientVers(t, `{"video_id":"dQw4w9WgXcQ","state":"pending"}`), "gk2")
	c, err := yt.Resoudre("https://www.youtube.com/watch?v=dQw4w9WgXcQ")
	if err != nil {
		t.Fatal(err)
	}
	if c.Genre != gateway.GenreVideo {
		t.Fatalf("genre %q", c.Genre)
	}
	if c.SourceURL != "https://www.youtube.com/watch?v=dQw4w9WgXcQ" {
		t.Fatalf("l'original (failover) doit être conservé : %q", c.SourceURL)
	}
	if c.Metadonnees["video_id"] != "dQw4w9WgXcQ" || c.Metadonnees["source"] != "youtube" || c.Metadonnees["etat"] != "pending" {
		t.Fatalf("tags de provenance manquants : %+v", c.Metadonnees)
	}
}

func TestYouTubeMiroirPoseUneReplique(t *testing.T) {
	yt := NouveauYouTube(clientVers(t, `{"video_id":"dQw4w9WgXcQ","state":"mirror","peertube_url":"https://peertube.gk2/w/xy"}`), "gk2")
	c, _ := yt.Resoudre("https://youtu.be/dQw4w9WgXcQ")
	if len(c.Repliques) != 1 || c.Repliques[0].Cible != "peertube" || c.Repliques[0].CibleURL != "https://peertube.gk2/w/xy" {
		t.Fatalf("réplique miroir attendue : %+v", c.Repliques)
	}
	if c.Metadonnees["etat"] != "mirror" {
		t.Fatalf("état %q", c.Metadonnees["etat"])
	}
}

func TestYouTubeYtsasHSRetombeSurWAN(t *testing.T) {
	yt := NouveauYouTube(&ClientYtsas{Base: "http://127.0.0.1:1", HTTP: &http.Client{Timeout: 150 * time.Millisecond}}, "gk2")
	c, err := yt.Resoudre("https://youtu.be/dQw4w9WgXcQ")
	if err != nil {
		t.Fatalf("un ytsas HS ne doit PAS faire échouer le rendu : %v", err)
	}
	if c.Metadonnees["etat"] != "pending" {
		t.Fatalf("ytsas HS → WAN (pending) attendu, eu %q", c.Metadonnees["etat"])
	}
	if c.SourceURL == "" {
		t.Fatal("l'original doit rester")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-bbs && go test ./internal/connectors/ -run TestYouTube -v`
Expected: FAIL — `undefined: NouveauYouTube`

- [ ] **Step 3: Write minimal implementation**

```go
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package connectors

import (
	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/gateway"
)

// YouTube : connecteur souverain. Il ne télécharge rien lui-même — il DEMANDE à
// ytsas la meilleure source locale et garde toujours l'original comme failover.
type YouTube struct {
	gateway.Base
	cl    *ClientYtsas
	noeud string
}

// NouveauYouTube construit le connecteur (lecture seule : pas de Sortie).
func NouveauYouTube(cl *ClientYtsas, noeud string) *YouTube {
	return &YouTube{cl: cl, noeud: noeud}
}

func (y *YouTube) Manifeste() gateway.Manifeste {
	return gateway.Manifeste{
		Nom: "youtube", Version: "1.0",
		Capacites: []string{gateway.CapResoudre, gateway.CapTirer},
		AuthKind:  gateway.AuthCookies, // #1048/#1051 : ytsas détient le coffre
		MotifsURL: []string{`(?i)youtube\.com/watch`, `(?i)youtu\.be/`, `(?i)youtube\.com/shorts/`},
	}
}

// Resoudre demande l'état à ytsas et fabrique le Contenu. AU DOUTE, WAN : si
// ytsas est injoignable, on rend quand même la vidéo en pending (embed WAN),
// jamais un échec — l'utilisateur voit sa vidéo.
func (y *YouTube) Resoudre(u string) (gateway.Contenu, error) {
	res, err := y.cl.Resoudre(u)
	etat := res.Etat
	if err != nil || etat == "" || etat == "unsupported" {
		etat = "pending" // ytsas HS ou muet → WAN direct
	}
	c := gateway.Contenu{
		Genre:        gateway.GenreVideo,
		Titre:        res.Titre,
		SourceURL:    u, // failover : jamais jeté
		Connecteur:   "youtube",
		RefNative:    res.VideoID,
		Propriete:    gateway.ProprieteTiers,
		NoeudOrigine: y.noeud,
		Metadonnees: map[string]string{
			"source":   "youtube",
			"video_id": res.VideoID,
			"etat":     etat,
		},
	}
	if etat == "mirror" && res.PeertubeURL != "" {
		c.Repliques = []gateway.Replique{{
			Cible: "peertube", CibleURL: res.PeertubeURL, Mode: gateway.ModeMiroir,
		}}
	}
	if etat == "cache" && res.StreamURL != "" {
		c.Metadonnees["stream_url"] = res.StreamURL
	}
	return c, nil
}

func (y *YouTube) RecupererMedias(gateway.Contenu) ([]gateway.Media, error) { return nil, nil }
func (y *YouTube) Tirer(int64) ([]gateway.Contenu, error)                   { return nil, nil }
func (y *YouTube) Sante() gateway.Sante                                     { return gateway.Sante{Etat: gateway.EtatSain} }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-bbs && go test ./internal/connectors/ -run TestYouTube -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-bbs/internal/connectors/youtube.go packages/secubox-bbs/internal/connectors/youtube_test.go
git commit -m "feat(bbs): connecteur youtube souverain (résolution ytsas + failover WAN + tags) (ref #1056)"
```

---

### Task 6: embed dans le CORPS d'un message (render.go) — le lecteur apparaît

**Contexte (ruling #1056) :** une URL YouTube collée dans un fil est rendue par
`internal/web/render.go` — les deux autolinkers `liens()` (liens markdown
`[t](url)`, ~ligne 280) et `adressesNues()` (URL nues `https://…`, ~ligne 334).
Aujourd'hui elles produisent un `<a>` : le lecteur ne voit qu'un lien. Cette
tâche fait émettre l'embed **youtube-nocookie** (la « première vue » approuvée
au spec) à la place du lien. `render.go` est PUR (aucun réseau) : on n'appelle
donc PAS ytsas ici — l'upgrade souverain (miroir/cache) est la Task 8.

**Files:**
- Create: `packages/secubox-bbs/internal/web/embed_youtube.go` (extracteur video_id PUR + `embedYouTubeURL` + `embedYouTube(Contenu)` pour l'upgrade souverain de la Task 8)
- Modify: `packages/secubox-bbs/internal/web/render.go` (`liens` ~280 et `adressesNues` ~334 : émettre l'embed si l'URL est YouTube)
- Test: `packages/secubox-bbs/internal/web/embed_youtube_test.go`

**Interfaces:**
- Produces: `idVideoYouTube(url string) string` (id 11 car. ou "") ; `embedYouTubeURL(url string) (html string, ok bool)` (iframe nocookie si YouTube) ; `embedYouTube(c gateway.Contenu) string` (rendu par état, consommé par la Task 8).
- Consumes (render.go) : `embedYouTubeURL` dans les deux autolinkers.

- [ ] **Step 1: Write the failing test**

```go
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
package web

import (
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/gateway"
)

func TestEmbedYouTubeURLLienNu(t *testing.T) {
	h, ok := embedYouTubeURL("https://youtu.be/kFuf9xUInzA?si=7DvT2wtSMprn4NHI")
	if !ok || !strings.Contains(h, "youtube-nocookie.com/embed/kFuf9xUInzA") {
		t.Fatalf("embed nocookie attendu : %q ok=%v", h, ok)
	}
}

func TestEmbedYouTubeURLNonYoutube(t *testing.T) {
	if _, ok := embedYouTubeURL("https://exemple.org/x"); ok {
		t.Fatal("une URL non-YouTube ne doit PAS produire d'embed")
	}
}

// LE test qui reproduit la capture utilisateur : une URL nue dans un corps.
func TestRenderCorpsEmbarqueLecteurYoutube(t *testing.T) {
	html := string(Render("Il explique ici https://youtu.be/kFuf9xUInzA les agendas"))
	if !strings.Contains(html, "youtube-nocookie.com/embed/kFuf9xUInzA") {
		t.Fatalf("le corps doit embarquer le lecteur, pas un simple lien : %s", html)
	}
	if strings.Contains(html, `href="https://youtu.be/kFuf9xUInzA"`) {
		t.Fatalf("l'URL YouTube nue ne doit pas rester un <a> : %s", html)
	}
}

// L'upgrade souverain (Task 8) s'appuie sur embedYouTube(Contenu).
func TestEmbedContenuMirrorRendPeertube(t *testing.T) {
	c := gateway.Contenu{Genre: gateway.GenreVideo, Connecteur: "youtube",
		Metadonnees: map[string]string{"video_id": "dQw4w9WgXcQ", "etat": "mirror"},
		Repliques:   []gateway.Replique{{Cible: "peertube", CibleURL: "https://peertube.gk2/w/xy", Mode: gateway.ModeMiroir}}}
	if h := embedYouTube(c); !strings.Contains(h, "<iframe") || !strings.Contains(h, "peertube.gk2/w/xy") {
		t.Fatalf("miroir → iframe peertube attendu : %s", h)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-bbs && go test ./internal/web/ -run 'TestEmbed|TestRenderCorpsEmbarque' -v`
Expected: FAIL — `undefined: embedYouTubeURL` / `undefined: embedYouTube`

- [ ] **Step 3: Write minimal implementation** (`internal/web/embed_youtube.go`)

```go
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"html"
	"net/url"
	"regexp"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/gateway"
)

var reIDYouTube = regexp.MustCompile(`^[A-Za-z0-9_-]{11}$`)

// idVideoYouTube extrait l'identifiant canonique (11 car.) d'une URL YouTube,
// ou "" si ce n'en est pas une. Miroir Go de ytid.py côté ytsas : le join du
// tuyau souverain se fait par CET identifiant, jamais par le titre.
func idVideoYouTube(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return ""
	}
	h := strings.TrimPrefix(strings.ToLower(p.Hostname()), "www.")
	switch h {
	case "youtube.com", "m.youtube.com":
		if p.Path == "/watch" {
			if v := p.Query().Get("v"); reIDYouTube.MatchString(v) {
				return v
			}
			return ""
		}
		for _, pf := range []string{"/shorts/", "/embed/", "/v/"} {
			if strings.HasPrefix(p.Path, pf) {
				v := strings.SplitN(strings.TrimPrefix(p.Path, pf), "/", 2)[0]
				if reIDYouTube.MatchString(v) {
					return v
				}
				return ""
			}
		}
		return ""
	case "youtu.be":
		v := strings.SplitN(strings.TrimPrefix(p.Path, "/"), "/", 2)[0]
		if reIDYouTube.MatchString(v) {
			return v
		}
	}
	return ""
}

// embedYouTubeURL rend l'embed « première vue » (youtube-nocookie) d'une URL
// YouTube. PUR : appelé depuis le rendu du corps, sans réseau. referrerpolicy
// no-referrer : le fil interne n'a pas à être annoncé au tiers.
func embedYouTubeURL(u string) (string, bool) {
	id := idVideoYouTube(u)
	if id == "" {
		return "", false
	}
	return `<iframe class="sbx-embed sbx-embed-yt" src="https://www.youtube-nocookie.com/embed/` +
		html.EscapeString(id) + `" allowfullscreen loading="lazy" referrerpolicy="no-referrer"></iframe>`, true
}

// embedYouTube rend l'embed selon l'état du tuyau souverain — consommé par
// l'upgrade côté serveur (Task 8) quand ytsas a répondu. mirror → PeerTube
// (souverain) ; cache → <video> locale (souverain) ; sinon youtube-nocookie.
func embedYouTube(c gateway.Contenu) string {
	id := html.EscapeString(c.Metadonnees["video_id"])
	switch c.Metadonnees["etat"] {
	case "mirror":
		for _, r := range c.Repliques {
			if r.Cible == "peertube" && r.CibleURL != "" {
				return `<iframe class="sbx-embed" src="` + html.EscapeString(r.CibleURL) +
					`" allowfullscreen loading="lazy"></iframe>`
			}
		}
		fallthrough // miroir annoncé mais URL absente : on retombe sur WAN
	case "cache":
		if s := c.Metadonnees["stream_url"]; s != "" {
			return `<video class="sbx-embed" controls preload="metadata" src="` + html.EscapeString(s) + `"></video>`
		}
		fallthrough
	default: // pending / inconnu → WAN (première vue)
		return `<iframe class="sbx-embed" src="https://www.youtube-nocookie.com/embed/` + id +
			`" allowfullscreen loading="lazy" referrerpolicy="no-referrer"></iframe>`
	}
}
```

Puis MODIFIER `render.go` — dans `liens()`, remplacer le bloc `if lienSur(url) {`
qui écrit le `<a>` par :

```go
		if lienSur(url) {
			if emb, ok := embedYouTubeURL(url); ok {
				b.WriteString(emb)
			} else {
				// noopener/noreferrer : cf. commentaire d'origine.
				b.WriteString(`<a href="` + template.HTMLEscapeString(url) +
					`" rel="noopener noreferrer">` + texte + `</a>`)
			}
		} else {
```

et dans `adressesNues()`, remplacer `if lienSur(url) && len(url) > 10 {` :

```go
		if lienSur(url) && len(url) > 10 {
			if emb, ok := embedYouTubeURL(url); ok {
				b.WriteString(emb)
			} else {
				b.WriteString(`<a href="` + url + `" rel="noopener noreferrer">` + url + `</a>`)
			}
		} else {
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-bbs && go test ./internal/web/ -v && go build ./...`
Expected: PASS (nouveaux tests + l'existant de render_test.go inchangé), build OK.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-bbs/internal/web/embed_youtube.go packages/secubox-bbs/internal/web/embed_youtube_test.go packages/secubox-bbs/internal/web/render.go
git commit -m "feat(bbs): embed youtube dans le corps (render.go) — le lecteur apparaît (ref #1056)"
```

---

### Task 7: CSP — youtube-nocookie (toujours) + origine ytsas (media-src)

**Contexte (ruling #1056) :** le rendu du corps (Task 6) émet TOUJOURS un `<iframe
youtube-nocookie>` pour une URL YouTube. `frame-src` DOIT donc toujours autoriser
`https://www.youtube-nocookie.com`, sinon l'embed est bloqué (cadre blanc). C'est
un changement ASSUMÉ de l'invariant « frame-src fermé par défaut » : la board
intègre YouTube par conception. `frame-ancestors 'none'` reste inchangé (NOS
pages ne sont jamais encadrées). Le cadrage PeerTube/tiers reste, lui, sur
configuration explicite (`FrameOrigines`). Deux tests existants qui verrouillaient
`frame-src 'none'` sont mis à jour en conséquence.

Les vraies fonctions (confirmées dans server.go) : `func (s *Server) frameSrc()
string` (assemble frame-src : `PeerTubeOrigine` + `FrameOrigines`, sinon `'none'`)
et `func politique(style, script, connect, frame, media string) string` (assemble
toute la CSP ; le param `media` alimente `img-src` ET `media-src`). `entetes()`
appelle `politique(style, script, connect, frame, "")`.

**Files:**
- Modify: `packages/secubox-bbs/internal/web/server.go` (`Options` +`YtsasOrigine` ; `frameSrc()` ajoute youtube-nocookie ; `entetes()` passe `YtsasOrigine` en `media`)
- Modify (tests existants à réconcilier): `packages/secubox-bbs/internal/web/frame_test.go` (`TestFrameSrcFermeParDefaut`), `packages/secubox-bbs/internal/web/media_test.go` (assertion `frame-src 'none'` ~ligne 126)
- Test: `packages/secubox-bbs/internal/web/csp_test.go` (nouveau)

**Interfaces:**
- Produces: `Options.YtsasOrigine string` ; `s.frameSrc()` contient toujours `https://www.youtube-nocookie.com` ; l'en-tête CSP a `media-src` incluant `YtsasOrigine` quand configuré.

- [ ] **Step 1: Write the failing test** (`csp_test.go`)

```go
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"strings"
	"testing"
)

// La board intègre YouTube par conception : frame-src doit TOUJOURS autoriser
// l'hôte cookieless, même sans autre configuration.
func TestFrameSrcAutoriseToujoursYoutubeNocookie(t *testing.T) {
	if f := (&Server{}).frameSrc(); !strings.Contains(f, "https://www.youtube-nocookie.com") {
		t.Fatalf("frame-src doit autoriser youtube-nocookie : %s", f)
	}
}

// L'origine ytsas alimente media-src pour le <video> du cas « cache ».
func TestPolitiqueMediaSrcInclutYtsas(t *testing.T) {
	csp := politique("'self'", "'self'", "'self'", "'none'", "http://10.100.0.180:8091")
	if !strings.Contains(csp, "media-src 'self' http://10.100.0.180:8091") {
		t.Fatalf("media-src doit inclure l'origine ytsas : %s", csp)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-bbs && go test ./internal/web/ -run 'TestFrameSrcAutoriseToujours|TestPolitiqueMediaSrc' -v`
Expected: FAIL — youtube-nocookie absent de frameSrc ; `YtsasOrigine` inexistant.

- [ ] **Step 3: Write minimal implementation**

Dans `server.go` :
1. Ajouter le champ à `Options` (près de `MediaOrigines`) :
```go
	// YtsasOrigine : origine de la SAS ytsas (http://IP:8091). Alimente
	// media-src pour le <video> local d'une vidéo YouTube rapatriée (#1056).
	YtsasOrigine string
```
2. Dans `frameSrc()`, AVANT le test `if len(ok) == 0`, ajouter l'hôte cookieless
   (via le même `ajoute(...)`, donc revalidé comme les autres) :
```go
	// #1056 — la board intègre YouTube : le rendu du corps émet un iframe
	// youtube-nocookie. Toujours autorisé, sinon l'embed serait bloqué.
	ajoute("https://www.youtube-nocookie.com")
	if len(ok) == 0 {
		return "'none'"
	}
```
   (Après cet ajout, `ok` n'est jamais vide → `frame-src` vaut au minimum
   `https://www.youtube-nocookie.com`, plus jamais `'none'`.)
3. Dans `entetes()`, passer l'origine ytsas en `media` :
```go
		hd.Set("Content-Security-Policy", politique(style, script, connect, frame, s.opt.YtsasOrigine))
```
   (`politique` n'ajoute rien si `YtsasOrigine == ""`.)

- [ ] **Step 4: Réconcilier les tests existants**

Le nouvel invariant casse deux assertions « fermé par défaut » — les mettre à
jour (changement INTENTIONNEL, commenter #1056) :
- `frame_test.go` `TestFrameSrcFermeParDefaut` : remplacer l'attente `f != "'none'"`
  par la vérification que youtube-nocookie est présent et que rien d'autre
  (aucune origine tierce) ne l'est sans configuration :
```go
// #1056 : la board intègre YouTube, donc frame-src n'est plus jamais 'none' —
// il vaut au minimum l'hôte cookieless. Aucune AUTRE origine sans configuration.
func TestFrameSrcFermeParDefaut(t *testing.T) {
	f := (&Server{}).frameSrc()
	if f != "https://www.youtube-nocookie.com" {
		t.Fatalf("frame-src par défaut inattendu : %s", f)
	}
}
```
- `media_test.go` (~ligne 126) : là où il attend `frame-src 'none'`, attendre
  désormais `frame-src https://www.youtube-nocookie.com` (même config, invariant
  mis à jour). Lire le test, ajuster la chaîne attendue, garder le reste.

- [ ] **Step 5: Run all web tests**

Run: `cd packages/secubox-bbs && go test ./internal/web/ -v && go build ./...`
Expected: PASS (nouveaux + existants réconciliés), build OK. Si un AUTRE test que
les deux cités casse, l'invariant touche plus large que prévu — s'ARRÊTER et
remonter le test concerné (ne pas le réécrire à l'aveugle).

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-bbs/internal/web/server.go packages/secubox-bbs/internal/web/csp_test.go packages/secubox-bbs/internal/web/frame_test.go packages/secubox-bbs/internal/web/media_test.go
git commit -m "feat(bbs): CSP autorise youtube-nocookie (toujours) + origine ytsas en media-src (ref #1056)"
```

---

### Task 8: câblage — flag ytsas, enregistrement du connecteur, branchement fiche

**Files:**
- Modify: `packages/secubox-bbs/cmd/secubox-bbsd/main.go` (flag `--ytsas-origine`, défaut `http://10.100.0.180:8091` ; construit `ClientYtsas` + `NouveauYouTube` ; passe l'origine à `Options.YtsasOrigine`)
- Modify: `packages/secubox-bbs/internal/web/server.go` + `media_fiche.go` (le `Server` porte `*connectors.YouTube` ; `servirMediaFiche` route une URL youtube vers `embedYouTube(youtube.Resoudre(u))`)

- [ ] **Step 1: Write the failing test** (le connecteur est enregistrable dans un Registre)

```go
// dans internal/connectors/youtube_test.go
func TestYouTubeSEnregistreDansLeRegistre(t *testing.T) {
	yt := NouveauYouTube(&ClientYtsas{Base: "http://x", HTTP: http.DefaultClient}, "gk2")
	r := gateway.NouveauRegistre()
	if err := r.Enregistrer(yt); err != nil {
		t.Fatalf("le connecteur youtube doit satisfaire gateway.Connecteur : %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails / passes**

Run: `cd packages/secubox-bbs && go test ./internal/connectors/ -run TestYouTubeSEnregistre -v`
Expected: PASS si Task 5 est correct (Manifeste valide). Sinon corriger le Manifeste. Ce test verrouille la conformité d'interface.

- [ ] **Step 3: Câbler (main.go + server.go + media_fiche.go)**

- `main.go` : `ytsasOrig := flag.String("ytsas-origine", "http://10.100.0.180:8091", "origine de la SAS ytsas")` ; construire `cl := &connectors.ClientYtsas{Base: *ytsasOrig, HTTP: &http.Client{Timeout: 3*time.Second}}` ; `yt := connectors.NouveauYouTube(cl, noeud)` ; passer `yt` au `Server` et `YtsasOrigine: *ytsasOrig` dans `Options`.
- `media_fiche.go` : dans `servirMediaFiche`, si l'URL matche le manifeste youtube, `c, _ := s.youtube.Resoudre(u); fmt.Fprint(w, embedYouTube(c))` (chemin déjà admis par `origineAdmise` OU nouveau court-circuit youtube avant le test d'origine — youtube n'est PAS dans MediaOrigines, donc ajouter le court-circuit explicite AVANT `origineAdmise`).

**Portée (ruling #1056) :** ce câblage donne au connecteur un appelant réel — le
point de résolution `/media-fiche` rend l'embed SOUVERAIN (mirror/cache/pending)
pour une URL YouTube. Le rendu du CORPS (Task 6) reste sur la ligne de base
youtube-nocookie ; faire consulter ytsas au renderer pur (upgrade mirror/cache
dans le corps, avec cache) est un SUIVI distinct — l'infra ytsas (Tasks 1-5) et
`embedYouTube(Contenu)` sont déjà prêts pour lui.

- [ ] **Step 4: Build + tout le paquet**

Run: `cd packages/secubox-bbs && go build ./... && go test ./...`
Expected: build OK, tous les tests PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-bbs/cmd/secubox-bbsd/main.go packages/secubox-bbs/internal/web/server.go packages/secubox-bbs/internal/web/media_fiche.go packages/secubox-bbs/internal/connectors/youtube_test.go
git commit -m "feat(bbs): câble le connecteur youtube (flag ytsas + résolution /media-fiche) (ref #1056)"
```

---

### Task 9: bump BBS + changelog + build paquet

**Files:**
- Modify: `packages/secubox-bbs/debian/changelog`

- [ ] **Step 1: Entrée changelog (0.26.0, fonctionnalité)**

```
secubox-bbs (0.26.0-1~bookworm1) bookworm; urgency=medium

  * feat #1056 : média intégré souverain. Connecteur youtube qui demande à
    ytsas (GET /resolve) la meilleure source locale et rend en conséquence :
    miroir PeerTube (souverain), cache ytsas <video> (souverain), sinon
    youtube-nocookie à la 1re vue (WAN). L'URL d'origine reste failover + tag
    de provenance ; le join se fait par video_id. CSP étendue (frame-src
    youtube-nocookie, media-src origine ytsas). Flag --ytsas-origine.
```

- [ ] **Step 2: Build arch (Go, arm64)**

Run: `cd packages/secubox-bbs && dpkg-buildpackage -us -uc -b -a arm64 --host-arch arm64` (ou build local `go build ./...` si buildpackage indispo dans l'agent).
Expected: `.deb` produit, ou build Go vert.

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-bbs/debian/changelog
git commit -m "chore(bbs): 0.26.0 — média intégré souverain #1056"
```

---

## Self-review (couverture spec)

- §2 tuyau à rebond → Task 2 (ytsas état) + Task 5 (mapping) + Task 6 (rendu). ✓
- §3.1 /resolve non bloquant → Task 2. ✓
- §3.2 connecteur + failover + tags → Task 5. ✓
- §3.3 CSP → Task 7. ✓
- §4 flux → couvert par 2/5/6 + câblage Task 8. ✓
- §5 erreurs (ytsas HS → WAN) → Task 5 (test dédié). ✓
- §6 tests → chaque task est TDD. ✓
- §8 réutilise conserve existant → Task 2 (enfile conserve). ✓
- Points à confirmer À L'EXÉCUTION (notés dans les tasks) : préfixe `API` exact de ytsas ; nom réel de l'assembleur CSP dans `server.go` ; forme exacte du branchement dans `servirMediaFiche`. Ce sont des lectures ciblées, pas des inconnues de conception.
