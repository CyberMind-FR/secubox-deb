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

### Task 6: rendu de l'embed (fiche média)

**Files:**
- Modify: `packages/secubox-bbs/internal/web/media_fiche.go` (ajouter un cas youtube à côté du cas `peertube` existant, ligne ~48)
- Test: `packages/secubox-bbs/internal/web/media_fiche_youtube_test.go`

**Interfaces:**
- Consumes: `connectors.YouTube.Resoudre` via un champ `Server` (ex. `s.youtube *connectors.YouTube`) ; `gateway.Contenu`.
- Produces: un fragment d'embed HTML selon l'état — `mirror` → `<iframe src=<peertube>>`, `cache` → `<video src=<ytsas stream>>`, `pending` → `<iframe src="https://www.youtube-nocookie.com/embed/<id>">`.

Note d'exécution : lire `media_fiche.go` (le type `Fiche` + `servirMediaFiche` + le cas `peertube`) pour raccorder ce rendu au même chemin ; réutiliser `vignetteRelayee` pour le poster. Le test cible la fonction pure qui, d'un `gateway.Contenu`, rend le fragment.

- [ ] **Step 1: Write the failing test**

```go
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
package web

import (
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/gateway"
)

func contenuYT(etat, id, ptURL, stream string) gateway.Contenu {
	c := gateway.Contenu{Genre: gateway.GenreVideo, Connecteur: "youtube",
		Metadonnees: map[string]string{"source": "youtube", "video_id": id, "etat": etat}}
	if stream != "" {
		c.Metadonnees["stream_url"] = stream
	}
	if ptURL != "" {
		c.Repliques = []gateway.Replique{{Cible: "peertube", CibleURL: ptURL, Mode: gateway.ModeMiroir}}
	}
	return c
}

func TestEmbedMirrorRendPeertube(t *testing.T) {
	h := embedYouTube(contenuYT("mirror", "dQw4w9WgXcQ", "https://peertube.gk2/w/xy", ""))
	if !strings.Contains(h, "<iframe") || !strings.Contains(h, "peertube.gk2/w/xy") {
		t.Fatalf("miroir → iframe peertube attendu : %s", h)
	}
}

func TestEmbedCacheRendVideoLocale(t *testing.T) {
	h := embedYouTube(contenuYT("cache", "dQw4w9WgXcQ", "", "http://10.100.0.180:8091/api/v1/ytsas/stream/dQw4w9WgXcQ"))
	if !strings.Contains(h, "<video") || !strings.Contains(h, "/ytsas/stream/dQw4w9WgXcQ") {
		t.Fatalf("cache → <video> locale attendu : %s", h)
	}
}

func TestEmbedPendingRendNocookie(t *testing.T) {
	h := embedYouTube(contenuYT("pending", "dQw4w9WgXcQ", "", ""))
	if !strings.Contains(h, "youtube-nocookie.com/embed/dQw4w9WgXcQ") {
		t.Fatalf("pending → iframe youtube-nocookie attendu : %s", h)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-bbs && go test ./internal/web/ -run TestEmbed -v`
Expected: FAIL — `undefined: embedYouTube`

- [ ] **Step 3: Write minimal implementation** (nouveau fichier `internal/web/embed_youtube.go`)

```go
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"html"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/gateway"
)

// embedYouTube rend le fragment d'embed d'une vidéo YouTube selon l'état du
// tuyau souverain. mirror → PeerTube (souverain) ; cache → <video> locale
// (souverain) ; pending → youtube-nocookie (WAN, première vue seulement).
func embedYouTube(c gateway.Contenu) string {
	id := html.EscapeString(c.Metadonnees["video_id"])
	switch c.Metadonnees["etat"] {
	case "mirror":
		for _, r := range c.Repliques {
			if r.Cible == "peertube" && r.CibleURL != "" {
				u := html.EscapeString(r.CibleURL)
				return `<iframe class="sbx-embed" src="` + u + `" allowfullscreen loading="lazy"></iframe>`
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
			`" allowfullscreen loading="lazy"></iframe>`
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-bbs && go test ./internal/web/ -run TestEmbed -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-bbs/internal/web/embed_youtube.go packages/secubox-bbs/internal/web/media_fiche_youtube_test.go
git commit -m "feat(bbs): rendu embed youtube (mirror/cache/pending) (ref #1056)"
```

---

### Task 7: CSP — ouvrir youtube-nocookie + origine ytsas

**Files:**
- Modify: `packages/secubox-bbs/internal/web/server.go` (`frameSrc`, assemblage `media-src`, ~227-265)
- Test: `packages/secubox-bbs/internal/web/csp_test.go` (étendre)

**Interfaces:**
- Consumes: `Server.opt.FrameOrigines`, l'origine ytsas (nouvelle option `Options.YtsasOrigine string`).
- Produces: `frame-src` contient `https://www.youtube-nocookie.com` ; `media-src` contient l'origine ytsas.

- [ ] **Step 1: Write the failing test** (ajouter à `csp_test.go`)

```go
func TestCSPAutoriseYoutubeNocookieEtYtsas(t *testing.T) {
	s := &Server{opt: Options{
		FrameOrigines: []string{"https://peertube.gk2.secubox.in"},
		YtsasOrigine:  "http://10.100.0.180:8091",
	}}
	csp := s.entetesCSP() // nom réel de l'assembleur CSP à confirmer dans server.go
	if !strings.Contains(csp, "https://www.youtube-nocookie.com") {
		t.Fatalf("frame-src doit autoriser youtube-nocookie : %s", csp)
	}
	if !strings.Contains(csp, "http://10.100.0.180:8091") {
		t.Fatalf("media-src doit autoriser l'origine ytsas : %s", csp)
	}
}
```

Note d'exécution : confirmer dans `server.go` le nom réel de la fonction qui assemble la CSP (le grep a montré `frameSrc` + la concat `"frame-src " + frame + "; media-src " + med`). Adapter l'appel du test et injecter `youtube-nocookie` dans `frame` et `YtsasOrigine` dans `med`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-bbs && go test ./internal/web/ -run TestCSPAutorise -v`
Expected: FAIL — `youtube-nocookie` absent (et champ `YtsasOrigine` inexistant).

- [ ] **Step 3: Write minimal implementation**

Dans `server.go` : ajouter `YtsasOrigine string` à `Options` ; dans l'assembleur, ajouter `https://www.youtube-nocookie.com` à la liste `frame-src` et, si `YtsasOrigine != ""`, l'ajouter à `media-src`. (Garder `frame-src 'none'` quand aucune origine n'est configurée — ne pas ouvrir youtube-nocookie inconditionnellement si `FrameOrigines` est vide et qu'aucun média n'est attendu : l'ajouter dans la même branche que les autres origines.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-bbs && go test ./internal/web/ -run TestCSP -v`
Expected: PASS (l'existant + le nouveau)

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-bbs/internal/web/server.go packages/secubox-bbs/internal/web/csp_test.go
git commit -m "feat(bbs): CSP autorise youtube-nocookie (1re vue) + origine ytsas (video) (ref #1056)"
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

- [ ] **Step 4: Build + tout le paquet**

Run: `cd packages/secubox-bbs && go build ./... && go test ./...`
Expected: build OK, tous les tests PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-bbs/cmd/secubox-bbsd/main.go packages/secubox-bbs/internal/web/server.go packages/secubox-bbs/internal/web/media_fiche.go packages/secubox-bbs/internal/connectors/youtube_test.go
git commit -m "feat(bbs): câble le connecteur youtube (flag ytsas + fiche + CSP) (ref #1056)"
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
