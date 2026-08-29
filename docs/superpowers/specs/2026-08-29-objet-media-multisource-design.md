# Objet média multi-sources adaptatif — conception (#1227, #1224, étend #1056)

Date : 2026-08-29 · Statut : conception · Portée : `secubox-bbs` + `secubox-billets` + `secubox-webos`

Étend le *tuyau à rebond* de [#1056](2026-08-19-bbs-media-embed-souverain-design.md).
Le #1056 résout **une** URL vers sa meilleure source locale (mirror → cache → WAN,
original en failover, join par `video_id`). Ce document généralise en **objet
média multi-sources** partagé BBS + billets, branché sur le viewer/barre du Hall
et le Broadcaster.

## 1. Le constat

- Le **modèle multi-sources existe déjà** : `gateway.Contenu` porte `SourceURL`
  (origine, failover) **et `Repliques []Replique{Cible, CibleURL}`** (miroir
  PeerTube, republication, archive). MetaNews porte la même forme au niveau sujet
  (`/topics/{id}/sources`).
- Le **tuyau `/resolve` est vivant** (`/api/v1/ytsas/resolve` → `{video_id, state,
  peertube_url, stream_url, title}`) et le rendu **re-résout à chaque vue** : l'objet
  escalade seul (pending → cache → mirror), sans réécrire le message.
- **Ce qui manque** : (a) les liens **simples/courts** collés dans un corps de
  message passent par `embedYouTubeURL` (render.go) qui rend un **youtube-nocookie
  « première vue » SANS passer par le tuyau** — pas d'escalade souveraine ; (b)
  l'objet n'expose pas son **jeu de sources** ; (c) pas d'action `voir`/`diffuser` ;
  (d) billets a un embed oembed one-shot, pas l'objet média.

## 2. L'objet média (contrat de rendu)

Un `<figure class="sbx-mediaobj" data-yt="<id>" data-etat="<state>">` :

```
┌───────────────────────────────┐
│  [ lecteur adaptatif ]        │   mirror→iframe PeerTube | cache→<video ytsas>
│                               │   | WAN→iframe youtube-nocookie (1re vue)
├───────────────────────────────┤
│ 🛰️ relayé · N sources         │  barre d'objet (figcaption)
│ ▢ voir · ⤓ souverain · 📡 diff │
└───────────────────────────────┘
```

**Jeu de sources** = origine (`SourceURL`) + répliques (`Repliques[].CibleURL`) +
les locales dérivées du tuyau (peertube_url, stream_url). `N sources` = compte
distinct ; un survol/expansion listera les provenances (itération suivante). Le
join reste **par `video_id`**, jamais par titre.

**Barre d'actions** (4) :
- `🛰️ relayé par la box` — info (pisteurs coupés, relayé).
- `▢ voir` — `data-voir` + `href=<watch>` → le client poste `sbx:'voir'` au Hall :
  le viewer joue **souverain** (il re-résout via ytsas), instance unique.
- `⤓ souverain` — `href=<ytsas/?src=watch>` → `sbx:'ouvre-hote'` (déjà) : ouvre
  ytsas embarqué **et déclenche** add+conserve (mirror à terme). L'objet, re-résolu
  aux vues suivantes, montrera de lui-même la source montée.
- `📡 diffuser` (#1224) — `data-diff` → `sbx:'diffuser'` au Hall → POST
  `/api/v1/webos/public/broadcast {url,titre}` + pastille direct. Le média vu
  devient un flux diffusé au parc.

## 3. Enhancement des liens simples/courts

`render.go` (corps de message) : un lien YouTube/short reste rendu **instantanément**
(première vue nocookie — pas de réseau sur le chemin de rendu), MAIS désormais
**enveloppé dans l'objet média** — il gagne donc `voir`/`souverain`/`diffuser`.
La souveraineté s'obtient par `⤓ souverain` (déclenche le tuyau) puis re-résolution
aux vues suivantes ; pas de blocage réseau au rendu. Les liens déjà **résolus**
(connecteur → `Contenu`, `media_fiche`) passent par `embedYouTube(c)` qui est lui
aussi enveloppé dans l'objet, avec le jeu de sources de `c`.

`ytid` reconnaît déjà `youtu.be`, `/shorts/`, `watch?v=` : les courts sont donc
déjà normalisés vers le `video_id` — l'enhancement est le **wrapper**, pas la
reconnaissance.

## 4. Parité billets

`secubox-billets` sert un embed oembed (embed_html + snapshot). On enveloppe cet
embed dans **le même markup `sbx-mediaobj`** (côté `billets.js`, où l'embed est
déjà monté au clic), avec la même barre 4 actions, pour les fournisseurs vidéo
(youtube/peertube). Un billet YouTube gagne alors `voir`/`souverain`/`diffuser`
identiques au BBS. CSS partagé de forme (chaque service garde sa peau).

## 5. Câblage Hall (`secubox-webos`)

- `sbx:'voir'` — **déjà géré** (ouvreViewer). Rien à ajouter.
- `sbx:'diffuser'` — **nouveau** handler : reprend la logique du bouton 📡 du
  viewer (POST broadcast + `broadcast-on`). Source-checké comme les autres
  (cadre posé par nous / relayé par cumul).
- `sbx:'ouvre-hote'` — déjà (souverain → ytsas embarqué).

## 6. Hors périmètre (YAGNI, itérations suivantes)

- Annonce `sbx:'media'` (suivi barre) d'un objet inline : l'iframe tierce ne donne
  pas son état de lecture ; on s'en tient à `voir` (promotion viewer) pour l'instant.
- Liste dépliable des N provenances au survol (l'objet montre le compte d'abord).
- Réécriture du message à la montée du miroir : inutile — le rendu re-résout.
- MetaNews topics → objet média unifié : même forme, ticket distinct.

## 7. Tests

- BBS (go) : `objetMedia` rend les 4 actions + `data-voir/data-diff` + compte de
  sources ; `embedYouTube(c)` et `embedYouTubeURL(u)` enveloppent tous deux ;
  `render.go` corps → objet. coquille : `data-voir`→`sbx:voir`, `data-diff`→`sbx:diffuser`,
  non captés par le routeur surf générique.
- webos : handler `sbx:'diffuser'` poste le broadcast (source-check).
- billets : `billets.js` enveloppe l'embed vidéo dans `sbx-mediaobj` + actions.
