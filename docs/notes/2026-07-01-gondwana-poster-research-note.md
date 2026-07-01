# 🪶 Research-Note Poster — *Gondwana Trust Substrate*
### Sketch-design architectural poster · vulgarized · last-day evolutions + roadmap
*2026-07-01 · CyberMind / SecuBox-Deb*

This note ships two things:
1. **A ready-to-paste image-generation prompt** (for GPT-Image / Midjourney / SDXL) that renders the poster.
2. **An ASCII layout mock** so the composition is concrete, plus the vulgarized copy the poster carries.

---

## 1 · The image-generation prompt (paste this)

> **A hand-drawn architectural research-note poster, "sketchnote" / engineering-lab-notebook style** — like a brilliant hacker's whiteboard photographed at 2 a.m. Ink-and-marker on aged parchment, cosmos-black background (#0a0a0f) with a subtle hexagonal grid, hand-lettered headings in a Cinzel-esque serif, body notes in a monospace "JetBrains Mono" hand, arrows drawn freehand.
>
> **Palette:** gold-hermetic (#c9a84c) for titles + borders, matrix-green (#00ff41) for "it works / live", cyber-cyan (#00d4ff) for data flows, cinnabar-red (#e63946) for "guarded / danger", void-purple (#6e40c9) for future/roadmap. Faint alchemical/hermetic marginalia (small circuit-sigils, a mirror glyph 🪞, tiny onion for Tor).
>
> **Title band (top):** big gold hand-lettering — **"GONDWANA · A VILLAGE OF BOXES THAT TRUST BY MATH, NOT BY FAITH"**. Subtitle in small caps: *"self-certifying mesh · federated services · lend-a-service macros"*.
>
> **Three stacked ‘strata’ drawn as geological layers of a mirror (the sketch's spine):**
> - **Layer 1 — THE HANDSHAKE (green):** two little box-characters shaking hands; above them a speech bubble *"my name = the hash of my key"*; a rejected forger box crossed out in red with *"can't fake a name you can't compute"*.
> - **Layer 2 — THE CATALOG (cyan):** a hand-drawn shop-shelf / market-stall labeled *"Service Registry"*; shelves hold little cards ("WAF mirror", "Suricata", "Tor exit"); an arrow *"Auto register all"* pulling neighbor stalls' cards onto your shelf.
> - **Layer 3 — LEND-A-SERVICE MACROS (gold+onion):** a box lending a glowing **onion (Tor exit)** across a rope-bridge (the mesh) to a neighbor box, who plugs it in and their traffic pops out somewhere far away. Little padlock-robot (AppArmor) guarding the rope.
>
> **A freehand ‘proof strip’ across the middle (green, like a lab result taped on):** a comic 4-panel: (1) gk2 pins a "Tor exit for rent" flyer, (2) flyer flies to c3box over a dotted mesh line, (3) c3box taps it → a guard checks a signed ticket → opens a tiny gate, (4) c3box's web traffic exits as a masked Tor node — caption in green marker: **`{"IsTor": true}` — PROVEN LIVE**.
>
> **Right margin — "THE BOUNCER" side-sketch (red):** a stern padlock-bouncer with a checklist: *"√ real name (hash) · √ signed ticket · √ from the mesh only · √ one door, one guest · everything else: DENIED"*. Small note: *"the review robots caught ~10 booby-traps before the doors opened"*.
>
> **Bottom third — "HORIZON / ROADMAP" as a dotted mountain trail into a purple sunrise:** milestone flags along the trail — *"more lendable services: VPN-relay · DNS · mirror"*, *"zero-knowledge secret handshake (GK·HAM)"*, *"ask-permission mode (pending)"*, *"two-way bridges + native Tor everywhere"*. A tiny hiker box walking toward them.
>
> **Overall vibe:** warm, playful, hand-crafted, a little hermetic/alchemical, highly legible, poster-ratio (2:3 portrait), lots of arrows and margin doodles, feels like a research lab's celebratory wall poster. No photorealism — pure ink-sketch + marker.

---

## 2 · ASCII layout mock (the composition)

```
╔══════════════════════════════════════════════════════════════════╗
║  🪞  G O N D W A N A   —   boxes that trust by MATH, not by FAITH ║   ← gold title
║      self-certifying mesh · federated services · lend-a-service   ║
╠══════════════════════════════════════════════════════════════════╣
║ ▓ LAYER 1 · THE HANDSHAKE            (green = works)              ║
║   [box]🤝[box]  "my name = hash(my key)"                          ║
║   [forger]✗     "can't fake a name you must compute"             ║
║------------------------------------------------------------------║
║ ▓ LAYER 2 · THE CATALOG             (cyan = data flows)           ║
║   ┌shelf: Service Registry┐   ◀── "Auto register all"            ║
║   │ [WAF][Suricata][Tor 🧅]│   pulls neighbours' cards to you    ║
║------------------------------------------------------------------║
║ ▓ LAYER 3 · LEND-A-SERVICE MACROS   (gold + 🧅)                   ║
║   gk2 [🧅]══rope-bridge (mesh)══▶ [box] c3box  🔒(AppArmor guard) ║
║==================================================================║
║ ✅ PROOF STRIP (taped lab result):                               ║
║   gk2 posts "Tor exit for rent" → flies to c3box → guard checks  ║
║   signed ticket → opens gate → c3box exits as Tor  {IsTor:true}  ║
╠══════════════════════════════════╦═══════════════════════════════╣
║ ⛰  HORIZON / ROADMAP  (purple)    ║  🔒 THE BOUNCER (red)         ║
║  ·→ more services: VPN·DNS·mirror ║   √ real name (hash)          ║
║  ·→ zero-knowledge handshake HAM  ║   √ signed ticket             ║
║  ·→ ask-permission (pending) mode ║   √ from the mesh only        ║
║  ·→ two-way bridges + Tor native  ║   √ one door / one guest      ║
║  🥾 …hiker box walking the trail  ║   ✗ everything else: DENIED   ║
╚══════════════════════════════════╩═══════════════════════════════╝
```

---

## 3 · The vulgarized story the poster tells

**The one-line pitch.** *A cluster of little security boxes (SecuBoxes) that don't need a boss or a
central authority to trust each other — their name literally IS a fingerprint of their key, so nobody
can impersonate anyone. On top of that trust, boxes publish a menu of services and can even lend each
other real capabilities — like one box lending its Tor exit so another box's traffic comes out
anonymized, far away.*

**What changed in the last day (three layers, all live on gk2 + c3box):**

| Layer | Plain-language | Under the hood |
|------|----------------|----------------|
| 🤝 **Handshake** | "My name is the math of my key — you can check it, you can't fake it." | did:plc self-cert; `ingest_offer` checks `did == hash(pubkey)` before trusting anything |
| 🛒 **Catalog** | "See every box's menu on one shelf; one click subscribes you." | p2p Service Registry = live view of the federated annuaire catalog + "Auto register all" |
| 🧅 **Lend-a-service** | "Rent my Tor exit / my relay — the guard only opens for a signed ticket." | `secubox-macro` (macroctl + tor-exit plugin, AppArmor-confined, nft-gated grant) |

**The headline proof.** gk2 offered its Tor exit as a service → it federated to c3box → c3box subscribed,
activated, and pulled a *signed* grant over the mesh → gk2's firewall opened just for c3box's mesh IP →
**c3box's traffic now exits through gk2's Tor node** (`{"IsTor":true}`). End-to-end, across two real
machines, with a hardened privilege chain (unprivileged app → tight sudo → root dispatcher → confined
plugin → firewall). The adversarial review loop caught **~10 critical booby-traps** before any of it shipped.

**The bouncer (why it's safe).** Every request is checked at the right door: a real (hash-derived) name,
a signature that only the key-owner could make, coming *only* from the mesh, opening exactly one port for
exactly one guest — and anything unexpected is denied by default (CSPN posture).

**Where the trail leads (roadmap).**
- 🧩 **More lendable services** — the same framework, new plugins: `wg-relay` (VPN), `dns-resolver`, `http-mirror`.
- 🕵️ **Zero-knowledge handshake** — swap the current stubs for the real GK·HAM Hamiltonian NIZK, so boxes prove things about themselves *without revealing secrets*.
- 🙋 **Ask-permission mode** — today lending is auto-approved; next, a provider can hold a request as *pending* and approve it, which needs cross-box approval federation.
- 🌉 **Two-way bridges + Tor everywhere** — finish the reverse mesh path and put a native Tor on every box so any box can be a full exit provider out of the box.

---

*Notebook margin, small hand: "the mirror shows the mesh; the mesh shows the mirror. — 🪞"*
