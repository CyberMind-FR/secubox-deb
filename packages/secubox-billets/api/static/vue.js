/* SPDX-License-Identifier: LicenseRef-CMSD-1.0
   Vue billet (#1268) — la scène du popup théâtre, en grand :
     · l'embed reprend LA POSITION MEMORISEE par le fil (même clé bpos:<slug>) ;
     · ça joue AVEC le son — pas d'auto-muet, pas de bouton ;
     · les messages passent en SOUS-TITRES par-dessus l'image, interactifs
       (survol = le message entier au curseur, clic = la ligne dans la console) ;
     · les réactions POPPENT par-dessus l'image.
   Aucune donnée en ligne : tout est lu dans le DOM déjà rendu (CSP script-src 'self'). */
(function () {
  "use strict";
  var art = document.querySelector(".vue-billet");
  if (!art) return;
  var scene = document.getElementById("scene");
  var track = document.getElementById("track");
  var pops = document.getElementById("pops");
  var slug = art.dataset.slug || "";

  var LS = {
    get: function (k, d) { try { var v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } },
    set: function (k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} }
  };
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }

  // SON : ça joue AVEC LE SON, point. Pas d'auto-muet, pas de bouton — le volume,
  // c'est celui du lecteur. Navigateur qui refuse l'autoplay sonore = image en
  // attente d'un clic, ce qui vaut mieux qu'un muet subi.

  // ── L'EMBED : même fabrique d'URL que le fil (autoplay + reprise) ─────────
  function embedSrc(embed, muted, start) {
    start = Math.floor(start || 0); var mm = muted ? 1 : 0;
    var y = (embed.match(/(?:youtu\.be\/|[?&]v=|\/embed\/)([A-Za-z0-9_-]{11})/) || [])[1];
    if (/youtu/.test(embed) && y) return "https://www.youtube-nocookie.com/embed/" + y + "?rel=0&playsinline=1&autoplay=1&mute=" + mm + "&start=" + start;
    var p = embed.match(/(https?:\/\/[^/]+)\/(?:w|videos\/(?:watch|embed))\/([0-9A-Za-z-]+)/);
    if (p) return p[1] + "/videos/embed/" + p[2] + "?autoplay=1&muted=" + mm + "&title=0&warningTitle=0&peertubeLink=0&p2p=0&controls=1&start=" + start;
    return null;
  }

  var ifr = scene ? scene.querySelector(".frame.live iframe") : null;
  var src0 = ifr ? (ifr.getAttribute("src") || "") : "";
  var base = 0, t0 = 0, joue = false;

  function lance(muted, at) {
    if (!ifr || !src0) return;
    var u = embedSrc(src0, muted, at);
    if (!u) return;                        /* fournisseur inconnu : on n'y touche pas */
    ifr.setAttribute("allow", "autoplay; fullscreen; picture-in-picture");
    ifr.src = u;
    base = at || 0; t0 = performance.now(); joue = true;
    if (scene) scene.classList.add("playing");
  }
  function pos() { return joue ? base + (performance.now() - t0) / 1000 : base; }
  function retiens() { if (slug && joue) LS.set("bpos:" + slug, Math.max(0, Math.floor(pos()))); }

  if (ifr && src0 && embedSrc(src0, false, 0)) {
    // On REPREND là où le fil s'était arrêté, avec le son.
    lance(false, LS.get("bpos:" + slug, 0));
    setInterval(retiens, 4000);
    addEventListener("pagehide", retiens);
    addEventListener("beforeunload", retiens);
    document.addEventListener("visibilitychange", function () { if (document.hidden) retiens(); });
  }

  // ── OSD ───────────────────────────────────────────────────────────────────
  // Les DEUX bascules sont retenues (#1268) : « crt » l'était, « sous-titres »
  // repassait à « affiché » au rechargement — le guide d'utilisation promet les
  // deux, et c'est le comportement attendu d'un réglage.
  var bSubs = scene && scene.querySelector('[data-act="subs"]');
  if (bSubs) {
    var subsOff = LS.get("nosubs", false);
    if (subsOff) scene.classList.add("nosubs");
    bSubs.classList.toggle("on", !subsOff);
    bSubs.setAttribute("aria-pressed", subsOff ? "false" : "true");
    bSubs.addEventListener("click", function () {
      var off = scene.classList.toggle("nosubs"); LS.set("nosubs", off);
      this.classList.toggle("on", !off); this.setAttribute("aria-pressed", off ? "false" : "true");
    });
  }
  var bCrt = scene && scene.querySelector('[data-act="crt"]');
  if (bCrt) {
    bCrt.classList.toggle("on", !LS.get("nocrt", false));
    if (LS.get("nocrt", false)) scene.classList.add("nocrt");
    bCrt.addEventListener("click", function () {
      var off = scene.classList.toggle("nocrt"); LS.set("nocrt", off);
      this.classList.toggle("on", !off); this.setAttribute("aria-pressed", off ? "false" : "true");
    });
  }

  // ── popup au curseur : le message ENTIER (même objet que dans le fil) ─────
  var cur = document.createElement("div"); cur.className = "curpop"; document.body.appendChild(cur);
  function montre(e, who, msg, when) {
    cur.innerHTML = '<div class="who"><span class="nm">' + esc(who) + '</span><span class="tm">' + esc(when || "") + '</span></div>'
      + '<div class="msg">' + esc(msg) + '</div><div class="go">clic → la ligne dans la console</div>';
    cur.classList.add("on");
    var x = Math.min(e.clientX + 16, innerWidth - 360), y = Math.min(e.clientY + 16, innerHeight - 150);
    cur.style.left = Math.max(8, x) + "px"; cur.style.top = Math.max(8, y) + "px";
  }
  function cache() { cur.classList.remove("on"); }

  // ── SOUS-TITRES : les messages déjà rendus, en défilé par-dessus l'image ──
  function mmss(t) { t = Math.max(0, Math.floor(t)); return Math.floor(t / 60) + ":" + ("0" + (t % 60)).slice(-2); }
  var src = [].slice.call(document.querySelectorAll("#comments .cline")).map(function (n, i) {
    var m = n.querySelector(".msg");
    return {
      i: i, who: n.dataset.who || "", when: n.dataset.when || "",
      t: n.dataset.t != null && n.dataset.t !== "" ? parseInt(n.dataset.t, 10) : null,
      msg: (m ? m.textContent : "").replace(/\s+/g, " ").trim(), node: n
    };
  }).filter(function (c) { return c.msg; });

  var pousseLigne = null;                       /* défini plus bas si la piste existe */
  if (track) {
    var k = 0, MAX = 3;
    function ligne(c, mienne, attente) {
      var d = document.createElement("div"); d.className = "line" + (mienne ? " mienne" : "");
      d.innerHTML = (c.t != null ? '<span class="at">' + mmss(c.t) + '</span>' : '<span class="k">▸</span>')
        + '<span class="nm">' + esc(c.who) + '</span>'
        + '<span class="msg">' + esc(c.msg) + '</span>'
        + (attente ? '<span class="att">en attente</span>' : "")
        + '<span class="tm">' + esc(c.when || "") + '</span>';
      d.addEventListener("mouseenter", function (e) { montre(e, c.who, c.msg, c.when); });
      d.addEventListener("mousemove", function (e) { montre(e, c.who, c.msg, c.when); });
      d.addEventListener("mouseleave", cache);
      if (c.node) d.addEventListener("click", function () {
        cache();
        c.node.scrollIntoView({ behavior: "smooth", block: "center" });
        [].forEach.call(document.querySelectorAll(".cline.vu"), function (n) { n.classList.remove("vu"); });
        c.node.classList.add("vu");
      });
      track.appendChild(d);
      while (track.children.length > MAX) track.removeChild(track.firstChild);
      setTimeout(function () {
        if (!d.parentNode) return;
        d.classList.add("out");
        setTimeout(function () { if (d.parentNode) d.parentNode.removeChild(d); }, 320);
      }, mienne ? 14000 : 9000);   /* la sienne reste un peu plus longtemps à l'écran */
    }
    pousseLigne = ligne;

    // ANCRES : ils apparaissent QUAND LA VIDEO Y ARRIVE — c'est ce qui fait d'eux
    // des sous-titres et non un bandeau qui défile. La position est celle que
    // nous estimons (base + temps écoulé) : un lecteur en iframe d'un autre
    // domaine ne nous dit pas où il en est, et c'est déjà la base de la reprise.
    var ancres = src.filter(function (c) { return c.t != null; })
                    .sort(function (a, b) { return a.t - b.t; });
    var libres = src.filter(function (c) { return c.t == null; });
    var vus = {}, dernier = 0;
    if (ancres.length) setInterval(function () {
      if (document.hidden || !joue || !scene || scene.classList.contains("nosubs")) return;
      var p = pos();
      if (p < dernier - 2) vus = {};        /* on est revenu en arrière : ils repassent */
      dernier = p;
      ancres.forEach(function (c, i) {
        if (!vus[i] && p >= c.t && p < c.t + 5) { vus[i] = 1; ligne(c); }
      });
    }, 700);

    // LIBRES (messages d'avant l'ancrage, ou écrits hors lecture) : ils tournent,
    // faute d'instant à respecter. Mieux vaut les montrer que les taire.
    function pousse() {
      if (document.hidden || !libres.length || !scene || scene.classList.contains("nosubs")) return;
      ligne(libres[k % libres.length]); k++;
    }
    if (libres.length) {
      pousse();
      setTimeout(pousse, 1400);
      setInterval(pousse, 6000);
    }
  }

  // ── RÉACTIONS : elles poppent par-dessus l'image ─────────────────────────
  var reacts = [].slice.call(document.querySelectorAll(".react-btn")).map(function (b) {
    var e = b.querySelector(".emoji"), n = b.querySelector(".count");
    return { emo: e ? e.textContent.trim() : "♥", n: n ? parseInt(n.textContent, 10) || 0 : 0, btn: b };
  }).filter(function (r) { return r.n > 0; });

  function popRe(emo, n) {
    if (!pops || document.hidden) return;
    var d = document.createElement("div"); d.className = "pop";
    d.innerHTML = '<span class="emo">' + esc(emo) + '</span><span class="n">' + (n != null ? "×" + n : "+1") + '</span>';
    pops.appendChild(d);
    setTimeout(function () { if (d.parentNode) d.parentNode.removeChild(d); }, 4800);
    while (pops.children.length > 5) pops.removeChild(pops.firstChild);
  }
  if (reacts.length) {
    var j = 0;
    setTimeout(function () { popRe(reacts[0].emo, reacts[0].n); }, 2200);
    setInterval(function () { var r = reacts[j % reacts.length]; j++; popRe(r.emo, r.n); }, 7000);
  }
  // un clic sur une réaction pop tout de suite : le geste se voit à l'écran
  document.addEventListener("click", function (e) {
    var b = e.target.closest ? e.target.closest(".react-btn") : null;
    if (!b) return;
    var em = b.querySelector(".emoji");
    popRe(em ? em.textContent.trim() : "♥", null);
  }, true);

  // cliquer une puce d'instant reprend la lecture À CE MOMENT
  document.addEventListener("click", function (e) {
    var b = e.target.closest ? e.target.closest("[data-seek]") : null;
    if (!b) return;
    e.preventDefault();
    var t = parseInt(b.dataset.seek, 10);
    if (isNaN(t) || !ifr || !src0) return;
    lance(false, t);
    if (scene) scene.scrollIntoView({ behavior: "smooth", block: "start" });
  });

  // ── ECRIRE SANS RECHARGER ────────────────────────────────────────────────
  // LA VIDEO S'ARRETAIT A CHAQUE MESSAGE. Le formulaire postait en 303, la page
  // se rechargeait, l'embed repartait en autoplay SONORE — refusé sans geste —
  // et l'image restait figée jusqu'à un clic. On poste donc en arrière-plan :
  // la lecture n'est jamais interrompue, et la ligne envoyée passe aussitôt en
  // sous-titre. La barre incrustée EST le formulaire de la page — elle porte les
  // jetons (csrf, anti-spam, piège) et reste postable sans JS : rien n'est perdu
  // pour un visiteur sans script, et il n'existe qu'une seule porte d'entrée.
  var clines = document.querySelector(".clines");
  var ETATS = {
    ok: "publié", pending: "en attente de modération", slow: "trop vite — réessayez",
    rate: "trop de messages — patientez", bad: "refusé (2 à 2000 caractères)",
    csrf: "session expirée — rechargez", absent: "billet introuvable"
  };

  function ajouteConsole(qui, texte, attente, t) {
    if (!clines) return;
    var vide = clines.querySelector(".vide"); if (vide) vide.remove();
    var n = clines.querySelectorAll(".cline").length + 1;
    var li = document.createElement("li");
    li.className = "comment cline vu"; li.dataset.who = qui; li.dataset.when = "à l'instant";
    li.innerHTML = '<span class="ix">' + (n < 10 ? "0" + n : n) + '</span>'
      + '<span class="nm c-meta"><strong>' + esc(qui) + '</strong></span>'
      + '<span class="msg c-body">' + esc(texte) + '</span>'
      + '<time class="tm">' + (attente ? "en attente" : "à l'instant") + '</time>';
    clines.appendChild(li);
    if (!attente) [].forEach.call(document.querySelectorAll(".nbc"), function (b) {
      b.textContent = (parseInt(b.textContent, 10) || 0) + 1;
    });
  }

  function envoyer(nom, texte, dire) {
    var f = document.getElementById("msgbox");
    if (!f) { dire("indisponible", true); return Promise.resolve(false); }
    var c = f.querySelector('[name="csrf"]'), t = f.querySelector('[name="ts_token"]');
    var fd = new FormData();
    fd.append("csrf", c ? c.value : ""); fd.append("ts_token", t ? t.value : "");
    fd.append("website", ""); fd.append("author_name", nom); fd.append("body", texte);
    var ct = document.getElementById("mb-t");
    if (ct && ct.value) fd.append("video_t", ct.value);
    return fetch("/b/" + encodeURIComponent(slug) + "/comment", {
      method: "POST", body: fd, credentials: "same-origin",
      headers: { "Accept": "application/json" }
    }).then(function (r) { return r.json(); }).then(function (d) {
      dire(ETATS[d.c] || d.c, !d.ok);
      if (!d.ok) return false;
      var qui = d.who || nom, quoi = d.msg || texte, attente = (d.c === "pending");
      if (pousseLigne) pousseLigne({ who: qui, msg: quoi, when: d.when || "à l'instant",
                                     t: (d.t == null ? null : d.t) }, true, attente);
      ajouteConsole(qui, quoi, attente, d.t);
      return true;
    }).catch(function () { dire("envoi impossible", true); return false; });
  }

  // la barre incrustée dans l'écran
  var mb = document.getElementById("msgbox");
  if (mb) {
    var qui = document.getElementById("mb-qui"), quoi = document.getElementById("mb-quoi"),
        etat = document.getElementById("mb-etat"), envoi = mb.querySelector(".send");
    qui.value = LS.get("nom", "") || "";
    function dire(txt, err) {
      etat.textContent = txt || "";
      etat.className = "etat" + (txt ? (err ? " err" : " ok") : "");
      if (txt && !err) setTimeout(function () { etat.textContent = ""; etat.className = "etat"; }, 4000);
    }
    mb.addEventListener("submit", function (e) {
      e.preventDefault();
      var piege = mb.querySelector('[name="website"]');
      if (piege && piege.value) return;            /* piège rempli : on laisse filer */
      var n = (qui.value || "").trim(), m = (quoi.value || "").trim();
      if (n.length < 2) { dire("votre nom, d'abord", true); qui.focus(); return; }
      if (m.length < 2) { quoi.focus(); return; }
      LS.set("nom", n);
      var champT = document.getElementById("mb-t");
      if (champT) champT.value = joue ? String(Math.floor(pos())) : "";
      envoi.disabled = true; dire("envoi…" + (joue ? " @" + mmss(pos()) : ""));
      envoyer(n, m, dire).then(function (ok) {
        envoi.disabled = false;
        if (ok) { quoi.value = ""; quoi.focus(); }
      });
    });
    [].forEach.call(mb.querySelectorAll(".emo"), function (b) {
      b.addEventListener("click", function () {
        quoi.value += b.dataset.emo; quoi.focus();
      });
    });
  }

})();
