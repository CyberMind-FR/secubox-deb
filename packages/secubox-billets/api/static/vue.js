/* SPDX-License-Identifier: LicenseRef-CMSD-1.0
   Vue billet (#1268) — la scène du popup théâtre, en grand :
     · l'embed reprend LA POSITION MEMORISEE par le fil (même clé bpos:<slug>) ;
     · le SON est un choix GLOBAL retenu (clé « son »), pas un bouton par lecture ;
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

  // ── SON : un choix, retenu, appliqué partout ──────────────────────────────
  // L'autoplay non-muté n'est autorisé qu'avec une activation de la page ; on
  // garde donc le muet tant que la page n'a rien reçu, puis on applique le choix.
  var gest = false;
  ["pointerdown", "keydown", "touchstart"].forEach(function (ev) {
    addEventListener(ev, function () { gest = true; }, { once: true, passive: true });
  });
  function son() { return LS.get("son", false) === true; }

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

  if (ifr && src0 && embedSrc(src0, true, 0)) {
    // On REPREND là où le fil s'était arrêté, muet par défaut (autoplay garanti),
    // avec le son si c'est le choix retenu et que la page est déjà activée.
    lance(!(son() && gest), LS.get("bpos:" + slug, 0));
    setInterval(retiens, 4000);
    addEventListener("pagehide", retiens);
    addEventListener("beforeunload", retiens);
    document.addEventListener("visibilitychange", function () { if (document.hidden) retiens(); });
  }

  // ── OSD ───────────────────────────────────────────────────────────────────
  var bSnd = scene && scene.querySelector('[data-act="snd"]');
  function majSnd() {
    if (!bSnd) return;
    var on = son();
    bSnd.textContent = on ? "🔊 son" : "🔇 muet";
    bSnd.classList.toggle("on", on);
    bSnd.setAttribute("aria-pressed", on ? "true" : "false");
    bSnd.title = on ? "Le son est retenu pour toutes les lectures" : "Muet — le choix sera retenu partout";
  }
  majSnd();
  if (bSnd) bSnd.addEventListener("click", function () {
    var v = !son(); LS.set("son", v); majSnd();
    if (ifr && src0) lance(!v, pos());      /* le clic EST le geste : ça repart au bon endroit */
  });

  var bSubs = scene && scene.querySelector('[data-act="subs"]');
  if (bSubs) bSubs.addEventListener("click", function () {
    var off = scene.classList.toggle("nosubs");
    this.classList.toggle("on", !off); this.setAttribute("aria-pressed", off ? "false" : "true");
  });
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
  var src = [].slice.call(document.querySelectorAll("#comments .cline")).map(function (n, i) {
    var m = n.querySelector(".msg");
    return {
      i: i, who: n.dataset.who || "", when: n.dataset.when || "",
      msg: (m ? m.textContent : "").replace(/\s+/g, " ").trim(), node: n
    };
  }).filter(function (c) { return c.msg; });

  if (track && src.length) {
    var k = 0, MAX = 3;
    function pousse() {
      if (document.hidden || !scene || scene.classList.contains("nosubs")) return;
      var c = src[k % src.length]; k++;
      var d = document.createElement("div"); d.className = "line";
      d.innerHTML = '<span class="k">▸</span><span class="nm">' + esc(c.who) + '</span>'
        + '<span class="msg">' + esc(c.msg) + '</span>'
        + '<span class="tm">' + esc(c.when) + '</span>';
      d.addEventListener("mouseenter", function (e) { montre(e, c.who, c.msg, c.when); });
      d.addEventListener("mousemove", function (e) { montre(e, c.who, c.msg, c.when); });
      d.addEventListener("mouseleave", cache);
      d.addEventListener("click", function () {
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
      }, 9000);
    }
    pousse();
    setTimeout(pousse, 1400);
    setInterval(pousse, 4200);
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
})();
