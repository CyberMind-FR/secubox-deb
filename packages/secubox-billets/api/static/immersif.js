// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Fil immersif billets (#1268) — survol=lecture (PeerTube réel + mémoire de
// position), couloirs-chat via /activity, dialog=permalien réel, scroll infini.
(function () {
  "use strict";
  var LS = {
    get: function (k, d) { try { var v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } },
    set: function (k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} }
  };
  var CATS = ["auth", "wall", "boot", "mind", "root", "mesh"];
  var COL = { auth: "#f0a020", wall: "#e8c637", boot: "#e8556e", mind: "#9b6ff0", root: "#2fcf6a", mesh: "#22c8e8" };
  var PEOPLE_COL = ["#c9a84c", "#4db6d6", "#e8836b", "#5fb98f", "#8b7fd6", "#d98fb0", "#6fb0e0"];
  var EMO_LABEL = { "❤️": "❤️", "🔥": "🔥", "👏": "👏", "🎧": "🎧", "🌀": "🌀", "⭐": "⭐" };

  var feed = document.getElementById("fil-billets");
  var col = document.getElementById("col");
  var laneL = document.getElementById("laneL"), laneR = document.getElementById("laneR");
  var emptyL = document.getElementById("emptyL"), emptyR = document.getElementById("emptyR");
  var linksSvg = document.getElementById("links");
  var legendEl = document.getElementById("legend");
  var sheet = document.getElementById("sheet");
  if (!feed) return;

  var active = null, raf = null, hoverStart = 0, basePos = 0, activeSlug = null, actToken = 0;
  function fmt(s) { s = Math.max(0, Math.floor(s)); return Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0"); }
  function colorOf(el) { return COL[el.dataset.cat] || "#4db6d6"; }

  // ── activation au survol ───────────────────────────────────
  function activate(el) {
    if (active === el) return;
    if (active) deactivate(active);
    active = el; el.classList.add("on");
    var slug = el.dataset.id; activeSlug = slug;
    var prov = el.dataset.prov, embed = el.dataset.embed;
    var pos = LS.get("bpos:" + slug, 0);
    var seen = el.querySelector(".seen"); if (seen && pos > 0) seen.style.width = Math.min(100, pos / 3) + "%";

    if (prov === "pt" && embed) {
      // lecteur PeerTube RÉEL : autoplay muet, reprise à la position mémorisée
      var frame = el.querySelector(".frame");
      if (frame && !frame.firstChild) {
        var sep = embed.indexOf("?") >= 0 ? "&" : "?";
        var src = embed + sep + "autoplay=1&muted=1&controls=1&title=0&warningTitle=0&peertubeLink=0&p2p=0&start=" + Math.floor(pos);
        var ifr = document.createElement("iframe");
        ifr.setAttribute("allow", "autoplay; fullscreen; encrypted-media");
        ifr.setAttribute("loading", "eager"); ifr.src = src;
        frame.appendChild(ifr);
      }
      el.classList.add("playing");
      var resume = el.querySelector(".resume"), rt = el.querySelector(".rt"), tc = el.querySelector(".tc"), played = el.querySelector(".played");
      if (pos > 1 && resume) { resume.classList.add("show"); if (rt) rt.textContent = fmt(pos); }
      basePos = pos; hoverStart = performance.now();
      (function tick(now) {
        if (active !== el) return;
        var t = basePos + (now - hoverStart) / 1000;
        if (tc) tc.textContent = fmt(t);
        if (played) played.style.width = Math.min(100, t / 3) + "%";  // échelle indicative
        raf = requestAnimationFrame(tick);
      })(performance.now());
    }
    loadLanes(slug);
    drawLinks(el);
  }
  function deactivate(el) {
    el.classList.remove("on", "playing");
    if (active === el) {
      var slug = el.dataset.id;
      if (el.dataset.prov === "pt") {
        cancelAnimationFrame(raf); raf = null;
        var t = basePos + (performance.now() - hoverStart) / 1000;
        LS.set("bpos:" + slug, Math.max(0, Math.floor(t)));      // souvenir de position
        var frame = el.querySelector(".frame"); if (frame) frame.innerHTML = "";  // arrêter le lecteur
        var seen = el.querySelector(".seen"); if (seen) seen.style.width = Math.min(100, t / 3) + "%";
      }
      active = null; activeSlug = null; clearLanes(); clearLinks();
    }
  }

  // ── couloirs latéraux : vraies données via /activity/<slug> ─
  function avatar(name, i) { var c = PEOPLE_COL[(i || 0) % PEOPLE_COL.length]; return '<span class="av" style="background:' + c + '">' + (name || "?").slice(0, 1).toUpperCase() + '</span>'; }
  function clearLanes() { laneL.innerHTML = ""; laneR.innerHTML = ""; emptyL.style.display = ""; emptyR.style.display = ""; }
  function bubble(lane, html, cls, delay) {
    var d = document.createElement("div"); d.className = "bub" + (cls ? " " + cls : "");
    d.innerHTML = html; d.style.animationDelay = (delay || 0) + "ms"; lane.appendChild(d);
  }
  function loadLanes(slug) {
    clearLanes();
    var token = ++actToken;
    fetch("/activity/" + encodeURIComponent(slug), { headers: { "Accept": "application/json" } })
      .then(function (r) { return r.ok ? r.json() : { comments: [], reactions: {} }; })
      .then(function (d) {
        if (token !== actToken) return;               // survol changé entre-temps
        var cm = d.comments || [];
        if (cm.length) { emptyL.style.display = "none";
          cm.forEach(function (c, i) {
            bubble(laneL, '<div class="who">' + avatar(c.who, i) + '<span class="nm">' + esc(c.who) + '</span><span class="tm">' + esc(c.when || "") + '</span></div><div class="msg">' + esc(c.msg) + '</div>', "", i * 70);
          });
        }
        var rx = d.reactions || {}, keys = Object.keys(rx), any = false, i = 0;
        keys.forEach(function (emo) {
          if (!rx[emo]) return; any = true;
          bubble(laneR, '<span class="emo">' + esc(emo) + '</span><span class="nm">×' + rx[emo] + '</span>', "react", (i++) * 80);
        });
        if (any) emptyR.style.display = "none";
        // total → compteur du bouton like de la carte
        var el = active; if (el && el.dataset.id === slug) {
          var total = keys.reduce(function (s, k) { return s + (rx[k] || 0); }, 0);
          var n = el.querySelector("[data-like] .n"); if (n) n.textContent = total || "·";
        }
        if (active) drawLinks(active);
      }).catch(function () {});
  }
  function esc(s) { return String(s == null ? "" : s).replace(/[<>&]/g, function (c) { return { "<": "&lt;", ">": "&gt;", "&": "&amp;" }[c]; }); }

  // ── connecteurs vers le billet actif ───────────────────────
  function clearLinks() { linksSvg.innerHTML = ""; }
  function drawLinks(el) {
    if (window.innerWidth < 1081) { clearLinks(); return; }
    var r = el.getBoundingClientRect(), lb = laneL.getBoundingClientRect(), rb = laneR.getBoundingClientRect();
    var yTop = r.top + 22, tone = colorOf(el);
    function mk(x1, y1, x2, y2) { var cx = (x1 + x2) / 2; return '<path d="M' + x1 + ' ' + y1 + ' C ' + cx + ' ' + y1 + ' ' + cx + ' ' + y2 + ' ' + x2 + ' ' + y2 + '" stroke="' + tone + '"/>'; }
    linksSvg.innerHTML = mk(r.left, yTop, lb.right - 10, Math.max(84, r.top + 40)) + mk(r.right, yTop, rb.left + 10, Math.max(84, r.top + 40));
  }
  window.addEventListener("scroll", function () { if (active) drawLinks(active); }, { passive: true });
  window.addEventListener("resize", function () { if (active) drawLinks(active); });

  // ── délégation hover / focus / clics ───────────────────────
  col.addEventListener("mouseover", function (e) { var c = e.target.closest(".card"); if (c && !c.contains(e.relatedTarget)) activate(c); });
  col.addEventListener("mouseout", function (e) { var c = e.target.closest(".card"); if (c && !c.contains(e.relatedTarget)) deactivate(c); });
  col.addEventListener("focusin", function (e) { var c = e.target.closest(".card"); if (c) activate(c); });
  col.addEventListener("click", function (e) {
    var like = e.target.closest("[data-like]");
    if (like) { e.preventDefault(); var c = like.closest(".card"); toggleLike(c, like); return; }
    var open = e.target.closest("[data-open],[data-comment],[data-play]");
    if (open) { var c2 = open.closest(".card"); if (c2) { e.preventDefault(); openSheet(c2, !!e.target.closest("[data-comment]")); } }
  });

  function toggleLike(card, btn) {
    var slug = card.dataset.id, liked = !LS.get("like:" + slug, false);
    LS.set("like:" + slug, liked); btn.classList.toggle("liked", liked);
    // le "like" visuel est local ; la réaction persistée se fait dans le permalien
    // (ouvert par « ouvrir »/« commenter »), qui porte le jeton anti-CSRF.
  }

  // ── overlay immersif = le permalien réel (vidéo + commentaires + réactions) ─
  function openSheet(card, focusComment) {
    var slug = card.dataset.id;
    var url = "/b/" + encodeURIComponent(slug) + (focusComment ? "#reactions" : "");
    sheet.innerHTML = '<div class="sheet"><button class="x" data-close aria-label="Fermer">✕</button><iframe src="' + url + '" title="' + esc(card.querySelector(".title") ? card.querySelector(".title").textContent : "billet") + '"></iframe></div>';
    if (typeof sheet.showModal === "function") sheet.showModal(); else location.href = url;
    sheet.querySelector("[data-close]").onclick = function () { sheet.close(); };
    sheet.addEventListener("click", function (e) { if (e.target === sheet) sheet.close(); }, { once: true });
  }

  // ── légende / filtre de catégories ─────────────────────────
  var activeFilter = null;
  (function buildLegend() {
    if (!legendEl) return;
    var all = document.createElement("button"); all.className = "lg on"; all.dataset.cat = "";
    all.innerHTML = '<span class="d" style="background:conic-gradient(#f0a020,#e8c637,#e8556e,#9b6ff0,#2fcf6a,#22c8e8,#f0a020)"></span>tous';
    legendEl.appendChild(all);
    CATS.forEach(function (k) {
      var b = document.createElement("button"); b.className = "lg"; b.dataset.cat = k;
      b.innerHTML = '<span class="d" style="background:' + COL[k] + '"></span>' + k;
      legendEl.appendChild(b);
    });
    legendEl.addEventListener("click", function (e) {
      var b = e.target.closest(".lg"); if (!b) return;
      activeFilter = b.dataset.cat || null;
      [].forEach.call(legendEl.children, function (x) { x.classList.toggle("on", x === b); });
      applyFilter();
    });
  })();
  function applyFilter() {
    [].forEach.call(feed.querySelectorAll(".card"), function (el) {
      el.classList.toggle("dim", !!(activeFilter && el.dataset.cat !== activeFilter));
    });
  }

  // ── mur infini (fragment /feed/suite) ──────────────────────
  var pager = document.getElementById("fil-pager"), loader = document.getElementById("loader"), loading = false, echecs = 0, obs = null;
  function stopScroll() { if (pager && pager.parentNode) pager.parentNode.removeChild(pager); if (obs) obs.disconnect(); if (loader) loader.hidden = true; }
  function loadMore() {
    if (loading || !pager) return;
    var cursor = pager.getAttribute("data-cursor"); if (!cursor) { stopScroll(); return; }
    loading = true; if (loader) loader.hidden = false;
    var tag = pager.getAttribute("data-tag");
    var url = "/feed/suite?cursor=" + encodeURIComponent(cursor) + (tag ? "&tag=" + encodeURIComponent(tag) : "");
    fetch(url, { headers: { "Accept": "application/json" } })
      .then(function (r) { if (!r.ok) throw 0; return r.json(); })
      .then(function (d) {
        if (d.html) { var tmp = document.createElement("div"); tmp.innerHTML = d.html; while (tmp.firstChild) feed.appendChild(tmp.firstChild); }
        echecs = 0; applyFilter();
        if (d.next_cursor) { pager.setAttribute("data-cursor", d.next_cursor); }
        else stopScroll();
      }).catch(function () { if (++echecs >= 3 && obs) obs.disconnect(); })
      .then(function () { loading = false; if (loader) loader.hidden = true; });
  }
  if (pager && "IntersectionObserver" in window) {
    obs = new IntersectionObserver(function (es) { if (es.some(function (e) { return e.isIntersecting; })) loadMore(); }, { rootMargin: "800px 0px" });
    obs.observe(pager);
  }
})();
