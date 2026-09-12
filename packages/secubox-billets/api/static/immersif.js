// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Fil immersif billets (#1268). Couloirs chat/likes GLOBAUX toujours visibles ;
// survol = spotlight + connecteur ; CLIC sur l'écran = lecture forcée (autoplay).
(function () {
  "use strict";
  var LS = {
    get: function (k, d) { try { var v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } },
    set: function (k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} }
  };
  var CATS = ["auth", "wall", "boot", "mind", "root", "mesh"];
  var COL = { auth: "#f0a020", wall: "#e8c637", boot: "#e8556e", mind: "#9b6ff0", root: "#2fcf6a", mesh: "#22c8e8" };
  var PCOL = ["#c9a84c", "#4db6d6", "#e8836b", "#5fb98f", "#8b7fd6", "#d98fb0", "#6fb0e0"];

  var feed = document.getElementById("fil-billets");
  var col = document.getElementById("col");
  var laneL = document.getElementById("laneL"), laneR = document.getElementById("laneR");
  var emptyL = document.getElementById("emptyL"), emptyR = document.getElementById("emptyR");
  var linksSvg = document.getElementById("links"), legendEl = document.getElementById("legend"), sheet = document.getElementById("sheet");
  if (!feed) return;

  var active = null;     // survolé (spotlight + connecteur)
  var playing = null;    // en lecture (iframe), un seul à la fois
  var raf = null, base = 0, t0 = 0;
  function fmt(s) { s = Math.max(0, Math.floor(s)); return Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0"); }
  function esc(s) { return String(s == null ? "" : s).replace(/[<>&]/g, function (c) { return { "<": "&lt;", ">": "&gt;", "&": "&amp;" }[c]; }); }
  function tone(el) { return COL[el.dataset.cat] || "#4db6d6"; }

  // ── survol = SPOTLIGHT (pas de lecture) ────────────────────
  function activate(el) {
    if (active === el) return;
    if (active) deactivate(active);
    active = el; el.classList.add("on");
    drawLinks(el); highlight(el.dataset.id, true);
  }
  function deactivate(el) {
    el.classList.remove("on");
    if (active === el) { active = null; clearLinks(); highlight(null, false); }
  }

  // ── clic sur l'écran = FORCE la lecture (autoplay, geste → son) ─
  function playableSrc(embed) {
    var m = embed.match(/(?:youtu\.be\/|[?&]v=|\/embed\/)([A-Za-z0-9_-]{11})/);
    if (m && /youtu/.test(embed)) return "https://www.youtube-nocookie.com/embed/" + m[1] + "?rel=0";
    return embed;
  }
  function stopPlaying() {
    if (!playing) return;
    var el = playing;
    cancelAnimationFrame(raf); raf = null;
    var t = base + (performance.now() - t0) / 1000;
    LS.set("bpos:" + el.dataset.id, Math.max(0, Math.floor(t)));
    var frame = el.querySelector(".frame"); if (frame) frame.innerHTML = "";
    var seen = el.querySelector(".seen"); if (seen) seen.style.width = Math.min(100, t / 3) + "%";
    el.classList.remove("playing");
    playing = null;
  }
  function togglePlay(el) {
    var embed = el.dataset.embed; if (!embed) return;
    if (playing === el) { stopPlaying(); return; }
    if (playing) stopPlaying();
    var slug = el.dataset.id, pos = LS.get("bpos:" + slug, 0);
    var src = playableSrc(embed);
    src += (src.indexOf("?") >= 0 ? "&" : "?") + "autoplay=1&muted=0&start=" + Math.floor(pos);
    var frame = el.querySelector(".frame");
    var ifr = document.createElement("iframe");
    ifr.setAttribute("allow", "autoplay; fullscreen; encrypted-media; picture-in-picture");
    ifr.src = src; frame.innerHTML = ""; frame.appendChild(ifr);
    el.classList.add("playing", "on"); playing = el;
    base = pos; t0 = performance.now();
    var tc = el.querySelector(".tc"), played = el.querySelector(".played");
    (function tick(now) {
      if (playing !== el) return;
      var t = base + (now - t0) / 1000;
      if (tc) tc.textContent = fmt(t);
      if (played) played.style.width = Math.min(100, t / 3) + "%";
      raf = requestAnimationFrame(tick);
    })(performance.now());
  }

  // ── couloirs GLOBAUX (toujours visibles) ───────────────────
  function avatar(name, i) { return '<span class="av" style="background:' + PCOL[(i || 0) % PCOL.length] + '">' + esc((name || "?").slice(0, 1).toUpperCase()) + '</span>'; }
  function bubble(lane, html, cls, slug, delay) {
    var d = document.createElement("div"); d.className = "bub" + (cls ? " " + cls : "");
    if (slug) d.dataset.slug = slug; d.innerHTML = html; d.style.animationDelay = (delay || 0) + "ms"; lane.appendChild(d);
  }
  function highlight(slug, on) {
    [].forEach.call(document.querySelectorAll(".bub[data-slug]"), function (b) {
      b.classList.toggle("hot", !!(on && slug && b.dataset.slug === slug));
    });
  }
  function loadActivity() {
    fetch("/feed/activity", { headers: { "Accept": "application/json" } })
      .then(function (r) { return r.ok ? r.json() : { comments: [], reactions: [] }; })
      .then(function (d) {
        laneL.innerHTML = ""; laneR.innerHTML = "";
        var cm = d.comments || [];
        if (cm.length) { emptyL.style.display = "none";
          cm.forEach(function (c, i) {
            bubble(laneL, '<div class="who">' + avatar(c.who, i) + '<span class="nm">' + esc(c.who) + '</span><span class="tm">' + esc(c.when || "") + '</span></div><div class="msg">' + esc(c.msg) + '</div>', "", c.slug, i * 45);
          });
        }
        var rx = d.reactions || [];
        if (rx.length) { emptyR.style.display = "none";
          rx.forEach(function (r, i) { bubble(laneR, '<span class="emo">' + esc(r.emoji) + '</span>', "react", r.slug, i * 45); });
        }
      }).catch(function () {});
  }

  // ── connecteurs ────────────────────────────────────────────
  function clearLinks() { linksSvg.innerHTML = ""; }
  function drawLinks(el) {
    if (window.innerWidth < 1081) { clearLinks(); return; }
    var r = el.getBoundingClientRect(), lb = laneL.getBoundingClientRect(), rb = laneR.getBoundingClientRect();
    var y = r.top + 22, c = tone(el);
    function mk(x1, y1, x2, y2) { var cx = (x1 + x2) / 2; return '<path d="M' + x1 + ' ' + y1 + ' C ' + cx + ' ' + y1 + ' ' + cx + ' ' + y2 + ' ' + x2 + ' ' + y2 + '" stroke="' + c + '"/>'; }
    linksSvg.innerHTML = mk(r.left, y, lb.right - 10, Math.max(84, r.top + 40)) + mk(r.right, y, rb.left + 10, Math.max(84, r.top + 40));
  }
  window.addEventListener("scroll", function () { if (active) drawLinks(active); }, { passive: true });
  window.addEventListener("resize", function () { if (active) drawLinks(active); });

  // ── délégation survol / clic ───────────────────────────────
  col.addEventListener("mouseover", function (e) { var c = e.target.closest(".card"); if (c && !c.contains(e.relatedTarget)) activate(c); });
  col.addEventListener("mouseout", function (e) { var c = e.target.closest(".card"); if (c && !c.contains(e.relatedTarget)) deactivate(c); });
  col.addEventListener("focusin", function (e) { var c = e.target.closest(".card"); if (c) activate(c); });
  col.addEventListener("click", function (e) {
    var like = e.target.closest("[data-like]");
    if (like) { e.preventDefault(); toggleLike(like.closest(".card"), like); return; }
    var btn = e.target.closest("[data-open],[data-comment]");
    if (btn) { e.preventDefault(); openSheet(btn.closest(".card"), !!e.target.closest("[data-comment]")); return; }
    var scr = e.target.closest("[data-play]");
    if (scr) { var c = scr.closest(".card"); if (c && c.dataset.embed) { e.preventDefault(); togglePlay(c); } }
  });
  // clic dans un lane → ouvrir le billet concerné
  [laneL, laneR].forEach(function (ln) {
    ln.addEventListener("click", function (e) {
      var b = e.target.closest(".bub[data-slug]"); if (!b) return;
      var card = feed.querySelector('.card[data-id="' + b.dataset.slug + '"]');
      if (card) openSheetSlug(b.dataset.slug, card);
    });
  });

  function toggleLike(card, btn) {
    var slug = card.dataset.id, liked = !LS.get("like:" + slug, false);
    LS.set("like:" + slug, liked); btn.classList.toggle("liked", liked);
  }

  function openSheetSlug(slug, card) {
    var url = "/b/" + encodeURIComponent(slug);
    var title = card && card.querySelector(".title") ? card.querySelector(".title").textContent : "billet";
    sheet.innerHTML = '<div class="sheet"><button class="x" data-close aria-label="Fermer">✕</button><iframe src="' + url + '" title="' + esc(title) + '"></iframe></div>';
    if (typeof sheet.showModal === "function") sheet.showModal(); else location.href = url;
    sheet.querySelector("[data-close]").onclick = function () { sheet.close(); };
    sheet.addEventListener("click", function (e) { if (e.target === sheet) sheet.close(); }, { once: true });
  }
  function openSheet(card, focusComment) { openSheetSlug(card.dataset.id, card); }

  // ── légende / filtre ───────────────────────────────────────
  var activeFilter = null;
  (function () {
    if (!legendEl) return;
    var all = document.createElement("button"); all.className = "lg on"; all.dataset.cat = "";
    all.innerHTML = '<span class="d" style="background:conic-gradient(#f0a020,#e8c637,#e8556e,#9b6ff0,#2fcf6a,#22c8e8,#f0a020)"></span>tous';
    legendEl.appendChild(all);
    CATS.forEach(function (k) { var b = document.createElement("button"); b.className = "lg"; b.dataset.cat = k;
      b.innerHTML = '<span class="d" style="background:' + COL[k] + '"></span>' + k; legendEl.appendChild(b); });
    legendEl.addEventListener("click", function (e) { var b = e.target.closest(".lg"); if (!b) return;
      activeFilter = b.dataset.cat || null;
      [].forEach.call(legendEl.children, function (x) { x.classList.toggle("on", x === b); }); applyFilter(); });
  })();
  function applyFilter() { [].forEach.call(feed.querySelectorAll(".card"), function (el) { el.classList.toggle("dim", !!(activeFilter && el.dataset.cat !== activeFilter)); }); }

  // ── mur infini ─────────────────────────────────────────────
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
        if (d.next_cursor) pager.setAttribute("data-cursor", d.next_cursor); else stopScroll();
      }).catch(function () { if (++echecs >= 3 && obs) obs.disconnect(); })
      .then(function () { loading = false; if (loader) loader.hidden = true; });
  }
  if (pager && "IntersectionObserver" in window) {
    obs = new IntersectionObserver(function (es) { if (es.some(function (e) { return e.isIntersecting; })) loadMore(); }, { rootMargin: "800px 0px" });
    obs.observe(pager);
  }

  loadActivity();
  setInterval(loadActivity, 45000);   // le flux reste vivant
})();
