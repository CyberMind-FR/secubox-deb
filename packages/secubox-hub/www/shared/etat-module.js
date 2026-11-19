// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

/**
 * SecuBox-Deb :: bouton d'état du module (#3812)
 * CyberMind — https://cybermind.fr
 *
 * Chargé par /shared/sidebar.js (même origine : `script-src 'self'` suffit).
 * Fichier à part plutôt que dans sidebar.js : sidebar.js (≈2 900 lignes) peint
 * encore du HTML par innerHTML et des gestionnaires en ligne ; ce bouton lit des
 * données d'API et propose des gestes (réveiller, endormir) — il ne bâtit son DOM
 * QUE par createElement/textContent, aucun gestionnaire en ligne, aucun style en
 * ligne (feuille /shared/etat-module.css), et sa logique pure se teste seule.
 *
 * 1. Module de la page : attribut explicite `data-sbx-module` (html ou body) ou
 *    <meta name="secubox-module">, sinon l'entrée du menu (menu.d) dont le chemin
 *    est le plus long préfixe de l'URL — son id EST l'id du manifeste (scan dérive
 *    les manifestes des unités secubox-<id> et de menu.d par le même id) —, sinon
 *    le premier segment du chemin. Le candidat retenu doit exister dans
 *    /api/v1/profiles/lifecycles ; aucun ne correspond : rien n'est affiché.
 * 2. Pastille (point + mot) insérée juste avant le bouton « Actualiser » de
 *    l'en-tête, sinon à la fin de `.tete .droite`, de `.tete`, ou au début de
 *    `.header .btn-group`.
 * 3. Clic : panneau (état, politique, unités, dépendances, Réveiller, Endormir
 *    avec confirmation DANS le panneau, jamais confirm()).
 * 4. Badge « HORS LIGNE » de la page : la vraie raison s'affiche à côté.
 *    « endormi » seulement si l'API le dit (sleep_state / etat), jamais déduit.
 * 5. Sans fiche d'administration (401/403 sur /module/{id}) : seulement ce que
 *    /lifecycles (garde de lecture) dit, et pas de bouton « Endormir ».
 */
(function (racine) {
    'use strict';

    var API = '/api/v1/profiles';

    var MOTS = {
        eveille: 'Éveillé', endormi: 'Endormi', arrete: 'Arrêté', echec: 'En échec',
        dependance: 'Dépendance en panne', inconnu: 'État inconnu', permanent: 'Permanent',
        manuel: 'Manuel', chargement: 'État…'
    };
    var POLITIQUES = {
        'always-on': 'toujours actif', 'eager': 'démarré d\'office, s\'endort inactif',
        'on-demand': 'à la demande (s\'endort inactif)', 'manual': 'manuel (opérateur seulement)'
    };
    var UNITES = {
        actif: ['actif', 'ok'], demarrage: ['démarrage', 'att'], arret: ['arrêt en cours', 'att'],
        inactif: ['inactif', ''], echec: ['en échec', 'ko'], absente: ['absente', 'ko'], inconnu: ['inconnu', '']
    };

    // ── Logique pure (testée sans navigateur) ─────────────────────────────
    function idValide(id) { return typeof id === 'string' && /^[a-z0-9][a-z0-9-]{0,63}$/.test(id); }

    function normaliserChemin(p) {
        if (typeof p !== 'string' || !p) return null;
        var m = p.match(/^[a-z]+:\/\/[^/]+(\/.*)?$/i);
        if (m) p = m[1] || '/';
        if (p.charAt(0) !== '/') return null;
        p = p.split('?')[0].split('#')[0];
        return p.replace(/index\.html$/, '');
    }

    function itemsDuMenu(menu) {
        var out = [];
        if (!menu || typeof menu !== 'object') return out;
        var groupes = [].concat(Array.isArray(menu.categories) ? menu.categories : [],
                                Array.isArray(menu.espaces) ? menu.espaces : []);
        groupes.forEach(function (g) {
            (g && Array.isArray(g.items) ? g.items : []).forEach(function (it) {
                if (it && typeof it.id === 'string' && typeof it.path === 'string') out.push(it);
            });
        });
        return out;
    }

    /** Candidats, par ordre de confiance, pour le chemin `chemin`. */
    function candidatsModule(chemin, menu, explicite) {
        var c = [];
        function ajoute(id) { if (idValide(id) && c.indexOf(id) < 0) c.push(id); }
        if (explicite) ajoute(String(explicite).trim());
        var page = normaliserChemin(chemin) || '/';
        var meilleurs = itemsDuMenu(menu).map(function (it) {
            return { id: it.id, p: normaliserChemin(it.path) };
        }).filter(function (x) {
            if (!x.p) return false;
            if (x.p === '/') return page === '/';
            return x.p.charAt(x.p.length - 1) === '/' ? page.indexOf(x.p) === 0 : page === x.p;
        }).sort(function (a, b) { return b.p.length - a.p.length; });
        meilleurs.forEach(function (x) { ajoute(x.id); });
        var seg = page.match(/^\/([a-z0-9-]+)(\/|$)/);
        if (seg) ajoute(seg[1]);
        else if (page === '/') ajoute('hub');
        return c;
    }

    function choisirModule(candidats, lifecycles) {
        var connus = {};
        (Array.isArray(lifecycles) ? lifecycles : []).forEach(function (l) { if (l && l.id) connus[l.id] = l; });
        for (var i = 0; i < candidats.length; i++) if (connus[candidats[i]]) return connus[candidats[i]];
        return null;
    }

    /** Clé d'état de la pastille. `fiche` = /module/{id} ; sinon `lecture` = ligne de /lifecycles. */
    function etatPastille(fiche, lecture) {
        if (fiche) {
            var e = fiche.etat_global || fiche.etat;
            return MOTS[e] ? e : 'inconnu';
        }
        if (lecture) {
            if (lecture.sleep_state === 'up') return 'eveille';
            if (lecture.sleep_state === 'asleep') return 'endormi';
            if (lecture.lifecycle === 'manual') return 'manuel';
            return 'permanent';
        }
        return 'inconnu';
    }

    function motEtat(cle) { return MOTS[cle] || MOTS.inconnu; }
    function politique(l) { return POLITIQUES[l] || (l ? String(l) : '—'); }

    /**
     * Raison d'un « HORS LIGNE » : {texte, reveiller (id du module à réveiller ou null)}.
     * Jamais « endormi » sans que l'API le dise.
     */
    function raisonHorsLigne(fiche, lecture) {
        if (fiche && fiche.raison) {
            var r = fiche.raison;
            if (r.code === 'endormi') return { texte: 'endormi', reveiller: fiche.id };
            if (r.code === 'echec') return { texte: 'en échec : ' + (r.unite || 'unité'), reveiller: null };
            if (r.code === 'arrete') return { texte: 'service arrêté', reveiller: null };
            if (r.code === 'dependance_endormie') return { texte: 'dépendance ' + r.dependance + ' endormie', reveiller: r.dependance };
            if (r.code === 'dependance_en_panne') return { texte: 'dépendance ' + r.dependance + ' en panne', reveiller: null };
            if (r.code === 'eveille') return { texte: 'raison inconnue (module éveillé)', reveiller: null };
            return { texte: 'raison inconnue', reveiller: null };
        }
        if (lecture && lecture.sleep_state === 'asleep') return { texte: 'endormi', reveiller: lecture.id };
        return { texte: 'raison inconnue', reveiller: null };
    }

    /** Message lisible d'un rapport de /wake ou /sleep. {texte, classe: ok|ko|''}. */
    function messageRapport(geste, rep, id) {
        rep = rep || {};
        var st = rep.status;
        if (geste === 'wake') {
            if (st === 'woken') return { texte: id + ' réveillé.', classe: 'ok' };
            if (st === 'already-up') return { texte: id + ' était déjà éveillé.', classe: 'ok' };
            if (st === 'refused') return { texte: 'Réveil refusé (' + (rep.reason || 'raison non donnée') + ').', classe: 'ko' };
            if (st === 'failed') return { texte: 'Échec du réveil' + (rep.detail ? ' : ' + rep.detail : '.'), classe: 'ko' };
            return { texte: 'Réponse du réveil : ' + (st || 'inconnue') + '.', classe: '' };
        }
        if (st === 'applied') {
            var ch = Array.isArray(rep.changed) ? rep.changed : [];
            if (ch.indexOf(id) >= 0) return { texte: id + ' endormi.', classe: 'ok' };
            return { texte: 'Rien n\'a été endormi : le profil actif (ou un épinglage) garde ' + id + ' éveillé.', classe: '' };
        }
        if (st === 'deferred') return { texte: 'Reporté : ' + (rep.reason || 'opération en cours'), classe: '' };
        if (st === 'rolled_back') return { texte: 'Échec de la mise en sommeil, état restauré.', classe: 'ko' };
        return { texte: 'Réponse : ' + (st || 'inconnue') + '.', classe: st === 'failed' ? 'ko' : '' };
    }

    function messageHttp(code, detail) {
        if (code === 401) return 'Connexion requise.';
        if (code === 403) return 'Réservé aux administrateurs de la box.';
        if (code === 409 || code === 404) return detail ? String(detail) : 'Refusé (HTTP ' + code + ').';
        if (code === 0) return 'Pas de réponse (délai dépassé ou réseau).';
        return 'Erreur HTTP ' + code + (detail ? ' : ' + detail : '') + '.';
    }

    var LOGIQUE = {
        idValide: idValide, normaliserChemin: normaliserChemin, candidatsModule: candidatsModule,
        choisirModule: choisirModule, etatPastille: etatPastille, motEtat: motEtat, politique: politique,
        raisonHorsLigne: raisonHorsLigne, messageRapport: messageRapport, messageHttp: messageHttp
    };
    if (typeof module !== 'undefined' && module.exports) { module.exports = LOGIQUE; }
    if (typeof document === 'undefined' || !racine) return;
    if (racine.SbxEtatModule) return;          // déjà chargé (sidebar réinjectée)
    racine.SbxEtatModule = LOGIQUE;

    // ── Navigateur ────────────────────────────────────────────────────────
    try { if (/(?:^|[?&])demo=1(?:&|$)/.test(location.search.slice(1))) return; } catch (e) { return; }

    var etat = { id: null, lecture: null, fiche: null, mode: null, confirmation: false, occupe: false, releve: null };
    var dom = {};

    function jeton() { try { return localStorage.getItem('sbx_token'); } catch (e) { return null; } }

    function appel(methode, url, corps, delaiMs) {
        var ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
        var minuterie = ctrl ? setTimeout(function () { ctrl.abort(); }, delaiMs || 20000) : null;
        var h = { 'Accept': 'application/json' };
        var t = jeton();
        if (t) h.Authorization = 'Bearer ' + t;
        if (corps) h['Content-Type'] = 'application/json';
        return fetch(url, { method: methode, headers: h, credentials: 'same-origin', cache: 'no-store',
                            body: corps ? JSON.stringify(corps) : undefined, signal: ctrl ? ctrl.signal : undefined })
            .then(function (r) {
                return r.json().catch(function () { return null; }).then(function (j) {
                    return { code: r.status, ok: r.ok, data: j };
                });
            }, function () { return { code: 0, ok: false, data: null }; })
            .then(function (res) { if (minuterie) clearTimeout(minuterie); return res; });
    }

    function el(tag, cls, texte) {
        var e = document.createElement(tag);
        if (cls) e.className = cls;
        if (texte !== undefined && texte !== null) e.textContent = String(texte);
        return e;
    }
    function vider(e) { while (e.firstChild) e.removeChild(e.firstChild); }
    function heure(d) { try { return d.toLocaleTimeString('fr-FR'); } catch (e) { return ''; } }

    function moduleExplicite() {
        var h = document.documentElement, b = document.body;
        var v = (h && h.getAttribute('data-sbx-module')) || (b && b.getAttribute('data-sbx-module'));
        if (v) return v;
        var m = document.querySelector('meta[name="secubox-module"]');
        return m ? m.getAttribute('content') : null;
    }

    function menuConnu() {
        if (racine._menuDataCache) return racine._menuDataCache;
        try {
            var c = localStorage.getItem('sbx_menu_cache');
            if (c && c.charAt(0) === '{') return (JSON.parse(c) || {}).menu || null;
        } catch (e) { /* stockage indisponible : le segment du chemin suffit */ }
        return null;
    }

    // ── Insertion dans l'en-tête ──────────────────────────────────────────
    function boutonActualiser(zone) {
        var b = zone.querySelector('#rafraichir, #btn-refresh, #btnRefresh');
        if (b) return b;
        var tous = zone.querySelectorAll('button, a.btn');
        for (var i = 0; i < tous.length; i++) {
            if (/actualiser|rafra[iî]chir|refresh/i.test(tous[i].textContent || '')) return tous[i];
        }
        return null;
    }

    function zoneEntete() { return document.querySelector('.tete') || document.querySelector('header.header, .header') || document; }

    function placer(noeud) {
        var tete = zoneEntete();
        if (tete === document) return false;
        var b = boutonActualiser(tete);
        if (b && b.parentNode) { b.parentNode.insertBefore(noeud, b); return true; }
        var droite = tete.querySelector('.droite');
        if (droite) { droite.appendChild(noeud); return true; }
        var groupe = tete.querySelector('.btn-group');
        if (groupe) { groupe.insertBefore(noeud, groupe.firstChild); return true; }
        tete.appendChild(noeud);
        return true;
    }

    function chargerFeuille() {
        if (document.querySelector('link[href="/shared/etat-module.css"]')) return;
        var l = document.createElement('link');
        l.rel = 'stylesheet';
        l.href = '/shared/etat-module.css';
        document.head.appendChild(l);
    }

    function construire() {
        var enveloppe = el('span', 'sbx-etat');
        enveloppe.setAttribute('data-etat', 'chargement');
        var puce = el('button', 'sbx-etat-puce');
        puce.type = 'button';
        puce.setAttribute('aria-haspopup', 'dialog');
        puce.setAttribute('aria-expanded', 'false');
        puce.title = 'État du module et de ses dépendances';
        var point = el('span', 'sbx-etat-point');
        point.setAttribute('aria-hidden', 'true');
        var mot = el('span', 'sbx-etat-mot', MOTS.chargement);
        puce.appendChild(point);
        puce.appendChild(mot);
        var panneau = el('div', 'sbx-etat-panneau');
        panneau.setAttribute('role', 'dialog');
        panneau.setAttribute('aria-label', 'État du module');
        panneau.hidden = true;
        enveloppe.appendChild(puce);
        enveloppe.appendChild(panneau);
        puce.addEventListener('click', function (ev) { ev.stopPropagation(); basculer(); });
        panneau.addEventListener('click', function (ev) { ev.stopPropagation(); });
        document.addEventListener('click', function () { if (!panneau.hidden && !etat.confirmation && !etat.occupe) fermer(); });
        document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape' && !panneau.hidden) { fermer(); puce.focus(); } });
        dom = { enveloppe: enveloppe, puce: puce, mot: mot, panneau: panneau };
        return enveloppe;
    }

    function ajusterPanneau() {
        var p = dom.panneau;
        p.style.left = ''; p.style.right = '';
        var r = p.getBoundingClientRect();
        var vw = document.documentElement.clientWidth || window.innerWidth;
        if (r.left < 8) {
            var env = dom.enveloppe.getBoundingClientRect();
            p.style.right = 'auto';
            p.style.left = Math.round(8 - env.left) + 'px';
        } else if (r.right > vw - 8) {
            p.style.right = Math.round(r.right - (vw - 8)) + 'px';
        }
    }

    function ouvrir() {
        dom.panneau.hidden = false;
        dom.puce.setAttribute('aria-expanded', 'true');
        rendrePanneau();
        ajusterPanneau();
    }
    function fermer() {
        dom.panneau.hidden = true;
        dom.puce.setAttribute('aria-expanded', 'false');
        etat.confirmation = false;
    }
    function basculer() { if (dom.panneau.hidden) ouvrir(); else fermer(); }

    // ── Rendu ─────────────────────────────────────────────────────────────
    function rendrePuce() {
        var cle = etatPastille(etat.fiche, etat.lecture);
        dom.enveloppe.setAttribute('data-etat', cle);
        dom.mot.textContent = motEtat(cle);
        var lc = (etat.fiche || etat.lecture || {}).lifecycle;
        dom.puce.title = 'Module ' + etat.id + ' — ' + motEtat(cle) + ' · politique : ' + politique(lc) +
            (etat.fiche ? '' : ' · détail des unités réservé à l\'administration');
    }

    function ligne(parent, etiquette, valeur) {
        var d = el('div', 'sbx-etat-ligne');
        d.appendChild(el('span', '', etiquette));
        d.appendChild(el('b', '', valeur));
        parent.appendChild(d);
    }

    function pastilleUnite(cle) {
        var u = UNITES[cle] || UNITES.inconnu;
        return el('span', 'sbx-etat-pastille ' + u[1], u[0]);
    }

    function pastilleModule(cle) {
        var cls = { eveille: 'ok', endormi: 'dort', arrete: 'att', echec: 'ko', absente: 'ko', dependance: 'att' }[cle] || '';
        return el('span', 'sbx-etat-pastille ' + cls, cle === 'absente' ? 'sans manifeste' : motEtat(cle));
    }

    function bouton(texte, cls, action) {
        var b = el('button', 'sbx-etat-btn ' + (cls || ''), texte);
        b.type = 'button';
        b.disabled = etat.occupe;
        b.addEventListener('click', action);
        return b;
    }

    var message = { texte: '', classe: '' };
    function dire(texte, classe) {
        message = { texte: texte || '', classe: classe || '' };
        if (dom.msg) {
            dom.msg.textContent = message.texte;
            dom.msg.className = 'sbx-etat-msg ' + message.classe;
            dom.msg.hidden = !message.texte;
        }
    }

    function rendrePanneau() {
        var p = dom.panneau;
        if (p.hidden) return;
        vider(p);
        var f = etat.fiche, l = etat.lecture || {};
        var cle = etatPastille(f, etat.lecture);
        p.appendChild(el('h3', '', 'Module ' + etat.id));
        ligne(p, 'État', motEtat(cle));
        ligne(p, 'Politique', politique((f || l).lifecycle));
        if (f && f.sleepable && f.wake_budget_s) ligne(p, 'Réveil', '≈ ' + Math.round(f.wake_budget_s) + ' s');

        if (f) {
            p.appendChild(el('div', 'sbx-etat-titre', 'Unités'));
            var ul = el('ul', 'sbx-etat-liste');
            (f.unites || []).forEach(function (u) {
                var li = el('li');
                li.appendChild(el('span', 'nom', u.unite));
                li.appendChild(pastilleUnite(u.etat));
                if (u.etat === 'echec' && u.result && u.result !== 'success') li.title = 'Résultat : ' + u.result;
                ul.appendChild(li);
            });
            if (!(f.unites || []).length) ul.appendChild(el('li', '', 'Aucune unité déclarée.'));
            p.appendChild(ul);

            p.appendChild(el('div', 'sbx-etat-titre', 'Dépendances'));
            var ud = el('ul', 'sbx-etat-liste');
            (f.dependances || []).forEach(function (d) {
                var li = el('li');
                li.appendChild(el('span', 'nom', d.id));
                li.appendChild(pastilleModule(d.etat));
                if (d.etat === 'endormi' && d.sleepable) {
                    li.appendChild(bouton('Réveiller', 'petit prim', function () { reveiller(d.id); }));
                }
                ud.appendChild(li);
            });
            if (!(f.dependances || []).length) ud.appendChild(el('li', '', 'Aucune dépendance déclarée.'));
            p.appendChild(ud);
        } else {
            var n = el('div', 'sbx-etat-note', 'Détail des unités et des dépendances : session d\'administration requise. ');
            var a = el('a', '', 'Se connecter');
            a.href = '/login.html';
            n.appendChild(a);
            p.appendChild(n);
        }

        var actions = el('div', 'sbx-etat-actions');
        var dort = f ? f.etat === 'endormi' : l.sleep_state === 'asleep';
        if (dort) actions.appendChild(bouton('Réveiller', 'prim', function () { reveiller(etat.id); }));
        var endormable = f && f.sleepable && f.sleep_state === 'up' && f.etat === 'eveille';
        if (endormable && !etat.confirmation) {
            actions.appendChild(bouton('Endormir', 'danger', function () { etat.confirmation = true; rendrePanneau(); }));
        }
        if (endormable && etat.confirmation) {
            var q = el('div', 'sbx-etat-note', 'Endormir ' + etat.id + ' ? Le service s\'arrête jusqu\'au prochain accès ou réveil.');
            p.appendChild(q);
            actions.appendChild(bouton('Confirmer', 'danger', function () { etat.confirmation = false; endormir(etat.id); }));
            actions.appendChild(bouton('Annuler', '', function () { etat.confirmation = false; rendrePanneau(); }));
        }
        if (actions.firstChild) p.appendChild(actions);

        dom.msg = el('div', 'sbx-etat-msg');
        dom.msg.setAttribute('role', 'status');
        dom.msg.setAttribute('aria-live', 'polite');
        p.appendChild(dom.msg);
        dire(message.texte, message.classe);

        var pied = el('div', 'sbx-etat-pied');
        pied.appendChild(el('span', '', etat.releve ? 'Relevé ' + heure(etat.releve) : '—'));
        pied.appendChild(bouton('⟳', 'petit', function () { dire('', ''); actualiser(); }));
        p.appendChild(pied);
    }

    // ── Badge « HORS LIGNE » de la page ───────────────────────────────────
    var badges = [];
    function trouverBadges() {
        var l = [], vus = [];
        var sel = '#etat, .tete .actif, .tete .pastille, .tete .pill, header .actif';
        document.querySelectorAll(sel).forEach(function (b) {
            if (vus.indexOf(b) < 0 && !b.closest('.sbx-etat')) { vus.push(b); l.push(b); }
        });
        return l;
    }

    function estHorsLigne(b) { return /hors[\s -]*ligne/i.test(b.textContent || ''); }

    function rendreRaison(b) {
        var r = b._sbxRaison;
        if (!r) {
            r = el('span', 'sbx-etat-raison');
            r.setAttribute('aria-live', 'polite');
            b.parentNode.insertBefore(r, b.nextSibling);
            b._sbxRaison = r;
        }
        if (!estHorsLigne(b) || (!etat.fiche && !etat.lecture)) { r.hidden = true; return; }
        vider(r);
        var raison = raisonHorsLigne(etat.fiche, etat.lecture);
        r.appendChild(el('span', '', 'Raison :'));
        r.appendChild(el('b', '', raison.texte));
        if (raison.reveiller) {
            r.appendChild(bouton('Réveiller', 'petit prim', function () {
                if (dom.panneau.hidden) ouvrir();
                reveiller(raison.reveiller);
            }));
        }
        r.hidden = false;
    }

    function rendreRaisons() { badges.forEach(function (b) { if (b.parentNode) rendreRaison(b); }); }

    function surveillerBadges() {
        badges = trouverBadges();
        if (typeof MutationObserver === 'undefined') return;
        badges.forEach(function (b) {
            new MutationObserver(function () { rendreRaison(b); })
                .observe(b, { childList: true, characterData: true, subtree: true, attributes: true, attributeFilter: ['class', 'hidden'] });
        });
    }

    // ── Données ───────────────────────────────────────────────────────────
    function lireLifecycles() {
        return appel('GET', API + '/lifecycles').then(function (r) {
            return r.ok && r.data && Array.isArray(r.data.lifecycles) ? r.data.lifecycles : null;
        });
    }

    function actualiser() {
        if (!etat.id) return Promise.resolve();
        return Promise.all([
            appel('GET', API + '/module/' + encodeURIComponent(etat.id)),
            lireLifecycles()
        ]).then(function (res) {
            var r = res[0], lcs = res[1];
            if (lcs) {
                var l = choisirModule([etat.id], lcs);
                if (l) etat.lecture = l;
            }
            if (r.ok && r.data && r.data.id === etat.id) { etat.fiche = r.data; etat.mode = 'admin'; }
            else if (r.code === 401 || r.code === 403) { etat.fiche = null; etat.mode = 'lecture'; }
            etat.releve = new Date();
            rendrePuce();
            rendrePanneau();
            rendreRaisons();
        });
    }

    function geste(nom, id) {
        if (etat.occupe) return;
        etat.occupe = true;
        var budget = etat.fiche && etat.fiche.wake_budget_s;
        dire(nom === 'wake' ? 'Réveil de ' + id + ' en cours…' + (budget ? ' (jusqu\'à ≈ ' + Math.round(budget) + ' s)' : '')
                            : 'Mise en sommeil de ' + id + ' en cours…', '');
        rendrePanneau();
        appel('POST', API + '/' + nom, { module: id }, 300000).then(function (r) {
            if (r.ok) {
                var m = messageRapport(nom, r.data, id);
                dire(m.texte, m.classe);
                // Geste abouti : la page relit aussi ses propres données (son badge « HORS LIGNE » n'a plus lieu d'être).
                if (m.classe === 'ok') {
                    var b = boutonActualiser(zoneEntete());
                    if (b && !b.disabled) b.click();
                }
            } else {
                dire(messageHttp(r.code, r.data && r.data.detail), 'ko');
            }
        }).then(function () {
            etat.occupe = false;
            return actualiser();
        });
    }
    function reveiller(id) { geste('wake', id); }
    function endormir(id) { geste('sleep', id); }

    function demarrer() {
        var explicite = moduleExplicite();
        lireLifecycles().then(function (lcs) {
            if (!lcs) return;
            var l = choisirModule(candidatsModule(location.pathname, menuConnu(), explicite), lcs);
            if (!l) return;
            etat.id = l.id;
            etat.lecture = l;
            chargerFeuille();
            if (!placer(construire())) return;
            rendrePuce();
            surveillerBadges();
            rendreRaisons();
            actualiser();
            var b = boutonActualiser(zoneEntete());
            if (b) b.addEventListener('click', function () { if (!etat.occupe) actualiser(); });
            setInterval(function () {
                if (!document.hidden && !etat.confirmation && !etat.occupe) actualiser();
            }, 60000);
        });
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', demarrer);
    else demarrer();
})(typeof window !== 'undefined' ? window : null);
