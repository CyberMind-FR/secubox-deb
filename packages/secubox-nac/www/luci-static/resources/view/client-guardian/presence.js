'use strict';
'require view';
'require dom';
'require ui';
'require secubox/kiss-theme';
'require client-guardian/nav as CgNav';
'require secubox-portal/header as SbHeader';

// #820 Task 8 — cross-plane "Presence" view (Project B: Cross-plane
// Presence Guardian). Renders WAN/LAN/WG/kbin presences fetched from
// GET /presence (+ aggregate GET /presence/geo and GET /presence/alerts).
//
// SECURITY: every presence field is attacker-influenceable — geo_cc/
// geo_asn/geo_org come from mmdb lookups keyed on a client-controlled IP,
// identity/device_mac/provenance/client_type are learned from untrusted
// network traffic, and `extra` is a JSON string that may carry a raw
// WAN request Host header / User-Agent (`extra.host`/`extra.ua`) or a
// kbin report token (`extra.report_token`). LuCI's dom.append() only
// renders a string child as a safe Text node when it is wrapped in an
// ARRAY — a BARE (non-array) string 3rd argument to E() is instead
// assigned to `node.innerHTML` and HTML-parsed. Every dynamic value in
// this file is therefore always passed to E() wrapped in an array (e.g.
// `E('div', {}, [value])`), never as a bare 3rd argument, so it can only
// ever become inert text — this file NEVER builds innerHTML/
// insertAdjacentHTML directly from a presence-derived value either.
// `extra` is parsed with JSON.parse (never eval) inside a try/catch that
// falls back to `{}` on any malformed or unexpected payload.

async function callGetPresence(params) {
	return sbxFetch('/api/v1/nac/presence', params, 'GET');
}

async function callGetPresenceGeo() {
	return sbxFetch('/api/v1/nac/presence/geo', null, 'GET');
}

async function callGetPresenceAlerts() {
	return sbxFetch('/api/v1/nac/presence/alerts', null, 'GET');
}

var PLANE_META = {
	wan: { icon: '🌐', label: 'WAN', badge: 'kiss-badge-blue' },
	lan: { icon: '🏠', label: 'LAN', badge: 'kiss-badge-green' },
	wg: { icon: '🔒', label: 'WG', badge: 'kiss-badge-yellow' },
	kbin: { icon: '🎭', label: 'kbin', badge: 'kiss-badge-red' }
};

var CLIENTS_PATH = ['admin', 'secubox', 'security', 'guardian', 'clients'];

function fmtOrDash(value) {
	if (value === null || value === undefined || value === '') return '—';
	return String(value);
}

function planeMeta(plane) {
	return PLANE_META[plane] || { icon: '❔', label: fmtOrDash(plane), badge: 'kiss-badge-blue' };
}

function tierBadgeClass(tier) {
	switch (String(tier || '').toLowerCase()) {
		case 'critical': return 'kiss-badge-red';
		case 'warn':
		case 'warning': return 'kiss-badge-yellow';
		case 'notice': return 'kiss-badge-green';
		case 'info':
		default: return 'kiss-badge-blue';
	}
}

// Parses the `extra` column (a JSON string produced by the collectors —
// see presence/wan.py, presence/local.py, presence/kbin.py). JSON.parse
// cannot execute code, and any failure (malformed/unexpected payload)
// degrades to an empty object rather than raising or falling back to a
// raw-string render.
function parseExtra(raw) {
	if (!raw) return {};
	if (typeof raw === 'object') return raw;
	try {
		var obj = JSON.parse(raw);
		return (obj && typeof obj === 'object') ? obj : {};
	} catch (e) {
		return {};
	}
}

// Converts a 2-letter ISO country code into a flag emoji via regional
// indicator code points. Never builds markup — String.fromCodePoint only
// ever produces a short unicode text string, and the input is validated
// against /^[A-Z]{2}$/ first so garbage input just yields ''.
function countryFlag(cc) {
	if (!cc || typeof cc !== 'string') return '';
	var code = cc.trim().toUpperCase();
	if (!/^[A-Z]{2}$/.test(code)) return '';
	var offset = 127397;
	return String.fromCodePoint(code.charCodeAt(0) + offset, code.charCodeAt(1) + offset);
}

function fmtAge(lastSeenEpoch) {
	if (!lastSeenEpoch) return '—';
	var now = Math.floor(Date.now() / 1000);
	var diff = Math.max(0, now - Number(lastSeenEpoch));
	if (diff < 60) return diff + 's';
	if (diff < 3600) return Math.floor(diff / 60) + 'm';
	if (diff < 86400) return Math.floor(diff / 3600) + 'h';
	return Math.floor(diff / 86400) + 'j';
}

function fmtTs(epoch) {
	if (!epoch) return '—';
	try {
		return new Date(Number(epoch) * 1000).toLocaleString();
	} catch (e) {
		return '—';
	}
}

return view.extend({
	load: function() {
		return Promise.all([
			callGetPresence(),
			callGetPresenceGeo(),
			callGetPresenceAlerts()
		]);
	},

	render: function(data) {
		var presenceData = data[0] || {};
		var items = Array.isArray(presenceData) ? presenceData : (presenceData.items || []);
		var geoData = data[1] || {};
		var alertsData = data[2] || {};
		var alerts = Array.isArray(alertsData) ? alertsData : (alertsData.alerts || []);

		var planeCounts = { wan: 0, lan: 0, wg: 0, kbin: 0 };
		items.forEach(function(item) {
			if (Object.prototype.hasOwnProperty.call(planeCounts, item.plane)) {
				planeCounts[item.plane]++;
			}
		});

		var content = [
			E('link', { 'rel': 'stylesheet', 'href': L.resource('client-guardian/dashboard.css') }),

			E('div', { 'style': 'display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;' }, [
				E('div', {}, [
					E('h2', { 'style': 'margin: 0 0 4px 0;' }, 'Présence Cross-Plane'),
					E('div', { 'style': 'color: var(--kiss-muted);' }, 'Client Guardian — WAN / LAN / WG / kbin')
				]),
				E('button', {
					'class': 'kiss-btn kiss-btn-green',
					'click': L.bind(this.handleRefresh, this)
				}, 'Actualiser')
			]),

			CgNav.renderTabs('presence'),

			E('p', { 'style': 'color: var(--kiss-muted); margin-bottom: 24px' },
				'Vue unifiée des identités vues sur chaque plan (visiteurs WAN, appareils LAN/WireGuard, personas kbin R3), avec origine géo/ASN et niveau de risque (tier).'
			),

			E('div', { 'class': 'kiss-grid kiss-grid-auto', 'style': 'margin-bottom: 20px' }, [
				this.renderFilterTab('all', 'Tous', items.length, true),
				this.renderFilterTab('wan', 'WAN', planeCounts.wan),
				this.renderFilterTab('lan', 'LAN', planeCounts.lan),
				this.renderFilterTab('wg', 'WireGuard', planeCounts.wg),
				this.renderFilterTab('kbin', 'kbin', planeCounts.kbin)
			]),

			E('div', { 'class': 'kiss-grid', 'style': 'grid-template-columns: 2fr 1fr; gap: 20px; align-items: start;' }, [
				E('div', { 'class': 'kiss-card' }, [
					E('div', { 'class': 'kiss-card-title' }, [
						'Présences',
						E('span', { 'class': 'kiss-badge kiss-badge-blue', 'style': 'margin-left: 12px;', 'id': 'presence-count-badge' }, [items.length + ' total'])
					]),
					E('div', { 'style': 'overflow-x: auto;' }, [
						E('table', { 'class': 'kiss-table', 'id': 'presence-table' }, [
							E('thead', {}, E('tr', {}, [
								E('th', {}, 'Plan'),
								E('th', {}, 'Identité'),
								E('th', {}, 'Origine'),
								E('th', {}, 'Type'),
								E('th', {}, 'Hits'),
								E('th', {}, 'Tier'),
								E('th', {}, 'Âge'),
								E('th', {}, 'Lien')
							])),
							E('tbody', { 'id': 'presence-tbody' },
								items.length
									? items.map(L.bind(this.renderPresenceRow, this))
									: [E('tr', {}, E('td', { 'colspan': '8', 'style': 'text-align: center; color: var(--kiss-muted); padding: 20px;' }, 'Aucune présence enregistrée.'))]
							)
						])
					])
				]),

				E('div', { 'style': 'display: flex; flex-direction: column; gap: 20px;' }, [
					this.renderGeoPanel(geoData),
					this.renderAlertsPanel(alerts)
				])
			])
		];

		return KissTheme.wrap(content, 'client-guardian/presence');
	},

	renderFilterTab: function(filter, label, count, active) {
		var tab = E('div', {
			'class': 'kiss-stat' + (active ? ' kiss-panel-green' : ''),
			'data-filter': filter,
			'style': 'cursor: pointer; transition: all 0.2s;'
		}, [
			E('div', { 'class': 'kiss-stat-value' }, [String(count)]),
			E('div', { 'class': 'kiss-stat-label' }, [label])
		]);

		tab.addEventListener('click', L.bind(this.handleFilter, this));
		return tab;
	},

	renderPresenceRow: function(item) {
		var meta = planeMeta(item.plane);
		var extra = parseExtra(item.extra);

		var identityCell = [
			E('div', { 'style': 'font-family: monospace; font-size: 12px;' }, [fmtOrDash(item.identity)])
		];
		// extra.host / extra.ua are attacker-influenceable (WAN Host header /
		// User-Agent) — always array-wrapped so E()/dom.append renders them
		// as their own inert Text node, never merged into a bigger markup
		// string and never assigned to innerHTML as a bare string.
		if (extra.host) {
			identityCell.push(E('div', { 'style': 'font-size: 11px; color: var(--kiss-muted);', 'title': 'Host' }, [String(extra.host)]));
		}
		if (extra.ua) {
			identityCell.push(E('div', { 'style': 'font-size: 11px; color: var(--kiss-muted);', 'title': 'User-Agent' }, [String(extra.ua)]));
		}
		if (extra.category) {
			identityCell.push(E('span', { 'class': 'kiss-badge kiss-badge-blue', 'style': 'font-size: 10px; margin-top: 2px; display: inline-block;' }, [String(extra.category)]));
		}

		var originCell;
		if (item.geo_cc) {
			var originParts = [countryFlag(item.geo_cc) + ' ', String(item.geo_cc)];
			if (item.geo_asn) originParts.push(' · ' + String(item.geo_asn));
			originCell = E('div', {}, [
				E('span', {}, originParts),
				item.geo_org ? E('div', { 'style': 'font-size: 11px; color: var(--kiss-muted);' }, [String(item.geo_org)]) : E('span')
			]);
		} else {
			originCell = E('span', { 'class': 'kiss-badge kiss-badge-blue', 'title': 'Provenance' }, [fmtOrDash(item.provenance)]);
		}

		var linkCell;
		if ((item.plane === 'lan' || item.plane === 'wg') && item.device_mac) {
			var clientsHref = L.url.apply(L, CLIENTS_PATH) + '?mac=' + encodeURIComponent(item.device_mac);
			linkCell = E('a', { 'href': clientsHref, 'class': 'kiss-btn', 'style': 'padding: 2px 8px; font-size: 11px;', 'title': 'Voir dans Clients (Project A)' }, '👥 Client');
		} else if (item.plane === 'kbin') {
			var token = extra.report_token;
			var kbinHref = token
				? ('/report/' + encodeURIComponent(String(token)))
				: ('/report/me?mh=' + encodeURIComponent(String(item.identity || '')));
			linkCell = E('a', {
				'href': kbinHref,
				'target': '_blank',
				'rel': 'noopener noreferrer',
				'class': 'kiss-btn',
				'style': 'padding: 2px 8px; font-size: 11px;',
				'title': token ? 'Rapport kbin (token)' : 'Rapport kbin (mac_hash, best-effort)'
			}, '📄 Rapport');
		} else {
			linkCell = E('span', { 'style': 'color: var(--kiss-muted);' }, '—');
		}

		return E('tr', { 'data-plane': item.plane || '' }, [
			E('td', {}, E('span', { 'class': 'kiss-badge ' + meta.badge }, [meta.icon + ' ' + meta.label])),
			E('td', {}, identityCell),
			E('td', {}, originCell),
			E('td', {}, [fmtOrDash(item.client_type)]),
			E('td', { 'style': 'font-family: monospace;' }, [String(item.hits || 0)]),
			E('td', {}, E('span', { 'class': 'kiss-badge ' + tierBadgeClass(item.tier) }, [fmtOrDash(item.tier)])),
			E('td', { 'style': 'color: var(--kiss-muted); font-size: 12px;' }, [fmtAge(item.last_seen)]),
			E('td', {}, linkCell)
		]);
	},

	renderGeoPanel: function(geoData) {
		var byCountry = (geoData && geoData.by_country) || {};
		var byAsn = (geoData && geoData.by_asn) || {};

		var countries = Object.keys(byCountry).map(function(cc) {
			return { cc: cc, n: byCountry[cc] };
		}).sort(function(a, b) { return b.n - a.n; }).slice(0, 10);

		var asns = Object.keys(byAsn).map(function(asn) {
			return { asn: asn, n: byAsn[asn] };
		}).sort(function(a, b) { return b.n - a.n; }).slice(0, 10);

		return E('div', { 'class': 'kiss-card' }, [
			E('div', { 'class': 'kiss-card-title' }, 'Géo / ASN'),
			E('div', { 'style': 'font-size: 12px; font-weight: 700; color: var(--kiss-muted); margin: 8px 0 4px;' }, 'Top pays'),
			E('div', {},
				countries.length
					? countries.map(function(c) {
						return E('div', { 'style': 'display: flex; justify-content: space-between; padding: 3px 0;' }, [
							E('span', {}, [countryFlag(c.cc) + ' ', String(c.cc)]),
							E('span', { 'class': 'kiss-badge kiss-badge-blue' }, [String(c.n)])
						]);
					})
					: [E('div', { 'style': 'color: var(--kiss-muted); font-size: 12px;' }, 'Aucune donnée.')]
			),
			E('div', { 'style': 'font-size: 12px; font-weight: 700; color: var(--kiss-muted); margin: 12px 0 4px;' }, 'Top ASN'),
			E('div', {},
				asns.length
					? asns.map(function(a) {
						return E('div', { 'style': 'display: flex; justify-content: space-between; padding: 3px 0;' }, [
							E('span', { 'style': 'font-family: monospace; font-size: 12px;' }, [String(a.asn)]),
							E('span', { 'class': 'kiss-badge kiss-badge-blue' }, [String(a.n)])
						]);
					})
					: [E('div', { 'style': 'color: var(--kiss-muted); font-size: 12px;' }, 'Aucune donnée.')]
			)
		]);
	},

	renderAlertsPanel: function(alerts) {
		var recent = (alerts || []).slice(0, 15);

		return E('div', { 'class': 'kiss-card' }, [
			E('div', { 'class': 'kiss-card-title' }, [
				'Alertes',
				E('span', { 'class': 'kiss-badge kiss-badge-blue', 'style': 'margin-left: 12px;' }, [String((alerts || []).length)])
			]),
			E('div', { 'style': 'max-height: 320px; overflow-y: auto;' },
				recent.length
					? recent.map(function(a) {
						return E('div', { 'style': 'padding: 6px 0; border-bottom: 1px solid var(--kiss-border, rgba(128,128,128,0.2));' }, [
							E('div', { 'style': 'display: flex; justify-content: space-between; align-items: center;' }, [
								E('span', { 'class': 'kiss-badge ' + tierBadgeClass(a.tier) }, [fmtOrDash(a.tier)]),
								E('span', { 'style': 'font-size: 11px; color: var(--kiss-muted);' }, [fmtTs(a.ts)])
							]),
							E('div', { 'style': 'font-size: 12px; margin-top: 2px;' }, [
								E('span', { 'style': 'font-weight: 700;' }, [fmtOrDash(a.plane)]),
								': ',
								fmtOrDash(a.detail)
							])
						]);
					})
					: [E('div', { 'style': 'color: var(--kiss-muted); font-size: 12px;' }, 'Aucune alerte enregistrée.')]
			)
		]);
	},

	handleFilter: function(ev) {
		var filter = ev.currentTarget.dataset.filter;
		var rows = document.querySelectorAll('#presence-tbody tr');
		var tabs = document.querySelectorAll('.kiss-stat');

		tabs.forEach(function(t) { t.classList.remove('kiss-panel-green'); });
		ev.currentTarget.classList.add('kiss-panel-green');

		rows.forEach(function(row) {
			var plane = row.dataset.plane;
			var show = (filter === 'all') || (plane === filter);
			row.style.display = show ? '' : 'none';
		});
	},

	handleRefresh: function() {
		return Promise.all([
			callGetPresence(),
			callGetPresenceGeo(),
			callGetPresenceAlerts()
		]).then(L.bind(function(data) {
			var container = document.querySelector('.kiss-main');
			if (container) {
				var newView = this.render(data);
				dom.content(container.parentNode, newView);
			}
		}, this)).catch(function(err) {
			console.error('Failed to refresh presence list:', err);
		});
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
