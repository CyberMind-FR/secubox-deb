// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

'use strict';
'require view';
'require dom';
'require poll';
'require ui';
'require client-guardian/api as API';
'require client-guardian/nav as CgNav';
'require secubox-portal/header as SbHeader';
'require secubox/kiss-theme';

return view.extend({
	refreshInterval: 5000,

	load: function() {
		return API.getLogs(100, null);
	},

	render: function(data) {
		var logs = data.logs || [];
		var self = this;

		// Main wrapper with SecuBox header
		var wrapper = E('div', { 'class': 'secubox-page-wrapper' });
		wrapper.appendChild(SbHeader.render());

		var view = E('div', { 'class': 'client-guardian-dashboard' }, [
			E('link', { 'rel': 'stylesheet', 'href': L.resource('secubox-theme/secubox-theme.css') }),
			E('link', { 'rel': 'stylesheet', 'href': L.resource('client-guardian/dashboard.css') }),
			CgNav.renderTabs('logs'),

			// Filters
			E('div', { 'class': 'cg-card' }, [
				E('div', { 'class': 'cg-card-header' }, [
					E('div', { 'class': 'cg-card-title' }, [
						E('span', { 'class': 'cg-card-title-icon' }, '🔍'),
						'Filtres'
					])
				]),
				E('div', { 'class': 'cg-card-body' }, [
					E('div', { 'style': 'display: flex; gap: 16px; flex-wrap: wrap; align-items: flex-end;' }, [
						E('div', { 'class': 'cg-form-group', 'style': 'margin: 0; flex: 1; min-width: 150px;' }, [
							E('label', { 'class': 'cg-form-label' }, 'Niveau'),
							E('select', { 'class': 'cg-select', 'id': 'filter-level', 'change': L.bind(this.filterLogs, this) }, [
								E('option', { 'value': '' }, 'Tous'),
								E('option', { 'value': 'info' }, '📝 Info'),
								E('option', { 'value': 'warning' }, '⚠️ Warning'),
								E('option', { 'value': 'error' }, '🚨 Error')
							])
						]),
						E('div', { 'class': 'cg-form-group', 'style': 'margin: 0; flex: 2; min-width: 200px;' }, [
							E('label', { 'class': 'cg-form-label' }, 'Recherche'),
							E('input', { 
								'type': 'text', 
								'class': 'cg-input', 
								'id': 'filter-search',
								'placeholder': 'Rechercher dans les logs...',
								'keyup': L.bind(this.filterLogs, this)
							})
						]),
						E('div', { 'class': 'cg-form-group', 'style': 'margin: 0;' }, [
							E('label', { 'class': 'cg-form-label' }, 'Limite'),
							E('select', { 'class': 'cg-select', 'id': 'filter-limit', 'change': L.bind(this.reloadLogs, this) }, [
								E('option', { 'value': '50' }, '50 lignes'),
								E('option', { 'value': '100', 'selected': true }, '100 lignes'),
								E('option', { 'value': '200' }, '200 lignes'),
								E('option', { 'value': '500' }, '500 lignes')
							])
						]),
						E('button', { 
							'class': 'cg-btn',
							'click': L.bind(this.reloadLogs, this)
						}, [ '🔄 Rafraîchir' ]),
						E('button', { 
							'class': 'cg-btn',
							'click': L.bind(this.exportLogs, this)
						}, [ '📥 Exporter' ])
					])
				])
			]),
			
			// Stats
			E('div', { 'class': 'cg-stats-grid', 'style': 'grid-template-columns: repeat(4, 1fr);' }, [
				E('div', { 'class': 'cg-stat-card' }, [
					E('div', { 'class': 'cg-stat-icon' }, '📋'),
					E('div', { 'class': 'cg-stat-value', 'id': 'stat-total' }, logs.length.toString()),
					E('div', { 'class': 'cg-stat-label' }, 'Total')
				]),
				E('div', { 'class': 'cg-stat-card' }, [
					E('div', { 'class': 'cg-stat-icon' }, '📝'),
					E('div', { 'class': 'cg-stat-value', 'id': 'stat-info', 'style': 'color: #3b82f6;' }, 
						logs.filter(function(l) { return l.level === 'info'; }).length.toString()),
					E('div', { 'class': 'cg-stat-label' }, 'Info')
				]),
				E('div', { 'class': 'cg-stat-card' }, [
					E('div', { 'class': 'cg-stat-icon' }, '⚠️'),
					E('div', { 'class': 'cg-stat-value', 'id': 'stat-warning', 'style': 'color: #f59e0b;' }, 
						logs.filter(function(l) { return l.level === 'warning'; }).length.toString()),
					E('div', { 'class': 'cg-stat-label' }, 'Warning')
				]),
				E('div', { 'class': 'cg-stat-card' }, [
					E('div', { 'class': 'cg-stat-icon' }, '🚨'),
					E('div', { 'class': 'cg-stat-value', 'id': 'stat-error', 'style': 'color: #ef4444;' }, 
						logs.filter(function(l) { return l.level === 'error'; }).length.toString()),
					E('div', { 'class': 'cg-stat-label' }, 'Error')
				])
			]),
			
			// Logs List
			E('div', { 'class': 'cg-card' }, [
				E('div', { 'class': 'cg-card-header' }, [
					E('div', { 'class': 'cg-card-title' }, [
						E('span', { 'class': 'cg-card-title-icon' }, '📋'),
						'Journal d\'Événements'
					]),
					E('div', { 'class': 'cg-card-badge', 'id': 'logs-count' }, logs.length + ' entrées')
				]),
				E('div', { 'class': 'cg-card-body' }, [
					E('div', { 'class': 'cg-log-list', 'id': 'logs-container' }, 
						this.renderLogs(logs)
					)
				])
			])
		]);

		// Setup auto-refresh
		poll.add(L.bind(this.pollLogs, this), this.refreshInterval);

		wrapper.appendChild(view);
		return KissTheme.wrap(wrapper, 'admin/secubox/guardian/logs');
	},

	renderLogs: function(logs) {
		if (!logs || logs.length === 0) {
			return E('div', { 'class': 'cg-empty-state' }, [
				E('div', { 'class': 'cg-empty-state-icon' }, '📋'),
				E('div', { 'class': 'cg-empty-state-title' }, 'Aucun log disponible'),
				E('div', { 'class': 'cg-empty-state-text' }, 'Les événements apparaîtront ici')
			]);
		}

		return logs.map(function(log) {
			return E('div', { 'class': 'cg-log-item', 'data-level': log.level }, [
				E('div', { 'class': 'cg-log-time' }, log.timestamp || 'N/A'),
				E('div', { 'class': 'cg-log-level ' + log.level }, log.level),
				E('div', { 'class': 'cg-log-message' }, log.message)
			]);
		});
	},

	filterLogs: function() {
		var level = document.getElementById('filter-level').value;
		var search = document.getElementById('filter-search').value.toLowerCase();
		var items = document.querySelectorAll('.cg-log-item');
		var visible = 0;

		items.forEach(function(item) {
			var itemLevel = item.dataset.level;
			var itemText = item.textContent.toLowerCase();
			var show = true;

			if (level && itemLevel !== level) show = false;
			if (search && !itemText.includes(search)) show = false;

			item.style.display = show ? '' : 'none';
			if (show) visible++;
		});

		document.getElementById('logs-count').textContent = visible + ' entrées affichées';
	},

	reloadLogs: function() {
		var self = this;
		var limit = parseInt(document.getElementById('filter-limit').value);

		ui.showModal(_('Chargement'), [
			E('p', {}, 'Chargement des logs...'),
			E('div', { 'class': 'spinning' })
		]);

		API.getLogs(limit, null).then(function(data) {
			var container = document.getElementById('logs-container');
			var logs = data.logs || [];
			
			dom.content(container, self.renderLogs(logs));
			
			// Update stats
			document.getElementById('stat-total').textContent = logs.length;
			document.getElementById('stat-info').textContent = logs.filter(function(l) { return l.level === 'info'; }).length;
			document.getElementById('stat-warning').textContent = logs.filter(function(l) { return l.level === 'warning'; }).length;
			document.getElementById('stat-error').textContent = logs.filter(function(l) { return l.level === 'error'; }).length;
			document.getElementById('logs-count').textContent = logs.length + ' entrées';
			
			ui.hideModal();
			self.filterLogs();
		});
	},

	pollLogs: function() {
		var self = this;
		var limit = parseInt(document.getElementById('filter-limit')?.value || 100);

		return API.getLogs(limit, null).then(function(data) {
			var container = document.getElementById('logs-container');
			if (!container) return;
			
			var logs = data.logs || [];
			var currentCount = container.querySelectorAll('.cg-log-item').length;
			
			// Only update if count changed
			if (logs.length !== currentCount) {
				dom.content(container, self.renderLogs(logs));
				document.getElementById('stat-total').textContent = logs.length;
				document.getElementById('stat-info').textContent = logs.filter(function(l) { return l.level === 'info'; }).length;
				document.getElementById('stat-warning').textContent = logs.filter(function(l) { return l.level === 'warning'; }).length;
				document.getElementById('stat-error').textContent = logs.filter(function(l) { return l.level === 'error'; }).length;
				document.getElementById('logs-count').textContent = logs.length + ' entrées';
				self.filterLogs();
			}
		});
	},

	exportLogs: function() {
		var items = document.querySelectorAll('.cg-log-item');
		var csv = 'Timestamp,Level,Message\n';
		
		items.forEach(function(item) {
			if (item.style.display !== 'none') {
				var time = item.querySelector('.cg-log-time').textContent;
				var level = item.querySelector('.cg-log-level').textContent;
				var message = item.querySelector('.cg-log-message').textContent.replace(/"/g, '""');
				csv += '"' + time + '","' + level + '","' + message + '"\n';
			}
		});

		var blob = new Blob([csv], { type: 'text/csv' });
		var url = URL.createObjectURL(blob);
		var a = document.createElement('a');
		a.href = url;
		a.download = 'client-guardian-logs-' + new Date().toISOString().slice(0,10) + '.csv';
		a.click();
		URL.revokeObjectURL(url);

		ui.addNotification(null, E('p', {}, '✅ Logs exportés!'), 'success');
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
