'use strict';
'require view';
'require dom';
'require ui';
'require secubox/kiss-theme';
'require client-guardian/nav as CgNav';
'require secubox-portal/header as SbHeader';

// #817 Task 8 — device groups view (mac-guard/device-intel absorption).
// Lists groups from GET /groups, creates via POST /groups, deletes via
// DELETE /groups/{id}, and assigns a device (by MAC) to a group via
// POST /groups/{id}/members. Every rendered field (group name/description,
// device hostname/mac/vendor) is attacker-influenceable and is always
// passed to E() as a text child, never concatenated into innerHTML.

async function callGetGroups(params) {
	return sbxFetch('/api/v1/nac/groups', params, 'GET');
}

async function callGetClients(params) {
	return sbxFetch('/api/v1/nac/clients', params, 'GET');
}

async function callCreateGroup(params) {
	return sbxFetch('/api/v1/nac/groups', params, 'POST');
}

async function callDeleteGroup(groupId) {
	return sbxFetch('/api/v1/nac/groups/' + encodeURIComponent(groupId), null, 'DELETE');
}

async function callAssignDevice(groupId, mac) {
	return sbxFetch('/api/v1/nac/groups/' + encodeURIComponent(groupId) + '/members', { mac: mac }, 'POST');
}

function fmtOrDash(value) {
	if (value === null || value === undefined || value === '') return '—';
	return String(value);
}

return view.extend({
	load: function() {
		return Promise.all([
			callGetGroups(),
			callGetClients()
		]);
	},

	render: function(data) {
		var groupsData = data[0] || {};
		var groups = Array.isArray(groupsData) ? groupsData : (groupsData.groups || []);
		var clientsData = data[1] || {};
		var clients = Array.isArray(clientsData) ? clientsData : (clientsData.clients || []);
		var self = this;

		var content = [
			E('link', { 'rel': 'stylesheet', 'href': L.resource('client-guardian/dashboard.css') }),

			E('div', { 'style': 'display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;' }, [
				E('div', {}, [
					E('h2', { 'style': 'margin: 0 0 4px 0;' }, 'Groupes d\'Appareils'),
					E('div', { 'style': 'color: var(--kiss-muted);' }, 'Client Guardian')
				]),
				E('button', {
					'class': 'kiss-btn kiss-btn-green',
					'click': L.bind(this.handleCreateGroup, this, clients)
				}, '+ Nouveau Groupe')
			]),

			CgNav.renderTabs('groups'),

			E('p', { 'style': 'color: var(--kiss-muted); margin-bottom: 24px' },
				'Organisez vos appareils en groupes (ex: "Appareils IoT", "Invites") pour faciliter la gestion et les rapports.'
			),

			E('div', { 'class': 'kiss-grid kiss-grid-auto', 'id': 'groups-list' },
				groups.length
					? groups.map(L.bind(this.renderGroupCard, this, clients))
					: [E('div', { 'class': 'kiss-card' }, 'Aucun groupe pour le moment.')]
			)
		];

		return KissTheme.wrap(content, 'client-guardian/groups');
	},

	renderGroupCard: function(clients, group) {
		var self = this;
		var color = group.color || '#3498db';
		var members = Array.isArray(group.members) ? group.members : [];

		var memberRows = members.map(function(mac) {
			var c = clients.filter(function(cl) { return cl.mac === mac; })[0];
			var label = c ? (c.hostname || c.name || mac) : mac;
			return E('div', { 'style': 'display: flex; justify-content: space-between; padding: 4px 0; font-size: 12px;' }, [
				E('span', {}, label),
				E('span', { 'style': 'color: var(--kiss-muted); font-family: monospace;' }, mac)
			]);
		});

		return E('div', {
			'class': 'kiss-card',
			'style': 'border-left: 3px solid ' + color + ';'
		}, [
			E('div', { 'style': 'display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;' }, [
				E('div', {}, [
					E('div', { 'style': 'font-weight: 700; font-size: 16px;' }, fmtOrDash(group.name)),
					E('div', { 'style': 'color: var(--kiss-muted); font-size: 12px;' }, fmtOrDash(group.description))
				]),
				E('span', { 'class': 'kiss-badge kiss-badge-blue' }, String(group.member_count || members.length || 0) + ' appareil(s)')
			]),
			E('div', { 'style': 'max-height: 160px; overflow-y: auto; margin-bottom: 12px;' },
				memberRows.length ? memberRows : [E('div', { 'style': 'color: var(--kiss-muted); font-size: 12px;' }, 'Aucun appareil assigne.')]
			),
			E('div', { 'class': 'cg-btn-group', 'style': 'gap: 8px;' }, [
				E('button', {
					'class': 'kiss-btn',
					'click': L.bind(this.handleAssignDevice, this, group, clients)
				}, 'Assigner'),
				E('button', {
					'class': 'kiss-btn kiss-btn-danger',
					'click': L.bind(this.handleDeleteGroup, this, group)
				}, 'Supprimer')
			])
		]);
	},

	handleCreateGroup: function(clients, ev) {
		var self = this;

		ui.showModal(_('Nouveau Groupe'), [
			E('div', { 'class': 'cg-form-group' }, [
				E('label', { 'class': 'cg-form-label' }, 'Nom du groupe'),
				E('input', { 'type': 'text', 'id': 'group-name', 'class': 'cg-input', 'placeholder': 'Ex: Appareils IoT' })
			]),
			E('div', { 'class': 'cg-form-group' }, [
				E('label', { 'class': 'cg-form-label' }, 'Description'),
				E('input', { 'type': 'text', 'id': 'group-description', 'class': 'cg-input', 'placeholder': 'Optionnel' })
			]),
			E('div', { 'class': 'cg-form-group' }, [
				E('label', { 'class': 'cg-form-label' }, 'Couleur'),
				E('input', { 'type': 'color', 'id': 'group-color', 'class': 'cg-input', 'value': '#3498db' })
			]),
			E('div', { 'class': 'cg-btn-group', 'style': 'justify-content: flex-end' }, [
				E('button', { 'class': 'cg-btn', 'click': ui.hideModal }, _('Annuler')),
				E('button', { 'class': 'cg-btn cg-btn-success', 'click': L.bind(function() {
					var name = document.getElementById('group-name').value;
					if (!name) return;
					var description = document.getElementById('group-description').value;
					var color = document.getElementById('group-color').value;
					callCreateGroup({ name: name, description: description, color: color }).then(L.bind(function() {
						ui.hideModal();
						ui.addNotification(null, E('p', {}, _('Group created successfully')), 'success');
						this.handleRefresh();
					}, this));
				}, this) }, _('Creer'))
			])
		]);
	},

	handleAssignDevice: function(group, clients, ev) {
		var self = this;

		ui.showModal(_('Assigner un appareil a ') + fmtOrDash(group.name), [
			E('div', { 'class': 'cg-form-group' }, [
				E('label', { 'class': 'cg-form-label' }, 'Appareil'),
				E('select', { 'id': 'assign-mac', 'class': 'cg-input' },
					clients.map(function(c) {
						return E('option', { 'value': c.mac }, (c.hostname || c.name || c.mac) + ' (' + c.mac + ')');
					})
				)
			]),
			E('div', { 'class': 'cg-btn-group', 'style': 'justify-content: flex-end' }, [
				E('button', { 'class': 'cg-btn', 'click': ui.hideModal }, _('Annuler')),
				E('button', { 'class': 'cg-btn cg-btn-primary', 'click': L.bind(function() {
					var mac = document.getElementById('assign-mac').value;
					callAssignDevice(group.id, mac).then(L.bind(function() {
						ui.hideModal();
						ui.addNotification(null, E('p', {}, _('Device assigned successfully')), 'success');
						this.handleRefresh();
					}, this));
				}, this) }, _('Assigner'))
			])
		]);
	},

	handleDeleteGroup: function(group, ev) {
		var self = this;

		ui.showModal(_('Supprimer le Groupe'), [
			E('p', {}, _('Voulez-vous vraiment supprimer ce groupe ? Les appareils ne seront pas supprimes, seulement de-assignes.')),
			E('p', { 'style': 'font-weight: 700;' }, fmtOrDash(group.name)),
			E('div', { 'class': 'cg-btn-group', 'style': 'justify-content: flex-end' }, [
				E('button', { 'class': 'cg-btn', 'click': ui.hideModal }, _('Annuler')),
				E('button', { 'class': 'cg-btn cg-btn-danger', 'click': L.bind(function() {
					callDeleteGroup(group.id).then(L.bind(function() {
						ui.hideModal();
						ui.addNotification(null, E('p', {}, _('Group deleted successfully')), 'info');
						this.handleRefresh();
					}, this));
				}, this) }, _('Supprimer'))
			])
		]);
	},

	handleRefresh: function() {
		return Promise.all([
			callGetGroups(),
			callGetClients()
		]).then(L.bind(function(data) {
			var container = document.querySelector('.kiss-main');
			if (container) {
				var newView = this.render(data);
				dom.content(container.parentNode, newView);
			}
		}, this)).catch(function(err) {
			console.error('Failed to refresh groups list:', err);
		});
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
