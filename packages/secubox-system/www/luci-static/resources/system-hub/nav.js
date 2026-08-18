// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

'use strict';
'require baseclass';
'require secubox/nav as SecuNav';

/**
 * System Hub Navigation
 * Uses SecuNav.renderCompactTabs() for consistent styling
 */

var tabs = [
	{ id: 'overview', icon: '📊', label: _('Overview'), path: ['admin', 'secubox', 'system', 'system-hub', 'overview'] },
	{ id: 'services', icon: '🧩', label: _('Services'), path: ['admin', 'secubox', 'system', 'system-hub', 'services'] },
	{ id: 'logs', icon: '📜', label: _('Logs'), path: ['admin', 'secubox', 'system', 'system-hub', 'logs'] },
	{ id: 'backup', icon: '💾', label: _('Backup'), path: ['admin', 'secubox', 'system', 'system-hub', 'backup'] },
	{ id: 'components', icon: '🧱', label: _('Components'), path: ['admin', 'secubox', 'system', 'system-hub', 'components'] },
	{ id: 'diagnostics', icon: '🧪', label: _('Diagnostics'), path: ['admin', 'secubox', 'system', 'system-hub', 'diagnostics'] },
	{ id: 'health', icon: '❤️', label: _('Health'), path: ['admin', 'secubox', 'system', 'system-hub', 'health'] },
	{ id: 'debug', icon: '🐛', label: _('Debug'), path: ['admin', 'secubox', 'system', 'system-hub', 'debug'] },
	{ id: 'remote', icon: '📡', label: _('Remote'), path: ['admin', 'secubox', 'system', 'system-hub', 'remote'] },
	{ id: 'settings', icon: '⚙️', label: _('Settings'), path: ['admin', 'secubox', 'system', 'system-hub', 'settings'] }
];

return baseclass.extend({
	getTabs: function() {
		return tabs.slice();
	},

	/**
	 * Render System Hub navigation tabs
	 * Delegates to SecuNav.renderCompactTabs() for consistent styling
	 */
	renderTabs: function(active) {
		return SecuNav.renderCompactTabs(active, this.getTabs(), { className: 'system-hub-nav-tabs' });
	},

	/**
	 * Render breadcrumb back to SecuBox
	 */
	renderBreadcrumb: function() {
		return SecuNav.renderBreadcrumb(_('System Hub'), '🖥️');
	}
});
