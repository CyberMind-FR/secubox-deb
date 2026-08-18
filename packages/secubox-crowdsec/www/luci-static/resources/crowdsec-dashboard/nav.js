// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

'use strict';
'require baseclass';
'require secubox/nav as SecuNav';

/**
 * CrowdSec Dashboard Navigation
 * Uses SecuNav.renderCompactTabs() for consistent styling
 */

var tabs = [
	{ id: 'overview', icon: '📊', label: _('Overview'), path: ['admin', 'secubox', 'security', 'crowdsec', 'overview'] },
	{ id: 'decisions', icon: '⛔', label: _('Decisions'), path: ['admin', 'secubox', 'security', 'crowdsec', 'decisions'] },
	{ id: 'alerts', icon: '⚠️', label: _('Alerts'), path: ['admin', 'secubox', 'security', 'crowdsec', 'alerts'] },
	{ id: 'bouncers', icon: '🛡️', label: _('Bouncers'), path: ['admin', 'secubox', 'security', 'crowdsec', 'bouncers'] },
	{ id: 'setup', icon: '⚙️', label: _('Setup'), path: ['admin', 'secubox', 'security', 'crowdsec', 'setup'] }
];

return baseclass.extend({
	getTabs: function() {
		return tabs.slice();
	},

	/**
	 * Render CrowdSec navigation tabs
	 * Delegates to SecuNav.renderCompactTabs() for consistent styling
	 */
	renderTabs: function(active) {
		return SecuNav.renderCompactTabs(active, this.getTabs(), { className: 'cs-nav-tabs' });
	},

	/**
	 * Render breadcrumb back to SecuBox
	 */
	renderBreadcrumb: function() {
		return SecuNav.renderBreadcrumb(_('CrowdSec'), '🛡️');
	}
});
