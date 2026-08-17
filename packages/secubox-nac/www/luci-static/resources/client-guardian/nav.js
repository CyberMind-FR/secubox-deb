'use strict';
'require baseclass';
'require secubox/nav as SecuNav';

/**
 * Client Guardian Navigation
 * Uses SecuNav.renderCompactTabs() for consistent styling
 */

var tabs = [
	{ id: 'overview', icon: '📊', label: _('Overview'), path: ['admin', 'secubox', 'security', 'guardian', 'overview'] },
	{ id: 'wizard', icon: '🚀', label: _('Setup Wizard'), path: ['admin', 'secubox', 'security', 'guardian', 'wizard'] },
	{ id: 'clients', icon: '👥', label: _('Clients'), path: ['admin', 'secubox', 'security', 'guardian', 'clients'] },
	{ id: 'zones', icon: '🏠', label: _('Zones'), path: ['admin', 'secubox', 'security', 'guardian', 'zones'] },
	{ id: 'groups', icon: '🗂️', label: _('Groupes'), path: ['admin', 'secubox', 'security', 'guardian', 'groups'] },
	{ id: 'presence', icon: '🌐', label: _('Présence'), path: ['admin', 'secubox', 'security', 'guardian', 'presence'] },
	{ id: 'autozoning', icon: '🎯', label: _('Auto-Zoning'), path: ['admin', 'secubox', 'security', 'guardian', 'autozoning'] },
	{ id: 'logs', icon: '📜', label: _('Logs'), path: ['admin', 'secubox', 'security', 'guardian', 'logs'] },
	{ id: 'alerts', icon: '🔔', label: _('Alerts'), path: ['admin', 'secubox', 'security', 'guardian', 'alerts'] },
	{ id: 'parental', icon: '👨‍👩‍👧', label: _('Parental'), path: ['admin', 'secubox', 'security', 'guardian', 'parental'] },
	{ id: 'settings', icon: '⚙️', label: _('Settings'), path: ['admin', 'secubox', 'security', 'guardian', 'settings'] }
];

return baseclass.extend({
	getTabs: function() {
		return tabs.slice();
	},

	/**
	 * Render Client Guardian navigation tabs
	 * Delegates to SecuNav.renderCompactTabs() for consistent styling
	 */
	renderTabs: function(active) {
		return SecuNav.renderCompactTabs(active, this.getTabs(), { className: 'cg-nav-tabs' });
	},

	/**
	 * Render breadcrumb back to SecuBox
	 */
	renderBreadcrumb: function() {
		return SecuNav.renderBreadcrumb(_('Client Guardian'), '🛡️');
	}
});
