// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

'use strict';
'require view';
'require secubox/kiss-theme';

return view.extend({
	load: function() {
		window.location.href = L.url('admin', 'secubox', 'network', 'modes', 'overview');
		return Promise.resolve();
	},
	render: function() {
		return E('div', {}, _('Redirecting to Network Modes...'));
	}
});
