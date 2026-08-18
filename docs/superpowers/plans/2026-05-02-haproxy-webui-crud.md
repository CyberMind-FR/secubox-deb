<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# HAProxy WebUI CRUD Enhancement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add full CRUD operations (Create, Read, Update, Delete) for VHosts, Backends, Servers, and Certificates to the HAProxy WebUI dashboard.

**Architecture:** Single-file enhancement to `packages/secubox-haproxy/www/haproxy/index.html`. Add reusable modal system, toast notifications, form validation, and CRUD functions. All API endpoints already exist — this is frontend-only work.

**Tech Stack:** Vanilla JavaScript, HTML5, CSS3 (P31 Phosphor theme)

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `packages/secubox-haproxy/www/haproxy/index.html` | Modify | Add ~450 lines: modal HTML, CSS, JavaScript functions |

All changes are in a single file to maintain the existing pattern used throughout secubox-deb.

---

### Task 1: Add Modal and Toast HTML Structure

**Files:**
- Modify: `packages/secubox-haproxy/www/haproxy/index.html:421` (before closing `</main>`)

- [ ] **Step 1: Add modal container HTML**

Insert before the closing `</main>` tag (line 421), after the existing migrate-modal:

```html
    <!-- Generic Modal -->
    <div id="modal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="modal-title"></h3>
                <button class="modal-close" onclick="closeModal()">&times;</button>
            </div>
            <div id="modal-body"></div>
            <div id="modal-footer" class="modal-footer"></div>
        </div>
    </div>

    <!-- Toast Container -->
    <div id="toast-container"></div>
```

- [ ] **Step 2: Verify HTML structure**

Open the file in browser dev tools and confirm:
- `#modal` element exists
- `#toast-container` element exists

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-haproxy/www/haproxy/index.html
git commit -m "feat(haproxy-ui): Add modal and toast HTML containers"
```

---

### Task 2: Add Modal and Toast CSS Styles

**Files:**
- Modify: `packages/secubox-haproxy/www/haproxy/index.html:283-287` (inside `<style>` block, before closing `</style>`)

- [ ] **Step 1: Add modal CSS**

Insert before the `@media (max-width: 768px)` rule (around line 285):

```css
        /* Modal styles */
        .modal {
            display: none;
            position: fixed;
            inset: 0;
            background: rgba(0,0,0,0.85);
            z-index: 200;
            align-items: center;
            justify-content: center;
        }
        .modal.active { display: flex; }
        .modal-content {
            background: var(--tube-pale);
            border: 1px solid var(--p31-dim);
            border-radius: 8px;
            min-width: 450px;
            max-width: 600px;
            max-height: 90vh;
            overflow-y: auto;
            box-shadow: 0 0 30px rgba(51,255,102,0.1);
        }
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 1.25rem;
            border-bottom: 1px solid var(--p31-ghost);
        }
        .modal-header h3 {
            color: var(--p31-decay);
            text-shadow: var(--bloom-amber);
            letter-spacing: 0.1em;
            text-transform: uppercase;
            font-size: 0.9rem;
            margin: 0;
        }
        .modal-close {
            background: none;
            border: none;
            color: var(--p31-dim);
            font-size: 1.5rem;
            cursor: pointer;
            line-height: 1;
        }
        .modal-close:hover { color: var(--red); }
        .modal-body { padding: 1.25rem; }
        .modal-footer {
            display: flex;
            justify-content: flex-end;
            gap: 0.5rem;
            padding: 1rem 1.25rem;
            border-top: 1px solid var(--p31-ghost);
        }
        .form-group { margin-bottom: 1rem; }
        .form-group label {
            display: block;
            font-size: 0.75rem;
            color: var(--p31-decay);
            text-transform: uppercase;
            letter-spacing: 0.1em;
            margin-bottom: 0.35rem;
        }
        .form-group input[type="text"],
        .form-group input[type="number"],
        .form-group select {
            width: 100%;
            padding: 0.6rem 0.75rem;
            border-radius: 4px;
        }
        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
        }
        .form-check {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.5rem;
        }
        .form-check input[type="checkbox"] {
            width: 16px;
            height: 16px;
        }
        .form-check label {
            font-size: 0.85rem;
            color: var(--p31-mid);
            margin: 0;
        }
```

- [ ] **Step 2: Add toast CSS**

Insert after the modal CSS:

```css
        /* Toast notifications */
        #toast-container {
            position: fixed;
            top: 1rem;
            right: 1rem;
            z-index: 300;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }
        .toast {
            padding: 0.75rem 1rem;
            border-radius: 6px;
            background: var(--tube-pale);
            border: 1px solid var(--p31-dim);
            font-size: 0.85rem;
            animation: slideIn 0.3s ease;
            max-width: 350px;
        }
        .toast.success {
            border-color: var(--p31-peak);
            color: var(--p31-peak);
        }
        .toast.error {
            border-color: var(--red);
            color: var(--red);
        }
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
```

- [ ] **Step 3: Verify styles render correctly**

Open the file, temporarily add `class="active"` to the modal div, confirm it displays centered with correct styling.

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-haproxy/www/haproxy/index.html
git commit -m "feat(haproxy-ui): Add modal and toast CSS styles"
```

---

### Task 3: Add Core JavaScript Functions (Modal, Toast, Validation, API)

**Files:**
- Modify: `packages/secubox-haproxy/www/haproxy/index.html:438-449` (inside `<script>`, after existing `headers()` function)

- [ ] **Step 1: Add modal functions**

Insert after line 441 (after `const headers = () => ...`):

```javascript
        // ══════════════════════════════════════════════════════════════
        // Modal System
        // ══════════════════════════════════════════════════════════════
        function openModal(title, bodyHtml, footerHtml) {
            document.getElementById('modal-title').textContent = title;
            document.getElementById('modal-body').innerHTML = bodyHtml;
            document.getElementById('modal-footer').innerHTML = footerHtml;
            document.getElementById('modal').classList.add('active');
        }

        function closeModal() {
            document.getElementById('modal').classList.remove('active');
        }

        // Close modal on backdrop click
        document.getElementById('modal')?.addEventListener('click', (e) => {
            if (e.target.id === 'modal') closeModal();
        });

        // Close modal on Escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') closeModal();
        });
```

- [ ] **Step 2: Add toast functions**

Insert after the modal functions:

```javascript
        // ══════════════════════════════════════════════════════════════
        // Toast Notifications
        // ══════════════════════════════════════════════════════════════
        function showToast(message, type = 'success') {
            const container = document.getElementById('toast-container');
            const toast = document.createElement('div');
            toast.className = `toast ${type}`;
            toast.textContent = message;
            container.appendChild(toast);
            setTimeout(() => toast.remove(), 3000);
        }
```

- [ ] **Step 3: Add validation function**

Insert after the toast functions:

```javascript
        // ══════════════════════════════════════════════════════════════
        // Form Validation
        // ══════════════════════════════════════════════════════════════
        function validateForm(fields) {
            for (const { id, rules } of fields) {
                const el = document.getElementById(id);
                if (!el) continue;
                const val = el.value?.trim() || '';

                if (rules.required && !val) {
                    showToast(rules.requiredMsg || `${id} is required`, 'error');
                    el.focus();
                    return false;
                }
                if (rules.pattern && val && !rules.pattern.test(val)) {
                    showToast(rules.patternMsg || `Invalid ${id} format`, 'error');
                    el.focus();
                    return false;
                }
                if (rules.min !== undefined && val && parseInt(val) < rules.min) {
                    showToast(rules.minMsg || `${id} must be at least ${rules.min}`, 'error');
                    el.focus();
                    return false;
                }
                if (rules.max !== undefined && val && parseInt(val) > rules.max) {
                    showToast(rules.maxMsg || `${id} must be at most ${rules.max}`, 'error');
                    el.focus();
                    return false;
                }
            }
            return true;
        }
```

- [ ] **Step 4: Add enhanced API call function**

Insert after the validation function:

```javascript
        // ══════════════════════════════════════════════════════════════
        // Enhanced API Call with Error Handling
        // ══════════════════════════════════════════════════════════════
        async function apiCall(path, opts = {}) {
            try {
                const res = await fetch(API + path, { ...opts, headers: headers() });

                if (res.status === 401) {
                    window.location = '/login.html';
                    return { error: 'Unauthorized' };
                }

                const data = await res.json();

                if (!res.ok || data.error) {
                    const msg = data.error || data.detail || `Error ${res.status}`;
                    showToast(msg, 'error');
                    return { error: msg };
                }

                return data;
            } catch (e) {
                showToast('Network error: ' + e.message, 'error');
                return { error: e.message };
            }
        }
```

- [ ] **Step 5: Test modal opens and closes**

In browser console, run:
```javascript
openModal('Test', '<p>Hello</p>', '<button class="btn" onclick="closeModal()">Close</button>');
```
Confirm modal appears and closes on button click, backdrop click, and Escape key.

- [ ] **Step 6: Test toast notifications**

In browser console, run:
```javascript
showToast('Success message', 'success');
showToast('Error message', 'error');
```
Confirm toasts appear in top-right and auto-dismiss after 3 seconds.

- [ ] **Step 7: Commit**

```bash
git add packages/secubox-haproxy/www/haproxy/index.html
git commit -m "feat(haproxy-ui): Add modal, toast, validation, and API core functions"
```

---

### Task 4: Add VHost CRUD Functions

**Files:**
- Modify: `packages/secubox-haproxy/www/haproxy/index.html` (inside `<script>`, after apiCall function)

- [ ] **Step 1: Add VHost modal functions**

Insert after the `apiCall` function:

```javascript
        // ══════════════════════════════════════════════════════════════
        // VHost CRUD
        // ══════════════════════════════════════════════════════════════
        let cachedBackends = [];

        async function loadBackendOptions() {
            const d = await api('/backends');
            cachedBackends = (d.backends || []).filter(b => b.type !== 'waf');
            return cachedBackends.map(b =>
                `<option value="${b.name}">${b.name}</option>`
            ).join('');
        }

        async function showAddVhostModal() {
            const backendOpts = await loadBackendOptions();
            const body = `
                <div class="form-group">
                    <label>Domain</label>
                    <input type="text" id="vhost-domain" placeholder="example.com">
                </div>
                <div class="form-group">
                    <label>Backend</label>
                    <select id="vhost-backend">
                        <option value="">-- Select Backend --</option>
                        ${backendOpts}
                    </select>
                </div>
                <div class="form-row">
                    <div class="form-check">
                        <input type="checkbox" id="vhost-ssl" checked>
                        <label>Enable SSL</label>
                    </div>
                    <div class="form-check">
                        <input type="checkbox" id="vhost-ssl-redirect" checked>
                        <label>Force HTTPS</label>
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-check">
                        <input type="checkbox" id="vhost-acme" checked>
                        <label>Auto-renew (ACME)</label>
                    </div>
                    <div class="form-check">
                        <input type="checkbox" id="vhost-waf-bypass">
                        <label>Bypass WAF</label>
                    </div>
                </div>
                <div class="form-check">
                    <input type="checkbox" id="vhost-enabled" checked>
                    <label>Enabled</label>
                </div>
            `;
            const footer = `
                <button class="btn" onclick="closeModal()">Cancel</button>
                <button class="btn primary" onclick="saveVhost(false)">Add VHost</button>
            `;
            openModal('Add Virtual Host', body, footer);
        }

        async function showEditVhostModal(vhost) {
            const backendOpts = await loadBackendOptions();
            const body = `
                <input type="hidden" id="vhost-original-name" value="${vhost.name || vhost.domain}">
                <div class="form-group">
                    <label>Domain</label>
                    <input type="text" id="vhost-domain" value="${vhost.domain}">
                </div>
                <div class="form-group">
                    <label>Backend</label>
                    <select id="vhost-backend">
                        <option value="">-- Select Backend --</option>
                        ${backendOpts}
                    </select>
                </div>
                <div class="form-row">
                    <div class="form-check">
                        <input type="checkbox" id="vhost-ssl" ${vhost.ssl ? 'checked' : ''}>
                        <label>Enable SSL</label>
                    </div>
                    <div class="form-check">
                        <input type="checkbox" id="vhost-ssl-redirect" ${vhost.ssl_redirect ? 'checked' : ''}>
                        <label>Force HTTPS</label>
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-check">
                        <input type="checkbox" id="vhost-acme" ${vhost.acme ? 'checked' : ''}>
                        <label>Auto-renew (ACME)</label>
                    </div>
                    <div class="form-check">
                        <input type="checkbox" id="vhost-waf-bypass" ${vhost.waf_bypass ? 'checked' : ''}>
                        <label>Bypass WAF</label>
                    </div>
                </div>
                <div class="form-check">
                    <input type="checkbox" id="vhost-enabled" ${vhost.enabled !== false ? 'checked' : ''}>
                    <label>Enabled</label>
                </div>
            `;
            const footer = `
                <button class="btn" onclick="closeModal()">Cancel</button>
                <button class="btn primary" onclick="saveVhost(true)">Save Changes</button>
            `;
            openModal('Edit Virtual Host', body, footer);
            document.getElementById('vhost-backend').value = vhost.backend || '';
        }

        async function saveVhost(isEdit) {
            const valid = validateForm([
                { id: 'vhost-domain', rules: { required: true, requiredMsg: 'Domain is required', pattern: /^[a-zA-Z0-9*][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}$/, patternMsg: 'Invalid domain format' }},
                { id: 'vhost-backend', rules: { required: true, requiredMsg: 'Please select a backend' }}
            ]);
            if (!valid) return;

            const data = {
                domain: document.getElementById('vhost-domain').value.trim(),
                backend: document.getElementById('vhost-backend').value,
                ssl: document.getElementById('vhost-ssl').checked,
                ssl_redirect: document.getElementById('vhost-ssl-redirect').checked,
                acme: document.getElementById('vhost-acme').checked,
                waf_bypass: document.getElementById('vhost-waf-bypass').checked,
                enabled: document.getElementById('vhost-enabled').checked
            };

            let res;
            if (isEdit) {
                const origName = document.getElementById('vhost-original-name').value;
                res = await apiCall(`/vhost/${encodeURIComponent(origName)}`, {
                    method: 'PUT',
                    body: JSON.stringify(data)
                });
            } else {
                res = await apiCall('/vhost', {
                    method: 'POST',
                    body: JSON.stringify(data)
                });
            }

            if (!res.error) {
                closeModal();
                showToast(isEdit ? 'VHost updated' : 'VHost created', 'success');
                loadVhosts();
                loadStatus();
            }
        }

        async function deleteVhost(name) {
            if (!confirm(`Delete vhost "${name}"?\n\nThis will remove the domain routing.`)) return;

            const res = await apiCall(`/vhost/${encodeURIComponent(name)}`, { method: 'DELETE' });
            if (!res.error) {
                showToast(`VHost "${name}" deleted`, 'success');
                loadVhosts();
                loadStatus();
            }
        }
```

- [ ] **Step 2: Commit**

```bash
git add packages/secubox-haproxy/www/haproxy/index.html
git commit -m "feat(haproxy-ui): Add VHost CRUD functions"
```

---

### Task 5: Add Backend CRUD Functions

**Files:**
- Modify: `packages/secubox-haproxy/www/haproxy/index.html` (inside `<script>`, after VHost functions)

- [ ] **Step 1: Add Backend modal functions**

Insert after the VHost CRUD section:

```javascript
        // ══════════════════════════════════════════════════════════════
        // Backend CRUD
        // ══════════════════════════════════════════════════════════════
        function showAddBackendModal() {
            const body = `
                <div class="form-group">
                    <label>Name</label>
                    <input type="text" id="backend-name" placeholder="my-backend">
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Mode</label>
                        <select id="backend-mode">
                            <option value="http">HTTP</option>
                            <option value="tcp">TCP</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Balance</label>
                        <select id="backend-balance">
                            <option value="roundrobin">Round Robin</option>
                            <option value="leastconn">Least Connections</option>
                            <option value="source">Source IP</option>
                        </select>
                    </div>
                </div>
                <div class="form-check">
                    <input type="checkbox" id="backend-health" checked>
                    <label>Enable Health Checks</label>
                </div>
                <div class="form-group">
                    <label>Health Check URI</label>
                    <input type="text" id="backend-health-uri" value="/health" placeholder="/health">
                </div>
            `;
            const footer = `
                <button class="btn" onclick="closeModal()">Cancel</button>
                <button class="btn primary" onclick="saveBackend(false)">Add Backend</button>
            `;
            openModal('Add Backend', body, footer);
        }

        async function showEditBackendModal(backend) {
            const body = `
                <input type="hidden" id="backend-original-name" value="${backend.name}">
                <div class="form-group">
                    <label>Name</label>
                    <input type="text" id="backend-name" value="${backend.name}">
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Mode</label>
                        <select id="backend-mode">
                            <option value="http" ${backend.mode === 'http' ? 'selected' : ''}>HTTP</option>
                            <option value="tcp" ${backend.mode === 'tcp' ? 'selected' : ''}>TCP</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Balance</label>
                        <select id="backend-balance">
                            <option value="roundrobin" ${backend.balance === 'roundrobin' ? 'selected' : ''}>Round Robin</option>
                            <option value="leastconn" ${backend.balance === 'leastconn' ? 'selected' : ''}>Least Connections</option>
                            <option value="source" ${backend.balance === 'source' ? 'selected' : ''}>Source IP</option>
                        </select>
                    </div>
                </div>
                <div class="form-check">
                    <input type="checkbox" id="backend-health" ${backend.health_check !== false ? 'checked' : ''}>
                    <label>Enable Health Checks</label>
                </div>
                <div class="form-group">
                    <label>Health Check URI</label>
                    <input type="text" id="backend-health-uri" value="${backend.health_uri || '/health'}">
                </div>
            `;
            const footer = `
                <button class="btn" onclick="closeModal()">Cancel</button>
                <button class="btn primary" onclick="saveBackend(true)">Save Changes</button>
            `;
            openModal('Edit Backend', body, footer);
        }

        async function saveBackend(isEdit) {
            const valid = validateForm([
                { id: 'backend-name', rules: { required: true, requiredMsg: 'Name is required', pattern: /^[a-zA-Z][a-zA-Z0-9_-]*$/, patternMsg: 'Name must start with letter, only letters/numbers/hyphens/underscores' }}
            ]);
            if (!valid) return;

            const data = {
                name: document.getElementById('backend-name').value.trim(),
                mode: document.getElementById('backend-mode').value,
                balance: document.getElementById('backend-balance').value,
                health_check: document.getElementById('backend-health').checked,
                health_uri: document.getElementById('backend-health-uri').value.trim() || '/health'
            };

            let res;
            if (isEdit) {
                const origName = document.getElementById('backend-original-name').value;
                res = await apiCall(`/backend/${encodeURIComponent(origName)}`, {
                    method: 'PUT',
                    body: JSON.stringify(data)
                });
            } else {
                res = await apiCall('/backend', {
                    method: 'POST',
                    body: JSON.stringify(data)
                });
            }

            if (!res.error) {
                closeModal();
                showToast(isEdit ? 'Backend updated' : 'Backend created', 'success');
                loadBackends();
                loadStatus();
            }
        }

        async function deleteBackend(name) {
            const backend = cachedBackends.find(b => b.name === name);
            const serverCount = backend?.servers?.length || 0;

            const msg = serverCount > 0
                ? `Delete backend "${name}" and its ${serverCount} server(s)?`
                : `Delete backend "${name}"?`;

            if (!confirm(msg)) return;

            const res = await apiCall(`/backend/${encodeURIComponent(name)}`, { method: 'DELETE' });
            if (!res.error) {
                showToast(`Backend "${name}" deleted`, 'success');
                loadBackends();
                loadStatus();
            }
        }
```

- [ ] **Step 2: Commit**

```bash
git add packages/secubox-haproxy/www/haproxy/index.html
git commit -m "feat(haproxy-ui): Add Backend CRUD functions"
```

---

### Task 6: Add Server CRUD Functions

**Files:**
- Modify: `packages/secubox-haproxy/www/haproxy/index.html` (inside `<script>`, after Backend functions)

- [ ] **Step 1: Add Server modal functions**

Insert after the Backend CRUD section:

```javascript
        // ══════════════════════════════════════════════════════════════
        // Server CRUD (nested under Backend)
        // ══════════════════════════════════════════════════════════════
        async function showBackendServers(backendName) {
            const d = await api(`/backend/${encodeURIComponent(backendName)}`);
            const backend = d.backend || d;
            const servers = backend.servers || [];

            const serverRows = servers.length === 0
                ? '<tr><td colspan="5" style="color:var(--p31-dim)">No servers configured</td></tr>'
                : servers.map(s => `
                    <tr>
                        <td>${s.name}</td>
                        <td>${s.address}</td>
                        <td>${s.port}</td>
                        <td>${s.weight || 100}</td>
                        <td>
                            <button class="btn" style="padding:0.3rem 0.6rem;font-size:0.75rem" onclick="showEditServerModal('${backendName}', ${JSON.stringify(s).replace(/"/g, '&quot;')})">Edit</button>
                            <button class="btn danger" style="padding:0.3rem 0.6rem;font-size:0.75rem" onclick="deleteServer('${backendName}', '${s.name}')">Delete</button>
                        </td>
                    </tr>
                `).join('');

            const body = `
                <p style="color:var(--p31-dim);margin-bottom:1rem">Backend: <strong>${backendName}</strong></p>
                <table style="margin-bottom:1rem">
                    <thead><tr><th>Name</th><th>Address</th><th>Port</th><th>Weight</th><th>Actions</th></tr></thead>
                    <tbody>${serverRows}</tbody>
                </table>
            `;
            const footer = `
                <button class="btn" onclick="closeModal()">Close</button>
                <button class="btn primary" onclick="showAddServerModal('${backendName}')">+ Add Server</button>
            `;
            openModal('Manage Servers', body, footer);
        }

        function showAddServerModal(backendName) {
            const body = `
                <input type="hidden" id="server-backend" value="${backendName}">
                <div class="form-group">
                    <label>Server Name</label>
                    <input type="text" id="server-name" placeholder="server1">
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Address</label>
                        <input type="text" id="server-address" placeholder="192.168.1.10">
                    </div>
                    <div class="form-group">
                        <label>Port</label>
                        <input type="number" id="server-port" value="80" min="1" max="65535">
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Weight</label>
                        <input type="number" id="server-weight" value="100" min="1" max="256">
                    </div>
                    <div class="form-check" style="align-self:end;padding-bottom:0.6rem">
                        <input type="checkbox" id="server-check" checked>
                        <label>Health Check</label>
                    </div>
                </div>
            `;
            const footer = `
                <button class="btn" onclick="showBackendServers('${backendName}')">Back</button>
                <button class="btn primary" onclick="saveServer('${backendName}', false)">Add Server</button>
            `;
            openModal('Add Server', body, footer);
        }

        function showEditServerModal(backendName, server) {
            const body = `
                <input type="hidden" id="server-backend" value="${backendName}">
                <input type="hidden" id="server-original-name" value="${server.name}">
                <div class="form-group">
                    <label>Server Name</label>
                    <input type="text" id="server-name" value="${server.name}">
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Address</label>
                        <input type="text" id="server-address" value="${server.address}">
                    </div>
                    <div class="form-group">
                        <label>Port</label>
                        <input type="number" id="server-port" value="${server.port}" min="1" max="65535">
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Weight</label>
                        <input type="number" id="server-weight" value="${server.weight || 100}" min="1" max="256">
                    </div>
                    <div class="form-check" style="align-self:end;padding-bottom:0.6rem">
                        <input type="checkbox" id="server-check" ${server.check !== false ? 'checked' : ''}>
                        <label>Health Check</label>
                    </div>
                </div>
            `;
            const footer = `
                <button class="btn" onclick="showBackendServers('${backendName}')">Back</button>
                <button class="btn primary" onclick="saveServer('${backendName}', true)">Save Changes</button>
            `;
            openModal('Edit Server', body, footer);
        }

        async function saveServer(backendName, isEdit) {
            const valid = validateForm([
                { id: 'server-name', rules: { required: true, requiredMsg: 'Server name is required' }},
                { id: 'server-address', rules: { required: true, requiredMsg: 'Address is required' }},
                { id: 'server-port', rules: { required: true, min: 1, max: 65535, minMsg: 'Port must be 1-65535', maxMsg: 'Port must be 1-65535' }}
            ]);
            if (!valid) return;

            const data = {
                backend: backendName,
                name: document.getElementById('server-name').value.trim(),
                address: document.getElementById('server-address').value.trim(),
                port: parseInt(document.getElementById('server-port').value),
                weight: parseInt(document.getElementById('server-weight').value) || 100,
                check: document.getElementById('server-check').checked
            };

            let res;
            if (isEdit) {
                const origName = document.getElementById('server-original-name').value;
                res = await apiCall(`/server/${encodeURIComponent(origName)}`, {
                    method: 'PUT',
                    body: JSON.stringify(data)
                });
            } else {
                res = await apiCall('/server', {
                    method: 'POST',
                    body: JSON.stringify(data)
                });
            }

            if (!res.error) {
                showToast(isEdit ? 'Server updated' : 'Server added', 'success');
                showBackendServers(backendName);
            }
        }

        async function deleteServer(backendName, serverName) {
            if (!confirm(`Delete server "${serverName}" from backend "${backendName}"?`)) return;

            const res = await apiCall(`/server/${encodeURIComponent(serverName)}?backend=${encodeURIComponent(backendName)}`, { method: 'DELETE' });
            if (!res.error) {
                showToast(`Server "${serverName}" deleted`, 'success');
                showBackendServers(backendName);
            }
        }
```

- [ ] **Step 2: Commit**

```bash
git add packages/secubox-haproxy/www/haproxy/index.html
git commit -m "feat(haproxy-ui): Add Server CRUD functions"
```

---

### Task 7: Add Certificate CRUD Functions

**Files:**
- Modify: `packages/secubox-haproxy/www/haproxy/index.html` (inside `<script>`, after Server functions)

- [ ] **Step 1: Add Certificate modal functions**

Insert after the Server CRUD section:

```javascript
        // ══════════════════════════════════════════════════════════════
        // Certificate CRUD
        // ══════════════════════════════════════════════════════════════
        function showRequestCertModal() {
            const body = `
                <div class="form-group">
                    <label>Domain</label>
                    <input type="text" id="cert-domain" placeholder="example.com">
                </div>
                <div class="form-check">
                    <input type="checkbox" id="cert-staging">
                    <label>Use Let's Encrypt Staging (for testing)</label>
                </div>
                <div id="cert-progress" style="display:none;margin-top:1rem">
                    <p style="color:var(--p31-mid)">Requesting certificate...</p>
                    <div style="background:var(--tube-soft);height:4px;border-radius:2px;overflow:hidden">
                        <div id="cert-progress-bar" style="background:var(--p31-peak);height:100%;width:0%;transition:width 0.5s"></div>
                    </div>
                </div>
            `;
            const footer = `
                <button class="btn" onclick="closeModal()">Cancel</button>
                <button class="btn primary" id="cert-submit-btn" onclick="requestCertificate()">Request Certificate</button>
            `;
            openModal('Request SSL Certificate', body, footer);
        }

        async function requestCertificate() {
            const valid = validateForm([
                { id: 'cert-domain', rules: { required: true, requiredMsg: 'Domain is required', pattern: /^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}$/, patternMsg: 'Invalid domain format' }}
            ]);
            if (!valid) return;

            const domain = document.getElementById('cert-domain').value.trim();
            const staging = document.getElementById('cert-staging').checked;

            // Show progress
            document.getElementById('cert-progress').style.display = 'block';
            document.getElementById('cert-submit-btn').disabled = true;
            const progressBar = document.getElementById('cert-progress-bar');
            progressBar.style.width = '30%';

            const res = await apiCall('/certificate/request', {
                method: 'POST',
                body: JSON.stringify({ domain, staging })
            });

            progressBar.style.width = '100%';

            if (!res.error) {
                setTimeout(() => {
                    closeModal();
                    showToast(`Certificate requested for ${domain}`, 'success');
                    loadCerts();
                }, 500);
            } else {
                document.getElementById('cert-progress').style.display = 'none';
                document.getElementById('cert-submit-btn').disabled = false;
            }
        }

        async function deleteCertificate(name) {
            if (!confirm(`Delete certificate "${name}"?`)) return;

            const res = await apiCall(`/certificate/${encodeURIComponent(name)}`, { method: 'DELETE' });
            if (!res.error) {
                showToast(`Certificate "${name}" deleted`, 'success');
                loadCerts();
            }
        }
```

- [ ] **Step 2: Commit**

```bash
git add packages/secubox-haproxy/www/haproxy/index.html
git commit -m "feat(haproxy-ui): Add Certificate CRUD functions"
```

---

### Task 8: Update VHosts Table with Add Button and Actions

**Files:**
- Modify: `packages/secubox-haproxy/www/haproxy/index.html:375-379` (VHosts tab content)

- [ ] **Step 1: Update VHosts tab HTML**

Replace the VHosts tab content (lines 375-379):

```html
            <div id="vhosts" class="tab-content">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
                    <h3 style="margin:0;color:var(--p31-decay)">Virtual Hosts</h3>
                    <button class="btn primary" onclick="showAddVhostModal()">+ Add VHost</button>
                </div>
                <table>
                    <thead><tr><th>Domain</th><th>Backend</th><th>SSL</th><th>WAF</th><th>Actions</th></tr></thead>
                    <tbody id="vhost-list"><tr><td colspan="5">Loading...</td></tr></tbody>
                </table>
            </div>
```

- [ ] **Step 2: Update loadVhosts function**

Find the existing `loadVhosts` function (around line 494) and replace it:

```javascript
        async function loadVhosts() {
            const d = await api('/vhosts');
            const list = document.getElementById('vhost-list');
            const vhosts = d.vhosts || [];
            if (!vhosts.length) {
                list.innerHTML = '<tr><td colspan="5" style="color:var(--text-dim)">No vhosts configured</td></tr>';
                return;
            }
            list.innerHTML = vhosts.map(v => `
                <tr>
                    <td><strong>${v.domain}</strong></td>
                    <td>${v.backend || '-'}</td>
                    <td>
                        ${v.ssl ? '<span class="badge up">SSL</span>' : ''}
                        ${v.acme ? '<span class="badge up" style="margin-left:4px">ACME</span>' : ''}
                        ${!v.ssl ? '<span class="badge bypass">No SSL</span>' : ''}
                    </td>
                    <td>${v.waf_bypass ? '<span class="badge bypass">Bypass</span>' : '<span class="badge waf">Protected</span>'}</td>
                    <td>
                        <button class="btn" style="padding:0.3rem 0.6rem;font-size:0.75rem" onclick='showEditVhostModal(${JSON.stringify(v)})'>Edit</button>
                        <button class="btn danger" style="padding:0.3rem 0.6rem;font-size:0.75rem" onclick="deleteVhost('${v.name || v.domain}')">Delete</button>
                    </td>
                </tr>
            `).join('');
        }
```

- [ ] **Step 3: Test VHost table**

Reload the page, go to VHosts tab:
- Confirm "+ Add VHost" button appears
- Confirm Edit and Delete buttons appear for each row
- Click "Add VHost" and confirm modal opens

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-haproxy/www/haproxy/index.html
git commit -m "feat(haproxy-ui): Update VHosts table with CRUD buttons"
```

---

### Task 9: Update Backends Table with Add Button and Actions

**Files:**
- Modify: `packages/secubox-haproxy/www/haproxy/index.html:382-386` (Backends tab content)

- [ ] **Step 1: Update Backends tab HTML**

Replace the Backends tab content (lines 382-386):

```html
            <div id="backends" class="tab-content">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
                    <h3 style="margin:0;color:var(--p31-decay)">Backends</h3>
                    <button class="btn primary" onclick="showAddBackendModal()">+ Add Backend</button>
                </div>
                <table>
                    <thead><tr><th>Name</th><th>Mode</th><th>Balance</th><th>Servers</th><th>Actions</th></tr></thead>
                    <tbody id="backend-list"><tr><td colspan="5">Loading...</td></tr></tbody>
                </table>
            </div>
```

- [ ] **Step 2: Update loadBackends function**

Find the existing `loadBackends` function (around line 517) and replace it:

```javascript
        async function loadBackends() {
            const d = await api('/backends');
            const list = document.getElementById('backend-list');
            const backends = d.backends || [];
            cachedBackends = backends;
            if (!backends.length) {
                list.innerHTML = '<tr><td colspan="5" style="color:var(--text-dim)">No backends</td></tr>';
                return;
            }
            list.innerHTML = backends.map(b => {
                const isWaf = b.type === 'waf' || b.name === 'waf_inspector';
                const serverCount = b.servers?.length || 0;
                return `
                <tr>
                    <td><strong>${b.name}</strong></td>
                    <td>${b.mode || 'http'}</td>
                    <td>${b.balance || '-'}</td>
                    <td>
                        ${isWaf ? '<span class="badge waf">WAF Inspector</span>' : `${serverCount} server${serverCount !== 1 ? 's' : ''}`}
                        ${!isWaf ? `<button class="btn" style="padding:0.2rem 0.5rem;font-size:0.7rem;margin-left:0.5rem" onclick="showBackendServers('${b.name}')">Manage</button>` : ''}
                    </td>
                    <td>
                        ${!isWaf ? `
                            <button class="btn" style="padding:0.3rem 0.6rem;font-size:0.75rem" onclick='showEditBackendModal(${JSON.stringify(b)})'>Edit</button>
                            <button class="btn danger" style="padding:0.3rem 0.6rem;font-size:0.75rem" onclick="deleteBackend('${b.name}')">Delete</button>
                        ` : ''}
                    </td>
                </tr>
            `}).join('');
        }
```

- [ ] **Step 3: Test Backends table**

Reload the page, go to Backends tab:
- Confirm "+ Add Backend" button appears
- Confirm "Manage" servers button appears for non-WAF backends
- Confirm Edit and Delete buttons appear (not for WAF inspector)

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-haproxy/www/haproxy/index.html
git commit -m "feat(haproxy-ui): Update Backends table with CRUD buttons"
```

---

### Task 10: Update Certificates Table with Request Button and Actions

**Files:**
- Modify: `packages/secubox-haproxy/www/haproxy/index.html:396-401` (Certs tab content)

- [ ] **Step 1: Update Certificates tab HTML**

Replace the Certificates tab content (lines 396-401):

```html
            <div id="certs" class="tab-content">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
                    <h3 style="margin:0;color:var(--p31-decay)">SSL Certificates</h3>
                    <button class="btn primary" onclick="showRequestCertModal()">+ Request Certificate</button>
                </div>
                <table>
                    <thead><tr><th>Certificate</th><th>Path</th><th>Actions</th></tr></thead>
                    <tbody id="cert-list"><tr><td colspan="3">Loading...</td></tr></tbody>
                </table>
            </div>
```

- [ ] **Step 2: Update loadCerts function**

Find the existing `loadCerts` function (around line 560) and replace it:

```javascript
        async function loadCerts() {
            const d = await api('/certificates');
            const list = document.getElementById('cert-list');
            const certs = d.certificates || [];
            if (!certs.length) {
                list.innerHTML = '<tr><td colspan="3" style="color:var(--text-dim)">No certificates</td></tr>';
                return;
            }
            list.innerHTML = certs.map(c => `
                <tr>
                    <td><strong>${c.name}</strong></td>
                    <td style="font-family:monospace;font-size:0.8rem;color:var(--p31-dim)">${c.path}</td>
                    <td>
                        <button class="btn danger" style="padding:0.3rem 0.6rem;font-size:0.75rem" onclick="deleteCertificate('${c.name}')">Delete</button>
                    </td>
                </tr>
            `).join('');
        }
```

- [ ] **Step 3: Test Certificates table**

Reload the page, go to Certificates tab:
- Confirm "+ Request Certificate" button appears
- Confirm Delete button appears for each certificate

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-haproxy/www/haproxy/index.html
git commit -m "feat(haproxy-ui): Update Certificates table with CRUD buttons"
```

---

### Task 11: Final Testing and Documentation Commit

**Files:**
- Modify: `packages/secubox-haproxy/www/haproxy/index.html` (if any fixes needed)

- [ ] **Step 1: Run through full test checklist**

Test each feature manually:

**VHost Operations:**
- [ ] Add vhost with all options
- [ ] Add vhost with minimal options (domain + backend only)
- [ ] Edit existing vhost
- [ ] Delete vhost with confirmation
- [ ] Validation errors display correctly

**Backend Operations:**
- [ ] Add backend with health check
- [ ] Edit backend settings
- [ ] Delete empty backend
- [ ] Delete backend with servers (cascade warning)

**Server Operations:**
- [ ] Add server to backend
- [ ] Edit server address/port
- [ ] Delete server
- [ ] Port validation (1-65535)

**Certificate Operations:**
- [ ] Request new certificate (modal shows progress)
- [ ] Delete certificate

**Error Handling:**
- [ ] API errors show toast
- [ ] Validation errors focus field

- [ ] **Step 2: Fix any issues found during testing**

Make any necessary fixes discovered during testing.

- [ ] **Step 3: Final commit**

```bash
git add packages/secubox-haproxy/www/haproxy/index.html
git commit -m "feat(haproxy-ui): Complete WebUI CRUD enhancement

- Added modal system for add/edit forms
- Added toast notifications for success/error feedback
- Added client-side form validation
- VHost CRUD: add, edit, delete with domain/backend/SSL/WAF options
- Backend CRUD: add, edit, delete with mode/balance/health check
- Server CRUD: nested under backends with address/port/weight
- Certificate CRUD: request ACME certs, delete existing
- Updated all tables with action buttons
- Maintained P31 Phosphor theme consistency

Closes: HAProxy WebUI Enhancement"
```

---

## Summary

| Task | Description | Estimated Steps |
|------|-------------|-----------------|
| 1 | Add Modal/Toast HTML | 3 |
| 2 | Add Modal/Toast CSS | 4 |
| 3 | Add Core JS Functions | 7 |
| 4 | Add VHost CRUD | 2 |
| 5 | Add Backend CRUD | 2 |
| 6 | Add Server CRUD | 2 |
| 7 | Add Certificate CRUD | 2 |
| 8 | Update VHosts Table | 4 |
| 9 | Update Backends Table | 4 |
| 10 | Update Certs Table | 4 |
| 11 | Final Testing | 3 |
| **Total** | | **37 steps** |

All changes are in a single file: `packages/secubox-haproxy/www/haproxy/index.html`
