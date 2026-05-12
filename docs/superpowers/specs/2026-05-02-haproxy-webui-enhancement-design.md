<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# HAProxy WebUI Enhancement Design

**Date:** 2026-05-02
**Author:** Claude + Gérald Kerma
**Status:** Approved
**Approach:** Minimal Enhancement (Approach A)

---

## Overview

Enhance the existing `packages/secubox-haproxy/www/haproxy/index.html` to add full CRUD operations for VHosts, Backends, Servers, and Certificates. The API already supports all operations — only the frontend needs enhancement.

### Goals

- Add CRUD modals for VHosts, Backends, Servers, Certificates
- Maintain P31 Phosphor theme consistency
- Keep single-file pattern (no separate JS modules)
- Reuse existing API endpoints

### Non-Goals

- No React/Vue SPA conversion
- No separate view files (unlike OpenWrt LuCI)
- No new API endpoints required

---

## Comparison: OpenWrt vs secubox-deb

| Feature | OpenWrt LuCI | secubox-deb Current | After Enhancement |
|---------|--------------|---------------------|-------------------|
| VHost CRUD | Full modal + table | Read-only table | Full CRUD |
| Backend CRUD | Full modal + server mgmt | Read-only table | Full CRUD |
| Server CRUD | Nested under backends | Not present | Full CRUD |
| Certificate CRUD | Async tasks + import | Read-only list | Request + Delete |
| ACL Management | Full CRUD | Not present | Phase 2 |
| Redirect Rules | Full CRUD | Not present | Phase 2 |
| Theme | KISS Theme (dark) | P31 Phosphor (light CRT) | Keep P31 |

---

## Architecture

### File Changes

| File | Changes |
|------|---------|
| `packages/secubox-haproxy/www/haproxy/index.html` | Add ~450 lines: modal system, CRUD functions, enhanced tables |

### Code Organization

```
<script>
├── Existing code (keep as-is)
│   ├── const API = '/api/v1/haproxy'
│   ├── api(), switchTab(), loadStatus(), etc.
│   └── refresh(), setInterval()
│
└── New additions
    ├── Modal System (~50 lines)
    │   ├── openModal(title, bodyHtml, footerHtml)
    │   ├── closeModal()
    │   └── showToast(message, type)
    │
    ├── Validation (~30 lines)
    │   ├── validateForm(fields)
    │   └── apiCall(path, opts)
    │
    ├── VHost CRUD (~80 lines)
    │   ├── showAddVhostModal()
    │   ├── showEditVhostModal(vhost)
    │   ├── saveVhost(isEdit)
    │   └── deleteVhost(name)
    │
    ├── Backend CRUD (~80 lines)
    │   ├── showAddBackendModal()
    │   ├── showEditBackendModal(backend)
    │   ├── saveBackend(isEdit)
    │   └── deleteBackend(name)
    │
    ├── Server CRUD (~70 lines)
    │   ├── showAddServerModal(backendName)
    │   ├── showEditServerModal(backendName, server)
    │   ├── saveServer(backendName, isEdit)
    │   └── deleteServer(backendName, serverName)
    │
    └── Certificate CRUD (~60 lines)
        ├── showRequestCertModal()
        ├── requestCertificate()
        └── deleteCertificate(name)
</script>
```

---

## UI Components

### Modal System

Reusable modal container:

```html
<div id="modal" class="modal">
  <div class="modal-content">
    <div class="modal-header">
      <h3 id="modal-title"></h3>
      <button onclick="closeModal()">&times;</button>
    </div>
    <div id="modal-body"></div>
    <div id="modal-footer" class="modal-footer"></div>
  </div>
</div>
```

### Toast Notifications

```html
<div id="toast-container"></div>
```

Non-blocking notifications:
- Green toast: success messages
- Red toast: error messages
- Auto-dismiss after 3 seconds

---

## Modal Specifications

### VHost Modal

| Field | Type | Default | Validation |
|-------|------|---------|------------|
| `domain` | text | — | Required, valid domain format |
| `backend` | select | — | Required |
| `ssl` | checkbox | ✓ | — |
| `ssl_redirect` | checkbox | ✓ | — |
| `acme` | checkbox | ✓ | — |
| `waf_bypass` | checkbox | ✗ | — |
| `enabled` | checkbox | ✓ | — |

### Backend Modal

| Field | Type | Default | Validation |
|-------|------|---------|------------|
| `name` | text | — | Required, alphanumeric + hyphen |
| `mode` | select | http | http / tcp |
| `balance` | select | roundrobin | roundrobin / leastconn / source |
| `health_check` | checkbox | ✓ | — |
| `health_uri` | text | /health | — |

### Server Modal (nested under Backend)

| Field | Type | Default | Validation |
|-------|------|---------|------------|
| `name` | text | — | Required |
| `address` | text | — | Required, valid IP or hostname |
| `port` | number | 80 | Required, 1-65535 |
| `weight` | number | 100 | 1-256 |
| `check` | checkbox | ✓ | — |

### Certificate Modal

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `domain` | text | — | Domain for certificate |
| `staging` | checkbox | ✗ | Use Let's Encrypt staging |
| Progress bar | — | — | Shows request status |

---

## API Endpoints

All endpoints already exist in `packages/secubox-haproxy/api/main.py`:

| Operation | Endpoint | Method |
|-----------|----------|--------|
| List vhosts | `/api/v1/haproxy/vhosts` | GET |
| Add vhost | `/api/v1/haproxy/vhost` | POST |
| Update vhost | `/api/v1/haproxy/vhost/{name}` | PUT |
| Delete vhost | `/api/v1/haproxy/vhost/{name}` | DELETE |
| List backends | `/api/v1/haproxy/backends` | GET |
| Get backend | `/api/v1/haproxy/backend/{name}` | GET |
| Add backend | `/api/v1/haproxy/backend` | POST |
| Update backend | `/api/v1/haproxy/backend/{name}` | PUT |
| Delete backend | `/api/v1/haproxy/backend/{name}` | DELETE |
| List certificates | `/api/v1/haproxy/certificates` | GET |
| Request certificate | `/api/v1/haproxy/certificate/request` | POST |
| Delete certificate | `/api/v1/haproxy/certificate/{name}` | DELETE |

---

## Data Flow

```
User clicks "Add VHost"
        ↓
showAddVhostModal()
        ↓
openModal() renders form with backend dropdown
        ↓
User fills form, clicks "Save"
        ↓
validateForm() checks required fields
        ↓
saveVhost(false) → POST /api/v1/haproxy/vhost
        ↓
    ┌───────────────────┐
    │  API Response     │
    └───────────────────┘
        ↓           ↓
    success       error
        ↓           ↓
closeModal()    showToast(error, 'error')
showToast()     (modal stays open)
loadVhosts()
```

---

## Error Handling

### Client-Side Validation

```javascript
function validateForm(fields) {
  const errors = [];

  fields.forEach(({ id, rules }) => {
    const el = document.getElementById(id);
    const val = el?.value?.trim() || '';

    if (rules.required && !val)
      errors.push({ id, msg: rules.requiredMsg || 'Required' });
    if (rules.pattern && val && !rules.pattern.test(val))
      errors.push({ id, msg: rules.patternMsg || 'Invalid format' });
    if (rules.min && val && parseInt(val) < rules.min)
      errors.push({ id, msg: rules.minMsg || `Min: ${rules.min}` });
    if (rules.max && val && parseInt(val) > rules.max)
      errors.push({ id, msg: rules.maxMsg || `Max: ${rules.max}` });
  });

  if (errors.length) {
    document.getElementById(errors[0].id)?.focus();
    showToast(errors[0].msg, 'error');
    return false;
  }
  return true;
}
```

### API Error Handling

```javascript
async function apiCall(path, opts = {}) {
  try {
    const res = await fetch(API + path, { ...opts, headers: headers() });

    if (res.status === 401) {
      window.location = '/login.html';
      return { error: 'Unauthorized' };
    }

    const data = await res.json();

    if (!res.ok || data.error) {
      showToast(data.error || data.detail || `Error ${res.status}`, 'error');
      return { error: data.error || 'Request failed' };
    }

    return data;
  } catch (e) {
    showToast('Network error: ' + e.message, 'error');
    return { error: e.message };
  }
}
```

### Delete Confirmation

- Simple confirm() dialog before delete
- Cascade warning when deleting backend with servers

---

## Table Enhancements

### VHosts Table Header

```html
<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem">
  <h3>Virtual Hosts</h3>
  <button class="btn primary" onclick="showAddVhostModal()">+ Add VHost</button>
</div>
```

### VHosts Table Row

```html
<tr>
  <td>example.com</td>
  <td>web_backend</td>
  <td><span class="badge up">SSL</span> <span class="badge up">ACME</span></td>
  <td><span class="badge waf">Protected</span></td>
  <td>
    <button class="btn" onclick="showEditVhostModal(vhost)">Edit</button>
    <button class="btn danger" onclick="deleteVhost('example.com')">Delete</button>
  </td>
</tr>
```

### Backends Table Row (with server count)

```html
<tr>
  <td>web_backend</td>
  <td>http</td>
  <td>roundrobin</td>
  <td>3 servers <button class="btn" onclick="showBackendServers('web_backend')">Manage</button></td>
  <td>
    <button class="btn" onclick="showEditBackendModal(backend)">Edit</button>
    <button class="btn danger" onclick="deleteBackend('web_backend')">Delete</button>
  </td>
</tr>
```

---

## Testing Checklist

### VHost Operations
- [ ] Add vhost with all options
- [ ] Add vhost with minimal options (domain + backend only)
- [ ] Edit existing vhost
- [ ] Delete vhost with confirmation
- [ ] Validation errors display correctly
- [ ] Domain format validation works

### Backend Operations
- [ ] Add backend with health check
- [ ] Add backend without health check
- [ ] Edit backend settings
- [ ] Delete empty backend
- [ ] Delete backend with servers (cascade warning)

### Server Operations
- [ ] Add server to backend
- [ ] Edit server address/port
- [ ] Delete server
- [ ] Port validation (1-65535)

### Certificate Operations
- [ ] Request new certificate
- [ ] Progress indicator during request
- [ ] Delete certificate

### Error Handling
- [ ] API errors show toast
- [ ] Network errors handled gracefully
- [ ] 401 redirects to login
- [ ] Validation errors highlight field

### WAF Integration
- [ ] New vhosts default to WAF protected
- [ ] WAF bypass toggle works
- [ ] Config regenerated after changes

---

## Future Enhancements (Phase 2)

Not in scope for this implementation:

1. **ACL Management** — Add/edit/delete ACL rules
2. **Redirect Rules** — HTTP redirect management
3. **Settings Modal** — Global HAProxy configuration
4. **Async Certificate Tasks** — Progress polling like OpenWrt
5. **Backend Discovery** — Auto-detect available services

---

## Implementation Notes

### P31 Phosphor Theme Consistency

Use existing CSS variables:
- `--p31-peak: #00dd44` — Primary green
- `--p31-hot: #00ff55` — Highlight green
- `--p31-decay: #ffb347` — Amber/warning
- `--bloom-text` — Glow effect for headings
- `--bloom-soft` — Subtle glow for badges

### Modal Styling

```css
.modal {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.85);
  z-index: 100;
  align-items: center;
  justify-content: center;
}
.modal.active { display: flex; }
.modal-content {
  background: var(--tube-pale);
  border: 1px solid var(--p31-dim);
  border-radius: 8px;
  min-width: 400px;
  max-width: 600px;
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
  margin: 0;
}
.modal-body { padding: 1.25rem; }
.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: 0.5rem;
  padding: 1rem 1.25rem;
  border-top: 1px solid var(--p31-ghost);
}
```

### Form Input Styling

Use existing input styles from the page — they already match P31 Phosphor theme.

---

## Estimated Effort

| Component | Lines | Complexity |
|-----------|-------|------------|
| Modal system | ~50 | Low |
| Validation | ~30 | Low |
| Toast system | ~30 | Low |
| VHost CRUD | ~80 | Medium |
| Backend CRUD | ~80 | Medium |
| Server CRUD | ~70 | Medium |
| Certificate CRUD | ~60 | Medium |
| Table enhancements | ~50 | Low |
| **Total** | **~450** | **Medium** |

Single file modification, no build tooling required.
