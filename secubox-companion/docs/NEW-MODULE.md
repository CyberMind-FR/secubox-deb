<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# Create a Companion module in < 30 minutes

A module is a self-contained folder. The core discovers it at runtime — you
never touch `core/`.

## 1. Copy the template

```bash
cp -r www/modules/_template www/modules/mymodule
```

## 2. Fill `www/modules/mymodule/module.json`

```json
{
  "id": "mymodule",
  "name": "My Module",
  "module": "WALL",              // AUTH | WALL | BOOT | MIND | ROOT | MESH — sets the colour + dashboard order
  "icon": "🛡️",
  "description": "One line shown on the dashboard card.",
  "api_base": "/api/v1/mymodule",
  "status_endpoint": "/api/v1/mymodule/health",  // optional: live status on the card
  "capabilities": ["read", "write"],
  "routes": [{ "path": "", "label": "Overview" }]
}
```

## 3. Register it

Add the id to `www/modules/index.json`:

```json
{ "modules": ["billets", "podcasteur", "mymodule"] }
```

## 4. Write `www/modules/mymodule/view.js`

```js
export default async function mount(ctx) {
  const { root, api, base, ui, navigate } = ctx;
  const { el, esc, toast } = ui;

  const data = await api.get(`${base}/things`);        // GET, cached for offline
  root.append(el('div.card', {}, [
    el('h3', { text: 'Things' }),
    ...(data.things || []).map(t => el('div.item', {}, [
      el('div.meta', {}, [el('b', { text: esc(t.name) })]),
      el('button.btn.sm.primary', {
        text: 'Do', onclick: async () => {
          const r = await api.post(`${base}/things/${t.id}/do`, { when: 'now' });  // queued if offline
          toast(r.queued ? 'Queued' : 'Done ✓');
        },
      }),
    ])),
  ]));
}
```

## The `ctx` your module receives

| key | what |
|-----|------|
| `root` | the element to render into |
| `api` | `api.get(path, {cache})`, `api.post(path, body)`, `api.put`, `api.del` — bearer token added automatically; GETs cached; writes auto-queued offline and replayed on reconnect |
| `base` | your `module.json` `api_base` |
| `module` | your full manifest |
| `ui` | `{ el, esc, toast, ago, clear, confirmAction }` |
| `navigate` | `navigate('#/m/mymodule/sub')` |

## Rules

- **Every write goes through a real box endpoint** — no client-side admin logic,
  nothing that bypasses the box's invariants (OPAD). The box journals it.
- **Escape** any API value put into the DOM (`esc()` / `textContent`).
- Wear your module's colour: the panel + card pick it up from `module.json`'s
  `module` automatically.
- If a box route is unknown, still write clean `api.*` calls and mark them
  `TODO(api)` — don't block.

That's it. Reload the app; your card appears on the dashboard in canonical order.
