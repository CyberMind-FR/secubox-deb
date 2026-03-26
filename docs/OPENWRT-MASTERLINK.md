# OpenWRT Master-Link Client Implementation

## Goal
Add Master-Link client support to SecuBox OpenWRT to join a SecuBox Debian mesh network.

---

## Files to Create/Modify

### 1. `/usr/bin/sbx-mesh-join` - Shell script
Already compatible with OpenWRT - uses wget, uci, br-lan detection.
Copy from secubox-deb: `packages/secubox-p2p/scripts/sbx-mesh-join`

### 2. `/usr/libexec/rpcd/luci.masterlink` - RPCD backend
```lua
-- Methods needed:
-- status: Get current mesh membership status
-- join: Join a mesh using token
-- leave: Leave current mesh
-- info: Get local node info (fingerprint, hostname, IP)
```

### 3. `/usr/share/luci/menu.d/luci-app-masterlink.json` - Menu entry
```json
{
  "admin/services/masterlink": {
    "title": "Master-Link",
    "order": 90,
    "action": { "type": "view", "path": "masterlink/join" }
  }
}
```

### 4. `/www/luci-static/resources/view/masterlink/join.js` - LuCI JS view
```javascript
// UI Features:
// - Input field for invite URL or token
// - Parse URL to extract master IP + token
// - Show master info before joining (fingerprint verification)
// - Join button → calls luci.masterlink/join
// - Status display: Not joined / Pending / Approved
```

### 5. `/etc/config/masterlink` - UCI config
```
config mesh 'settings'
    option enabled '0'
    option role 'peer'
    option master_ip ''
    option master_fingerprint ''
    option local_fingerprint ''
    option depth '0'
    option joined_at ''
```

### 6. `/etc/secubox/node.id` - Persistent node fingerprint
```bash
# Generate on first boot:
owrt-$(cat /sys/class/net/br-lan/address | tr -d ':')
```

---

## RPCD Script (`/usr/libexec/rpcd/luci.masterlink`)

```bash
#!/bin/sh
. /usr/share/libubox/jshn.sh

NODE_ID_FILE="/etc/secubox/node.id"
CONFIG_FILE="/etc/config/masterlink"

get_fingerprint() {
    if [ -f "$NODE_ID_FILE" ]; then
        cat "$NODE_ID_FILE"
    else
        mkdir -p /etc/secubox
        local fp="owrt-$(cat /sys/class/net/br-lan/address 2>/dev/null | tr -d ':')"
        echo "$fp" > "$NODE_ID_FILE"
        echo "$fp"
    fi
}

get_local_ip() {
    ip -4 addr show br-lan 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1
}

case "$1" in
    list)
        echo '{"status":{},"join":{"master_ip":"str","token":"str"},"leave":{},"info":{}}'
        ;;
    call)
        case "$2" in
            status)
                json_init
                json_add_string "role" "$(uci -q get masterlink.settings.role || echo 'standalone')"
                json_add_string "master_ip" "$(uci -q get masterlink.settings.master_ip)"
                json_add_string "fingerprint" "$(get_fingerprint)"
                json_add_boolean "enabled" "$(uci -q get masterlink.settings.enabled || echo 0)"
                json_dump
                ;;
            join)
                read -r input
                json_load "$input"
                json_get_var master_ip master_ip
                json_get_var token token

                local fp=$(get_fingerprint)
                local hostname=$(uci get system.@system[0].hostname)
                local address=$(get_local_ip)

                # Call master API
                local response=$(wget -qO- --post-data="{\"token\":\"$token\",\"fingerprint\":\"$fp\",\"hostname\":\"$hostname\",\"address\":\"$address\"}" \
                    --header="Content-Type: application/json" \
                    "http://$master_ip:7331/api/v1/p2p/master-link/join" 2>/dev/null)

                # Parse response
                local status=$(echo "$response" | jsonfilter -e '@.status')

                if [ "$status" = "approved" ]; then
                    uci set masterlink.settings.enabled='1'
                    uci set masterlink.settings.role='peer'
                    uci set masterlink.settings.master_ip="$master_ip"
                    uci commit masterlink
                fi

                echo "$response"
                ;;
            leave)
                uci set masterlink.settings.enabled='0'
                uci set masterlink.settings.role='standalone'
                uci delete masterlink.settings.master_ip
                uci commit masterlink
                json_init
                json_add_string "status" "ok"
                json_dump
                ;;
            info)
                json_init
                json_add_string "fingerprint" "$(get_fingerprint)"
                json_add_string "hostname" "$(uci get system.@system[0].hostname)"
                json_add_string "address" "$(get_local_ip)"
                json_add_string "model" "$(cat /tmp/sysinfo/model 2>/dev/null)"
                json_dump
                ;;
        esac
        ;;
esac
```

---

## LuCI View (`/www/luci-static/resources/view/masterlink/join.js`)

```javascript
'use strict';
'require view';
'require form';
'require rpc';
'require ui';

var callMasterLinkStatus = rpc.declare({
    object: 'luci.masterlink',
    method: 'status'
});

var callMasterLinkJoin = rpc.declare({
    object: 'luci.masterlink',
    method: 'join',
    params: ['master_ip', 'token']
});

var callMasterLinkLeave = rpc.declare({
    object: 'luci.masterlink',
    method: 'leave'
});

var callMasterLinkInfo = rpc.declare({
    object: 'luci.masterlink',
    method: 'info'
});

return view.extend({
    load: function() {
        return Promise.all([
            callMasterLinkStatus(),
            callMasterLinkInfo()
        ]);
    },

    render: function(data) {
        var status = data[0];
        var info = data[1];
        var view = this;

        var container = E('div', { 'class': 'cbi-map' }, [
            E('h2', {}, _('Master-Link')),
            E('div', { 'class': 'cbi-map-descr' },
                _('Join a SecuBox mesh network using an invite token.'))
        ]);

        // Status section
        var statusSection = E('div', { 'class': 'cbi-section' }, [
            E('h3', {}, _('Mesh Status')),
            E('div', { 'class': 'cbi-value' }, [
                E('label', { 'class': 'cbi-value-title' }, _('Status')),
                E('div', { 'class': 'cbi-value-field' },
                    status.enabled == 1
                        ? E('span', { 'style': 'color:green' }, '✓ Connected to ' + status.master_ip)
                        : E('span', { 'style': 'color:gray' }, 'Not connected'))
            ]),
            E('div', { 'class': 'cbi-value' }, [
                E('label', { 'class': 'cbi-value-title' }, _('Fingerprint')),
                E('div', { 'class': 'cbi-value-field' },
                    E('code', {}, info.fingerprint || 'Unknown'))
            ]),
            E('div', { 'class': 'cbi-value' }, [
                E('label', { 'class': 'cbi-value-title' }, _('Hostname')),
                E('div', { 'class': 'cbi-value-field' }, info.hostname || 'Unknown')
            ]),
            E('div', { 'class': 'cbi-value' }, [
                E('label', { 'class': 'cbi-value-title' }, _('Local IP')),
                E('div', { 'class': 'cbi-value-field' }, info.address || 'Unknown')
            ])
        ]);
        container.appendChild(statusSection);

        // Join section (only if not connected)
        if (status.enabled != 1) {
            var joinSection = E('div', { 'class': 'cbi-section' }, [
                E('h3', {}, _('Join Mesh')),
                E('div', { 'class': 'cbi-value' }, [
                    E('label', { 'class': 'cbi-value-title' }, _('Invite URL or Token')),
                    E('div', { 'class': 'cbi-value-field' }, [
                        E('input', {
                            'type': 'text',
                            'id': 'invite_input',
                            'class': 'cbi-input-text',
                            'style': 'width: 100%; max-width: 500px;',
                            'placeholder': 'http://192.168.1.1:7331/master-link/?token=abc123...'
                        })
                    ])
                ]),
                E('div', { 'class': 'cbi-value' }, [
                    E('label', { 'class': 'cbi-value-title' }, ''),
                    E('div', { 'class': 'cbi-value-field' }, [
                        E('button', {
                            'class': 'cbi-button cbi-button-apply',
                            'click': function() {
                                var input = document.getElementById('invite_input').value;
                                var match = input.match(/(\d+\.\d+\.\d+\.\d+).*token=([^&\s]+)/);
                                var master_ip, token;

                                if (match) {
                                    master_ip = match[1];
                                    token = match[2];
                                } else if (input.includes(' ')) {
                                    // Format: "IP TOKEN"
                                    var parts = input.trim().split(/\s+/);
                                    master_ip = parts[0];
                                    token = parts[1];
                                } else {
                                    ui.addNotification(null, E('p', _('Invalid invite format')), 'error');
                                    return;
                                }

                                ui.showModal(_('Joining...'), [
                                    E('p', { 'class': 'spinning' }, _('Connecting to master...'))
                                ]);

                                callMasterLinkJoin(master_ip, token).then(function(res) {
                                    ui.hideModal();
                                    if (res.status == 'approved') {
                                        ui.addNotification(null, E('p', _('Successfully joined mesh!')), 'success');
                                        window.location.reload();
                                    } else if (res.status == 'pending') {
                                        ui.addNotification(null, E('p', _('Waiting for master approval. Your fingerprint: ') + info.fingerprint), 'warning');
                                    } else {
                                        ui.addNotification(null, E('p', _('Failed: ') + JSON.stringify(res)), 'error');
                                    }
                                }).catch(function(err) {
                                    ui.hideModal();
                                    ui.addNotification(null, E('p', _('Error: ') + err), 'error');
                                });
                            }
                        }, _('Join Mesh'))
                    ])
                ])
            ]);
            container.appendChild(joinSection);
        } else {
            // Leave section
            var leaveSection = E('div', { 'class': 'cbi-section' }, [
                E('h3', {}, _('Leave Mesh')),
                E('div', { 'class': 'cbi-value' }, [
                    E('label', { 'class': 'cbi-value-title' }, ''),
                    E('div', { 'class': 'cbi-value-field' }, [
                        E('button', {
                            'class': 'cbi-button cbi-button-remove',
                            'click': function() {
                                if (confirm(_('Are you sure you want to leave the mesh?'))) {
                                    callMasterLinkLeave().then(function() {
                                        ui.addNotification(null, E('p', _('Left mesh network')), 'success');
                                        window.location.reload();
                                    });
                                }
                            }
                        }, _('Leave Mesh'))
                    ])
                ])
            ]);
            container.appendChild(leaveSection);
        }

        return container;
    }
});
```

---

## UCI Default Config (`/etc/config/masterlink`)

```
config mesh 'settings'
    option enabled '0'
    option role 'standalone'
    option master_ip ''
    option master_fingerprint ''
    option depth '0'
```

---

## Package Makefile

```makefile
include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-masterlink
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Gerald KERMA <devel@cybermind.fr>
PKG_LICENSE:=GPL-3.0

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-masterlink
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=SecuBox Master-Link mesh client
  DEPENDS:=+luci-base +wget +jsonfilter
  PKGARCH:=all
endef

define Package/luci-app-masterlink/description
  LuCI application for joining SecuBox mesh networks via Master-Link.
  Allows OpenWRT devices to join a SecuBox Debian master node.
endef

define Package/luci-app-masterlink/install
	$(INSTALL_DIR) $(1)/usr/libexec/rpcd
	$(INSTALL_BIN) ./files/luci.masterlink $(1)/usr/libexec/rpcd/

	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d
	$(INSTALL_DATA) ./files/luci-app-masterlink.json $(1)/usr/share/luci/menu.d/

	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./files/luci-app-masterlink.acl $(1)/usr/share/rpcd/acl.d/

	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/masterlink
	$(INSTALL_DATA) ./files/join.js $(1)/www/luci-static/resources/view/masterlink/

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/masterlink.config $(1)/etc/config/masterlink

	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/sbx-mesh-join $(1)/usr/bin/
endef

define Package/luci-app-masterlink/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || /etc/init.d/rpcd restart
exit 0
endef

$(eval $(call BuildPackage,luci-app-masterlink))
```

---

## ACL File (`/usr/share/rpcd/acl.d/luci-app-masterlink.acl`)

```json
{
    "luci-app-masterlink": {
        "description": "Grant access to Master-Link mesh functions",
        "read": {
            "ubus": {
                "luci.masterlink": ["status", "info"]
            },
            "uci": ["masterlink"]
        },
        "write": {
            "ubus": {
                "luci.masterlink": ["join", "leave"]
            },
            "uci": ["masterlink"]
        }
    }
}
```

---

## Directory Structure

```
luci-app-masterlink/
├── Makefile
└── files/
    ├── luci.masterlink              # RPCD backend script
    ├── luci-app-masterlink.json     # Menu entry
    ├── luci-app-masterlink.acl      # ACL permissions
    ├── masterlink.config            # UCI default config
    ├── join.js                      # LuCI JS view
    └── sbx-mesh-join                # CLI tool (copy from Debian)
```

---

## Testing Commands

```bash
# On OpenWRT device:

# 1. Test CLI join
sbx-mesh-join 192.168.1.1 abc123token456

# Or with URL
sbx-mesh-join 'http://192.168.1.1:7331/master-link/?token=abc123'

# 2. Test RPCD methods
ubus call luci.masterlink status
ubus call luci.masterlink info
ubus call luci.masterlink join '{"master_ip":"192.168.1.1","token":"abc123"}'
ubus call luci.masterlink leave

# 3. Check UCI config
uci show masterlink

# 4. Restart RPCD after changes
/etc/init.d/rpcd restart
```

---

## Workflow Summary

### On SecuBox Debian (Master)
1. Generate invite: `POST /api/v1/p2p/master-link/invite`
2. Copy the invite URL or CLI command

### On OpenWRT (Client)
**Option A - Web UI:**
1. Go to Services → Master-Link
2. Paste invite URL
3. Click "Join Mesh"

**Option B - CLI:**
```bash
sbx-mesh-join 'http://master-ip:7331/master-link/?token=xxx'
```

**Option C - One-liner:**
```bash
wget -qO- 'http://master-ip:7331/api/v1/p2p/master-link/join-script?token=xxx' | sh
```

---

## See Also
- SecuBox Debian P2P API: `packages/secubox-p2p/api/main.py`
- Join script: `packages/secubox-p2p/scripts/sbx-mesh-join`
- Master-Link web UI: `packages/secubox-p2p/www/master-link/`
