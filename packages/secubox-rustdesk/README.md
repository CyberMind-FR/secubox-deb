# secubox-rustdesk

[RustDesk](https://rustdesk.com) self-hosted remote-desktop signal (`hbbs`)
and relay (`hbbr`) servers in a Debian LXC at `10.100.0.90` on the SecuBox
`br-lxc` bridge.

Follows [`docs/MODULE-GUIDELINES.md`](../../docs/MODULE-GUIDELINES.md);
opens the **REMOTE-ACCESS** layer of the SecuBox CTL grammar.

## Why this module deviates from the grafana/yacy pattern

- **Two daemons** in the LXC (`hbbs` + `hbbr`), each on its own systemd
  unit. `rustdeskctl components` surfaces them as **separate** components,
  not aggregated.
- **Non-HTTP exposure** — RustDesk uses raw TCP on 21115/21116/21117 and
  UDP on 21116. mitmproxy cannot inspect raw UDP, so:
  - HAProxy **stream-mode** handles the three TCP ports (config shipped at
    `/etc/haproxy/secubox-streams/rustdesk-stream.cfg`)
  - **nftables DNAT** handles the UDP signal port (rule installed by
    `install-lxc.sh` into the `inet secubox` table)
  - Only the **web admin UI** (port 21114) goes through nginx like the
    other modules.

## Quickstart

```bash
apt install secubox-rustdesk
rustdeskctl install     # provisions LXC + hbbs + hbbr + nftables DNAT + PSK
rustdeskctl status
```

Pre-shared key for clients lives at `/etc/secubox/secrets/rustdesk-key`.
Embed it (and `relay = <your-public-ip>:21117`) into RustDesk client builds
or paste it into the client's *Custom Server* config.

## CTL — `rustdeskctl`

```text
rustdeskctl components   # lxc + hbbs + hbbr + host-api (4 components, not 3)
rustdeskctl status       # green only if all 4 are running
rustdeskctl access       # 4 URLs: lan-web, public-web, lan-signal, lan-relay
```

Module-specific nouns (v1.1.0 follow-up):

```text
rustdeskctl peer    list|add <id> <pubkey>|remove <id>
rustdeskctl relay   status|restart|log
rustdeskctl key     show|rotate
rustdeskctl session list|kill <id>

rustdeskctl install
rustdeskctl reload      # restarts host FastAPI + hbbs + hbbr
```

## Ports

| Port | Proto | Daemon | Exposure |
|---|---|---|---|
| 21114 | tcp | hbbs (web admin) | nginx `/rustdesk/` → iframe |
| 21115 | tcp | hbbs (NAT-test) | HAProxy stream-mode |
| 21116 | tcp | hbbs (signal) | HAProxy stream-mode |
| 21116 | udp | hbbs (signal) | nftables DNAT (mitmproxy can't inspect UDP) |
| 21117 | tcp | hbbr (relay) | HAProxy stream-mode |

## Files

```text
/etc/secubox/rustdesk.toml                # operator config
/etc/secubox/secrets/rustdesk-key         # pre-shared key (generated)
/etc/nginx/secubox.d/rustdesk.conf
/etc/haproxy/secubox-streams/rustdesk-stream.cfg
/usr/lib/secubox/rustdesk/api/            # host FastAPI
/usr/share/secubox/lib/rustdesk/          # install-lxc.sh
/usr/share/secubox/www/rustdesk/
/usr/share/secubox/menu.d/70-rustdesk.json
/data/lxc/rustdesk/                       # LXC rootfs (created by rustdeskctl install)
```

## Troubleshooting

- `rustdeskctl status` shows `hbbs: stopped` → `lxc-attach -n rustdesk -- journalctl -u rustdesk-hbbs`.
- UDP not forwarding → `nft list table inet secubox` should show the DNAT rule for 21116/udp.
- Client cannot connect → confirm PSK is identical on both ends; relay IP must be the **host's** public IP, not the LXC IP.
