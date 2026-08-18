<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# FAQ — LXC container has no DNS / no internet

## Symptom

An app in an LXC (Nextcloud, PhotoPrism, PeerTube…) behaves as if offline:

- Nextcloud: *"Ce serveur ne peut se connecter à Internet"*, app store /
  optional addons don't show, update checks and external-storage mounts fail.
- `getent hosts apps.nextcloud.com` → nothing; `curl https://…` → `000`.
- But reaching the internet **by IP** works (`curl https://1.1.1.1` → 301).

That last point is the tell: **routing/NAT is fine, only name resolution is
broken.**

## Cause

The container's `/etc/resolv.conf` points at the systemd-resolved stub
`127.0.0.53`, but systemd-resolved has **no upstream** configured (the
containers are statically addressed, so there's no DHCP to hand one over).
A static `resolv.conf` written at install time gets **hijacked** by
systemd-resolved on boot — it replaces the file with a symlink to its stub.

Working containers (e.g. grafana) instead carry a direct
`nameserver 1.1.1.1` in `resolv.conf` and resolve fine.

## Fix (live, minimal)

Give systemd-resolved an explicit upstream inside the container:

```bash
lxc-attach -n <container> -- bash -c '
  mkdir -p /etc/systemd/resolved.conf.d
  printf "[Resolve]\nDNS=1.1.1.1 9.9.9.9\nFallbackDNS=8.8.8.8\n" \
    > /etc/systemd/resolved.conf.d/secubox-dns.conf
  systemctl restart systemd-resolved'
# verify
lxc-attach -n <container> -- getent hosts apps.nextcloud.com
```

NAT egress for the LXC bridge is already in the host ruleset
(`ip saddr 10.100.0.0/24 oifname != "br-lxc" masquerade`), so no firewall
change is needed — this is purely a resolver fix.

## Fix (persistent, in the installer)

New container builds must drop the same `resolved.conf.d/secubox-dns.conf` into
the rootfs alongside the static `resolv.conf`. Reference implementation:
`packages/secubox-nextcloud/sbin/nextcloudctl` (the `# DNS` block in the base
install). Apply the same pattern to every `install-lxc.sh` that provisions a
systemd container.

## Rule of thumb

When provisioning a statically-addressed LXC, **always configure
systemd-resolved's upstream**, don't rely on a static `resolv.conf` — it will
be overwritten.
