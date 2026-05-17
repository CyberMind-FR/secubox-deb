# Eye Remote — Multi-Gadget Limitation

Status: known limitation as of issue #155 fix.

## What works

The host (MOCHAbin / ESPRESSObin SecuBox) accepts an arbitrary number of Pi
RNDIS USB gadgets simultaneously plugged into its USB hub. Each gadget
enumerates as a `Linux Foundation Multifunction Composite Gadget`
(`1d6b:0104`) with kernel-assigned names `usb0`, `usb1`, … and udev
(`/etc/udev/rules.d/90-secubox-eye-remote.rules`) enslaves each one into
the `eye-br0` bridge created by systemd-networkd
(`/etc/systemd/network/05-eye-br0.netdev`, `10-eye-br0.network`).

The bridge owns the host IP **10.55.0.1/24** and survives gadget hot-plug
thanks to `ConfigureWithoutCarrier=yes`. Each gadget is also exposed as
its own ACM serial endpoint under `/dev/ttyACM*` (the `eye-console`
symlink only points at the first ACM by udev order — that is intentional;
use `udevadm info` to map each ACM device to a specific gadget when
needed).

## What does *not* work — peer-IP collision at L3

Every Round image currently flashes the same static peer configuration on
the gadget side: **`10.55.0.2/30`** with host `10.55.0.1`. As a result,
when two or more Round gadgets are plugged into the same host they all
claim **the same** L3 address (`10.55.0.2`). The Linux bridge ARPs them
in order; whichever Pi answers first wins, and traffic to `10.55.0.2`
from the host is non-deterministically routed to one of them.

The eye-br0 bridge keeps the **L2** topology clean — no host-side
duplicate IP, no rp_filter drops, no per-port routing ambiguity — but it
cannot solve a duplicate-address L3 conflict that originates on the Pi
side.

### Symptoms

- `ping 10.55.0.2` from the host alternates RTT / TTL between gadgets
- `ssh root@10.55.0.2` may land on either Pi depending on cache state
- `arp -n` on the host shows a flapping MAC for `10.55.0.2`

### Workaround for "one Pi at a time"

Unplug the gadgets you don't want active. The bridge keeps `10.55.0.1`
live regardless, so the API at `http://10.55.0.1:8000` stays reachable
whenever any single gadget is plugged in.

### Proper fix — Round image change (future)

The Round image needs to derive its peer IP from its own MAC address
(or run a tiny DHCP client requesting a unique lease from
`secubox-eye-remote`). Sketch:

```bash
# /etc/systemd/network/10-secubox-eye.network on the Pi
[Network]
DHCP=yes
LinkLocalAddressing=no
```

…paired with a host-side `dnsmasq` (or `systemd-networkd` DHCP server
section) on `eye-br0` handing out leases from `10.55.0.10/24` upward,
keyed by MAC for stable addressing.

This is **out of scope for issue #155** — that fix is purely host-side.
Track the follow-up in its own issue when the Round image rework starts.

## Verification commands

```bash
ip -br link show type bridge                # eye-br0 should be UP
ip -br addr show eye-br0                    # 10.55.0.1/24
bridge link show                            # usb0/usb1/… should list master eye-br0
journalctl -t secubox-eye-remote --since -10m
curl -s http://10.55.0.1:8000/api/v1/eye-remote/health
```
