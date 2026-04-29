#!/usr/bin/env python3
"""
SecuBox-DEB :: Migration Transformer
CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>

Transform OpenWrt UCI configs to Debian formats (TOML, netplan, nftables, dnsmasq).

Usage:
    python3 migration-transform.py uci-to-toml <input.uci> <output.toml>
    python3 migration-transform.py network-to-netplan <network.uci> <output.yaml>
    python3 migration-transform.py firewall-to-nftables <firewall.uci> <output.nft>
    python3 migration-transform.py dhcp-to-dnsmasq <dhcp.uci> <output.conf>
    python3 migration-transform.py transform-all <input-dir> <output-dir>
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

# Try to import toml, fall back to basic serialization
try:
    import tomli_w
    HAS_TOML = True
except ImportError:
    try:
        import toml
        HAS_TOML = True
    except ImportError:
        HAS_TOML = False

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


class UCIParser:
    """Parse OpenWrt UCI configuration format."""

    def __init__(self):
        self.config = {}

    def parse(self, content: str) -> dict:
        """Parse UCI config content into structured dict."""
        self.config = {}
        current_section = None
        current_type = None
        current_name = None
        section_counter = {}

        for line in content.splitlines():
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue

            # Config section: config <type> ['<name>']
            match = re.match(r"config\s+(\w+)(?:\s+['\"]?(\w+)['\"]?)?", line)
            if match:
                current_type = match.group(1)
                current_name = match.group(2)

                # Generate name if not provided
                if not current_name:
                    section_counter.setdefault(current_type, 0)
                    current_name = f"{current_type}{section_counter[current_type]}"
                    section_counter[current_type] += 1

                # Initialize section
                self.config.setdefault(current_type, {})
                self.config[current_type][current_name] = {'_type': current_type}
                current_section = self.config[current_type][current_name]
                continue

            # Option: option <key> '<value>'
            match = re.match(r"option\s+(\w+)\s+['\"]?(.*?)['\"]?\s*$", line)
            if match and current_section is not None:
                key = match.group(1)
                value = match.group(2).strip("'\"")
                current_section[key] = self._parse_value(value)
                continue

            # List: list <key> '<value>'
            match = re.match(r"list\s+(\w+)\s+['\"]?(.*?)['\"]?\s*$", line)
            if match and current_section is not None:
                key = match.group(1)
                value = match.group(2).strip("'\"")
                current_section.setdefault(key, [])
                if not isinstance(current_section[key], list):
                    current_section[key] = [current_section[key]]
                current_section[key].append(self._parse_value(value))
                continue

        return self.config

    def _parse_value(self, value: str) -> Any:
        """Parse a UCI value to appropriate Python type."""
        if value.lower() in ('1', 'yes', 'on', 'true', 'enabled'):
            return True
        if value.lower() in ('0', 'no', 'off', 'false', 'disabled'):
            return False
        if value.isdigit():
            return int(value)
        try:
            return float(value)
        except ValueError:
            pass
        return value


class NetworkTransformer:
    """Transform UCI network config to netplan YAML."""

    def transform(self, uci_config: dict) -> dict:
        """Transform UCI network config to netplan format."""
        netplan = {
            'network': {
                'version': 2,
                'renderer': 'networkd',
                'ethernets': {},
                'bridges': {},
                'vlans': {}
            }
        }

        interfaces = uci_config.get('interface', {})
        devices = uci_config.get('device', {})

        for name, iface in interfaces.items():
            if name in ('loopback',):
                continue

            # Get device name
            device = iface.get('device', iface.get('ifname', ''))
            if not device:
                continue

            # Handle bridges
            if iface.get('type') == 'bridge':
                bridge_ports = iface.get('ports', [])
                if isinstance(bridge_ports, str):
                    bridge_ports = [bridge_ports]

                netplan['network']['bridges'][device] = {
                    'interfaces': bridge_ports,
                    'parameters': {
                        'stp': iface.get('stp', False),
                        'forward-delay': iface.get('forward_delay', 4)
                    }
                }

                # Add IP config to bridge
                self._add_ip_config(netplan['network']['bridges'][device], iface)
            else:
                # Regular ethernet interface
                eth_config = {}
                self._add_ip_config(eth_config, iface)

                if eth_config:
                    netplan['network']['ethernets'][device] = eth_config

        return netplan

    def _add_ip_config(self, config: dict, iface: dict):
        """Add IP configuration to netplan interface."""
        proto = iface.get('proto', 'dhcp')

        if proto == 'dhcp':
            config['dhcp4'] = True
        elif proto == 'static':
            ipaddr = iface.get('ipaddr')
            netmask = iface.get('netmask', '255.255.255.0')

            if ipaddr:
                # Convert netmask to CIDR
                cidr = self._netmask_to_cidr(netmask)
                config['addresses'] = [f"{ipaddr}/{cidr}"]

            gateway = iface.get('gateway')
            if gateway:
                config['routes'] = [{'to': 'default', 'via': gateway}]

            dns = iface.get('dns', [])
            if isinstance(dns, str):
                dns = dns.split()
            if dns:
                config['nameservers'] = {'addresses': dns}

    def _netmask_to_cidr(self, netmask: str) -> int:
        """Convert netmask to CIDR notation."""
        netmask_map = {
            '255.255.255.255': 32, '255.255.255.254': 31,
            '255.255.255.252': 30, '255.255.255.248': 29,
            '255.255.255.240': 28, '255.255.255.224': 27,
            '255.255.255.192': 26, '255.255.255.128': 25,
            '255.255.255.0': 24, '255.255.254.0': 23,
            '255.255.252.0': 22, '255.255.248.0': 21,
            '255.255.240.0': 20, '255.255.224.0': 19,
            '255.255.192.0': 18, '255.255.128.0': 17,
            '255.255.0.0': 16, '255.254.0.0': 15,
            '255.252.0.0': 14, '255.248.0.0': 13,
            '255.240.0.0': 12, '255.224.0.0': 11,
            '255.192.0.0': 10, '255.128.0.0': 9,
            '255.0.0.0': 8
        }
        return netmask_map.get(netmask, 24)


class FirewallTransformer:
    """Transform UCI firewall config to nftables."""

    def transform(self, uci_config: dict) -> str:
        """Transform UCI firewall config to nftables format."""
        lines = [
            '#!/usr/sbin/nft -f',
            '# SecuBox-DEB nftables rules',
            '# Migrated from OpenWrt UCI firewall',
            '',
            'flush ruleset',
            '',
            'table inet filter {',
        ]

        # Process zones
        zones = uci_config.get('zone', {})
        zone_policies = {}

        for name, zone in zones.items():
            zone_name = zone.get('name', name)
            input_policy = zone.get('input', 'DROP').upper()
            output_policy = zone.get('output', 'ACCEPT').upper()
            forward_policy = zone.get('forward', 'DROP').upper()
            zone_policies[zone_name] = {
                'input': input_policy,
                'output': output_policy,
                'forward': forward_policy,
                'network': zone.get('network', [])
            }

        # Input chain
        lines.append('    chain input {')
        lines.append('        type filter hook input priority 0; policy drop;')
        lines.append('')
        lines.append('        # Accept established/related')
        lines.append('        ct state established,related accept')
        lines.append('        ct state invalid drop')
        lines.append('')
        lines.append('        # Accept loopback')
        lines.append('        iifname "lo" accept')
        lines.append('')

        # Add rules from UCI
        rules = uci_config.get('rule', {})
        for rule_name, rule in rules.items():
            if rule.get('target') == 'ACCEPT' and rule.get('dest') in ('', None):
                nft_rule = self._convert_rule(rule, 'input')
                if nft_rule:
                    lines.append(f'        {nft_rule}')

        lines.append('    }')
        lines.append('')

        # Forward chain
        lines.append('    chain forward {')
        lines.append('        type filter hook forward priority 0; policy drop;')
        lines.append('')
        lines.append('        ct state established,related accept')
        lines.append('        ct state invalid drop')
        lines.append('')

        # Forwarding rules
        forwardings = uci_config.get('forwarding', {})
        for fwd_name, fwd in forwardings.items():
            src = fwd.get('src', '')
            dest = fwd.get('dest', '')
            if src and dest:
                lines.append(f'        # Forward: {src} -> {dest}')
                lines.append(f'        meta nfproto ipv4 accept comment "fwd-{src}-{dest}"')

        lines.append('    }')
        lines.append('')

        # Output chain
        lines.append('    chain output {')
        lines.append('        type filter hook output priority 0; policy accept;')
        lines.append('    }')
        lines.append('}')
        lines.append('')

        # NAT table
        lines.append('table inet nat {')
        lines.append('    chain prerouting {')
        lines.append('        type nat hook prerouting priority dstnat;')

        # Port redirects
        redirects = uci_config.get('redirect', {})
        for redir_name, redir in redirects.items():
            nft_rule = self._convert_redirect(redir)
            if nft_rule:
                lines.append(f'        {nft_rule}')

        lines.append('    }')
        lines.append('')
        lines.append('    chain postrouting {')
        lines.append('        type nat hook postrouting priority srcnat;')
        lines.append('        oifname "wan*" masquerade')
        lines.append('    }')
        lines.append('}')
        lines.append('')

        return '\n'.join(lines)

    def _convert_rule(self, rule: dict, chain: str) -> str:
        """Convert a UCI rule to nftables format."""
        parts = []

        # Protocol
        proto = rule.get('proto', 'tcp')
        if proto and proto != 'all':
            parts.append(f'meta l4proto {proto}')

        # Source
        src_ip = rule.get('src_ip')
        if src_ip:
            parts.append(f'ip saddr {src_ip}')

        # Destination port
        dest_port = rule.get('dest_port')
        if dest_port:
            parts.append(f'{proto} dport {dest_port}')

        # Target
        target = rule.get('target', 'ACCEPT').lower()
        parts.append(target)

        # Comment
        name = rule.get('name', '')
        if name:
            parts.append(f'comment "{name}"')

        return ' '.join(parts) if parts else ''

    def _convert_redirect(self, redir: dict) -> str:
        """Convert a UCI redirect to nftables DNAT."""
        proto = redir.get('proto', 'tcp')
        src_dport = redir.get('src_dport')
        dest_ip = redir.get('dest_ip')
        dest_port = redir.get('dest_port', src_dport)
        name = redir.get('name', 'redirect')

        if not all([src_dport, dest_ip]):
            return ''

        return f'{proto} dport {src_dport} dnat to {dest_ip}:{dest_port} comment "{name}"'


class DHCPTransformer:
    """Transform UCI dhcp config to dnsmasq format."""

    def transform(self, uci_config: dict) -> str:
        """Transform UCI dhcp config to dnsmasq.conf format."""
        lines = [
            '# SecuBox-DEB dnsmasq configuration',
            '# Migrated from OpenWrt UCI dhcp',
            '',
            '# General settings',
            'domain-needed',
            'bogus-priv',
            'expand-hosts',
            ''
        ]

        # Process dnsmasq section
        dnsmasq = uci_config.get('dnsmasq', {})
        for name, cfg in dnsmasq.items():
            domain = cfg.get('domain', 'lan')
            lines.append(f'domain={domain}')
            lines.append(f'local=/{domain}/')

            # DNS servers
            servers = cfg.get('server', [])
            if isinstance(servers, str):
                servers = [servers]
            for server in servers:
                lines.append(f'server={server}')

            # Rebind protection
            if cfg.get('rebind_protection', True):
                lines.append('stop-dns-rebind')
                rebind_allowed = cfg.get('rebind_domain', [])
                if isinstance(rebind_allowed, str):
                    rebind_allowed = [rebind_allowed]
                for domain in rebind_allowed:
                    lines.append(f'rebind-domain-ok={domain}')

        lines.append('')

        # Process DHCP pools
        dhcp_pools = uci_config.get('dhcp', {})
        for name, pool in dhcp_pools.items():
            interface = pool.get('interface', name)
            start = pool.get('start', 100)
            limit = pool.get('limit', 150)
            leasetime = pool.get('leasetime', '12h')

            if pool.get('ignore', False):
                continue

            lines.append(f'# DHCP pool: {interface}')
            lines.append(f'dhcp-range=tag:{interface},{start},{start + limit - 1},{leasetime}')
            lines.append('')

        # Static hosts
        hosts = uci_config.get('host', {})
        if hosts:
            lines.append('# Static DHCP leases')
        for name, host in hosts.items():
            mac = host.get('mac', '')
            ip = host.get('ip', '')
            hostname = host.get('name', name)

            if mac and ip:
                lines.append(f'dhcp-host={mac},{ip},{hostname}')

        lines.append('')

        # Domain entries
        domains = uci_config.get('domain', {})
        if domains:
            lines.append('# DNS records')
        for name, entry in domains.items():
            domain_name = entry.get('name', '')
            ip = entry.get('ip', '')
            if domain_name and ip:
                lines.append(f'address=/{domain_name}/{ip}')

        return '\n'.join(lines)


class MigrationTransformer:
    """Main transformer class for SecuBox migration."""

    def __init__(self):
        self.uci_parser = UCIParser()
        self.network_transformer = NetworkTransformer()
        self.firewall_transformer = FirewallTransformer()
        self.dhcp_transformer = DHCPTransformer()

    def uci_to_dict(self, uci_content: str) -> dict:
        """Parse UCI content to dictionary."""
        return self.uci_parser.parse(uci_content)

    def uci_to_toml(self, uci_content: str) -> str:
        """Convert UCI config to TOML format."""
        config = self.uci_parser.parse(uci_content)

        # Clean up internal fields
        cleaned = self._clean_for_toml(config)

        if HAS_TOML:
            try:
                import tomli_w
                return tomli_w.dumps(cleaned)
            except ImportError:
                import toml
                return toml.dumps(cleaned)
        else:
            # Basic TOML serialization
            return self._basic_toml_dumps(cleaned)

    def _clean_for_toml(self, obj: Any) -> Any:
        """Clean object for TOML serialization."""
        if isinstance(obj, dict):
            return {
                k: self._clean_for_toml(v)
                for k, v in obj.items()
                if not k.startswith('_')
            }
        elif isinstance(obj, list):
            return [self._clean_for_toml(v) for v in obj]
        return obj

    def _basic_toml_dumps(self, obj: dict, prefix: str = '') -> str:
        """Basic TOML serialization without external dependencies."""
        lines = []

        for key, value in obj.items():
            if isinstance(value, dict):
                # Check if it contains only primitives
                has_nested = any(isinstance(v, dict) for v in value.values())
                if has_nested:
                    for subkey, subvalue in value.items():
                        if isinstance(subvalue, dict):
                            section = f'{prefix}{key}.{subkey}' if prefix else f'{key}.{subkey}'
                            lines.append(f'\n[{section}]')
                            lines.append(self._basic_toml_dumps(subvalue, f'{section}.'))
                else:
                    section = f'{prefix}{key}' if prefix else key
                    lines.append(f'\n[{section}]')
                    for k, v in value.items():
                        lines.append(f'{k} = {self._toml_value(v)}')
            else:
                lines.append(f'{key} = {self._toml_value(value)}')

        return '\n'.join(lines)

    def _toml_value(self, value: Any) -> str:
        """Convert value to TOML representation."""
        if isinstance(value, bool):
            return 'true' if value else 'false'
        elif isinstance(value, (int, float)):
            return str(value)
        elif isinstance(value, list):
            items = ', '.join(self._toml_value(v) for v in value)
            return f'[{items}]'
        else:
            # Escape string
            escaped = str(value).replace('\\', '\\\\').replace('"', '\\"')
            return f'"{escaped}"'

    def network_to_netplan(self, uci_content: str) -> str:
        """Convert UCI network config to netplan YAML."""
        config = self.uci_parser.parse(uci_content)
        netplan = self.network_transformer.transform(config)

        if HAS_YAML:
            return yaml.dump(netplan, default_flow_style=False, sort_keys=False)
        else:
            # Basic YAML output
            return self._basic_yaml_dumps(netplan)

    def _basic_yaml_dumps(self, obj: Any, indent: int = 0) -> str:
        """Basic YAML serialization without external dependencies."""
        lines = []
        prefix = '  ' * indent

        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, dict):
                    lines.append(f'{prefix}{key}:')
                    lines.append(self._basic_yaml_dumps(value, indent + 1))
                elif isinstance(value, list):
                    lines.append(f'{prefix}{key}:')
                    for item in value:
                        if isinstance(item, dict):
                            lines.append(f'{prefix}  -')
                            for k, v in item.items():
                                lines.append(f'{prefix}    {k}: {v}')
                        else:
                            lines.append(f'{prefix}  - {item}')
                else:
                    lines.append(f'{prefix}{key}: {value}')
        elif isinstance(obj, list):
            for item in obj:
                lines.append(f'{prefix}- {item}')

        return '\n'.join(lines)

    def firewall_to_nftables(self, uci_content: str) -> str:
        """Convert UCI firewall config to nftables."""
        config = self.uci_parser.parse(uci_content)
        return self.firewall_transformer.transform(config)

    def dhcp_to_dnsmasq(self, uci_content: str) -> str:
        """Convert UCI dhcp config to dnsmasq.conf."""
        config = self.uci_parser.parse(uci_content)
        return self.dhcp_transformer.transform(config)

    def transform_all(self, input_dir: Path, output_dir: Path):
        """Transform all configs in a migration archive."""
        output_dir.mkdir(parents=True, exist_ok=True)

        # Network → netplan
        network_uci = input_dir / 'configs' / 'network' / 'network.uci'
        if network_uci.exists():
            content = network_uci.read_text()
            netplan = self.network_to_netplan(content)
            (output_dir / 'netplan').mkdir(exist_ok=True)
            (output_dir / 'netplan' / '00-secubox.yaml').write_text(netplan)
            print(f'  Created: netplan/00-secubox.yaml')

        # Firewall → nftables
        firewall_uci = input_dir / 'configs' / 'firewall' / 'firewall.uci'
        if firewall_uci.exists():
            content = firewall_uci.read_text()
            nft = self.firewall_to_nftables(content)
            (output_dir / 'nftables.conf').write_text(nft)
            print(f'  Created: nftables.conf')

        # DHCP → dnsmasq
        dhcp_uci = input_dir / 'configs' / 'dhcp' / 'dhcp.uci'
        if dhcp_uci.exists():
            content = dhcp_uci.read_text()
            dnsmasq = self.dhcp_to_dnsmasq(content)
            (output_dir / 'dnsmasq.conf').write_text(dnsmasq)
            print(f'  Created: dnsmasq.conf')

        # Generic UCI → TOML for other configs
        for uci_file in input_dir.glob('configs/**/*.uci'):
            if uci_file.name in ('network.uci', 'firewall.uci', 'dhcp.uci'):
                continue  # Already handled

            content = uci_file.read_text()
            toml_content = self.uci_to_toml(content)

            rel_path = uci_file.relative_to(input_dir / 'configs')
            toml_path = output_dir / rel_path.parent / f'{uci_file.stem}.toml'
            toml_path.parent.mkdir(parents=True, exist_ok=True)
            toml_path.write_text(toml_content)
            print(f'  Created: {toml_path.relative_to(output_dir)}')


def main():
    parser = argparse.ArgumentParser(
        description='SecuBox Migration Transformer - Convert OpenWrt UCI to Debian formats'
    )
    subparsers = parser.add_subparsers(dest='command', help='Transformation command')

    # uci-to-toml
    p_toml = subparsers.add_parser('uci-to-toml', help='Convert UCI to TOML')
    p_toml.add_argument('input', help='Input UCI file')
    p_toml.add_argument('output', help='Output TOML file')

    # network-to-netplan
    p_net = subparsers.add_parser('network-to-netplan', help='Convert network UCI to netplan YAML')
    p_net.add_argument('input', help='Input network.uci file')
    p_net.add_argument('output', help='Output netplan YAML file')

    # firewall-to-nftables
    p_fw = subparsers.add_parser('firewall-to-nftables', help='Convert firewall UCI to nftables')
    p_fw.add_argument('input', help='Input firewall.uci file')
    p_fw.add_argument('output', help='Output nftables file')

    # dhcp-to-dnsmasq
    p_dhcp = subparsers.add_parser('dhcp-to-dnsmasq', help='Convert dhcp UCI to dnsmasq.conf')
    p_dhcp.add_argument('input', help='Input dhcp.uci file')
    p_dhcp.add_argument('output', help='Output dnsmasq.conf file')

    # transform-all
    p_all = subparsers.add_parser('transform-all', help='Transform all configs from migration archive')
    p_all.add_argument('input_dir', help='Input directory (extracted migration archive)')
    p_all.add_argument('output_dir', help='Output directory for transformed configs')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    transformer = MigrationTransformer()

    if args.command == 'uci-to-toml':
        content = Path(args.input).read_text()
        result = transformer.uci_to_toml(content)
        Path(args.output).write_text(result)
        print(f'Converted: {args.input} -> {args.output}')

    elif args.command == 'network-to-netplan':
        content = Path(args.input).read_text()
        result = transformer.network_to_netplan(content)
        Path(args.output).write_text(result)
        print(f'Converted: {args.input} -> {args.output}')

    elif args.command == 'firewall-to-nftables':
        content = Path(args.input).read_text()
        result = transformer.firewall_to_nftables(content)
        Path(args.output).write_text(result)
        print(f'Converted: {args.input} -> {args.output}')

    elif args.command == 'dhcp-to-dnsmasq':
        content = Path(args.input).read_text()
        result = transformer.dhcp_to_dnsmasq(content)
        Path(args.output).write_text(result)
        print(f'Converted: {args.input} -> {args.output}')

    elif args.command == 'transform-all':
        transformer.transform_all(Path(args.input_dir), Path(args.output_dir))
        print('Transformation complete')


if __name__ == '__main__':
    main()
