<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox CLI: APT and Clone Commands Design

## Overview

Add APT repository management and system bootstrap commands to the `secubox` CLI tool.

**Commands:**
- `secubox apt` — Manage APT repository (client and server operations)
- `secubox clone` — Bootstrap a new SecuBox system interactively

## Architecture

**Hybrid approach:**
- Client operations (`apt setup`, `clone`) — Pure Go implementation
- Server operations (`apt init/publish/sync/list/remove/check`) — Wrap existing shell scripts

This leverages the robust shell scripts for complex reprepro operations while keeping client setup self-contained in the binary.

---

## Command: `secubox apt`

### Subcommands

| Command | Type | Description |
|---------|------|-------------|
| `secubox apt setup` | Client | Add SecuBox repo to system |
| `secubox apt init` | Server | Initialize local APT repository |
| `secubox apt publish <files>` | Server | Publish .deb packages |
| `secubox apt sync` | Server | Sync to apt.secubox.in |
| `secubox apt list` | Server | List packages in repository |
| `secubox apt remove <pkg>` | Server | Remove package from repository |
| `secubox apt check` | Server | Verify repository integrity |

### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--codename` | `-c` | bookworm | Distribution codename |
| `--component` | `-C` | main | Repository component |
| `--dry-run` | `-n` | false | Preview without executing |
| `--skip-lintian` | `-s` | false | Skip lintian validation (publish) |

### `apt setup` Implementation (Pure Go)

```go
func runAptSetup() error {
    // 1. Check root
    if os.Getuid() != 0 {
        return fmt.Errorf("must run as root")
    }

    // 2. Download GPG key
    resp, err := http.Get("https://apt.secubox.in/secubox.gpg")
    // Write to /usr/share/keyrings/secubox.gpg

    // 3. Write sources.list
    content := `deb [signed-by=/usr/share/keyrings/secubox.gpg] https://apt.secubox.in bookworm main`
    os.WriteFile("/etc/apt/sources.list.d/secubox.list", []byte(content), 0644)

    // 4. Run apt update
    exec.Command("apt", "update").Run()
}
```

### Server Subcommands Implementation (Script Wrappers)

| Subcommand | Implementation |
|------------|----------------|
| `apt init` | Copy `apt/conf/*` to `/srv/apt/conf/`, exec `reprepro export` |
| `apt publish` | Exec `scripts/apt-publish.sh` with flags |
| `apt sync` | Exec `scripts/apt-sync.sh` with flags |
| `apt list` | Exec `reprepro list <codename>` |
| `apt remove` | Exec `reprepro remove <codename> <pkg>` |
| `apt check` | Exec `reprepro check` |

---

## Command: `secubox clone`

Bootstrap wizard for new SecuBox installations.

### Workflow

```
1. Check root permissions
2. Add SecuBox repository (reuse apt setup logic)
   - Download GPG key
   - Write sources.list
   - Run apt update
3. Interactive wizard (promptui)
   - Select tier: Lite / Standard / Pro / Minimal / Custom
   - If Custom: multi-select packages
4. Install selected packages via apt install
```

### Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--tier` | `-t` | Install specific tier (lite/standard/pro) |
| `--minimal` | | Install secubox-core + secubox-hub only |
| `--packages` | `-p` | Comma-separated package list |
| `--yes` | `-y` | Auto-confirm apt prompts |

### Tier Package Mapping

| Tier | Meta-package | Description |
|------|--------------|-------------|
| Lite | `secubox-lite` | 1-2GB RAM devices (ESPRESSObin) |
| Standard | `secubox-standard` | 4GB RAM, general purpose |
| Pro | `secubox-full` | 8GB+ RAM, all features |
| Minimal | `secubox-core secubox-hub` | Base only |

### Interactive Wizard

```
$ secubox clone

SecuBox Bootstrap Wizard
========================

Adding SecuBox repository...
✓ GPG key installed
✓ Repository added
✓ Package list updated

Select installation tier:
  › Lite (1-2GB RAM) - ESPRESSObin, basic security
    Standard (4GB RAM) - General purpose
    Pro (8GB+ RAM) - Full features, MOCHAbin
    Minimal - Core + Hub only
    Custom - Pick individual packages

[User selects "Standard"]

Installing secubox-standard...
[apt output]

✓ SecuBox installation complete!

Access dashboard at: https://<IP>:9443
Default credentials: admin / secubox
```

### Non-Interactive Examples

```bash
# Install pro tier
secubox clone --tier pro -y

# Minimal install
secubox clone --minimal -y

# Specific packages
secubox clone --packages "secubox-core,secubox-hub,secubox-crowdsec" -y
```

---

## File Structure

```
cmd/secubox/cmd/
├── apt.go              # apt parent command + setup subcommand
├── apt_server.go       # Server subcommands (init, publish, sync, list, remove, check)
└── clone.go            # Bootstrap wizard

cmd/secubox/internal/apt/
├── client.go           # Client operations (setup, GPG download)
├── server.go           # Server operations (script wrappers)
└── packages.go         # Package/tier resolution
```

---

## Error Handling

| Scenario | Handling |
|----------|----------|
| Not root | Exit with message: "must run as root (use sudo)" |
| Network error (GPG) | Retry 3 times with 2s backoff |
| reprepro not found | Exit with: "reprepro not installed (apt install reprepro)" |
| Script failure | Display stderr, exit with script's exit code |
| Invalid tier | Exit with: "invalid tier: X (valid: lite, standard, pro)" |

---

## Dependencies

**Client operations:**
- Go `net/http` for GPG key download
- `apt` command (exec)

**Server operations:**
- `reprepro` — APT repository management
- `rsync` — Remote sync
- `lintian` — Package validation (optional)
- `gpg` — Package signing

---

## Testing

**Unit tests:**
- Sources.list content generation
- Tier to package mapping
- Flag parsing

**Integration tests:**
- Mock apt commands via interface
- Test wizard flow with mock promptui

**Manual test script:**
```bash
# Test full workflow on fresh Debian VM
sudo secubox clone --tier lite -y
systemctl status secubox-hub
```

---

## Success Criteria

- [ ] `secubox apt setup` adds repository to fresh Debian system
- [ ] `secubox apt publish *.deb` publishes packages with lintian check
- [ ] `secubox apt sync` uploads to apt.secubox.in
- [ ] `secubox clone` wizard completes full installation
- [ ] `secubox clone --tier pro -y` works non-interactively
- [ ] All commands show help with `--help`
