<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# FAQ: Busybox Emergency Recovery

## The Problem

**Symptom:** All commands fail with "cannot execute: required file not found"

```bash
root@host:~# ls
-bash: /usr/bin/ls: cannot execute: required file not found
root@host:~# ln -s foo bar
-bash: /usr/bin/ln: cannot execute: required file not found
```

**Cause:** The `/lib` symlink (pointing to `/usr/lib`) was replaced by a directory, breaking access to `libc.so` and the dynamic linker.

**Common trigger:** Extracting a tarball containing `lib/` at root level:
```bash
# DANGEROUS - overwrites /lib symlink!
cd / && tar xzf modules.tar.gz
```

---

## The Solution: Busybox

Busybox is typically **statically linked** - it doesn't need libc to run.

### Step 1: Check if busybox exists
```bash
echo /bin/busybox
echo /usr/bin/busybox
```

### Step 2: Use busybox to fix the symlink
```bash
# Remove broken /lib directory
/bin/busybox rm -rf /lib

# Recreate the symlink
/bin/busybox ln -s usr/lib /lib

# Verify
/bin/busybox ls -la /lib
```

### Step 3: Test recovery
```bash
ls -la /lib/aarch64-linux-gnu/libc.so*
cat /etc/os-release
uname -r
```

---

## Why This Works

| Component | Location | Status when /lib broken |
|-----------|----------|------------------------|
| libc.so | `/usr/lib/aarch64-linux-gnu/` | Exists but inaccessible |
| ld-linux | `/usr/lib/aarch64-linux-gnu/` | Exists but inaccessible |
| /lib | Should be symlink to `usr/lib` | **Broken** - is a directory |
| busybox | `/bin/busybox` | **Works** - statically linked |

Busybox contains 300+ commands in a single static binary. When libc is inaccessible, it's your lifeline.

---

## Prevention

### Safe tarball extraction for kernel modules:
```bash
# WRONG
cd / && tar xzf modules.tar.gz

# RIGHT - extract only the modules subdirectory
tar xzf modules.tar.gz -C /lib/modules/ --strip-components=2

# OR create tarball with correct structure
cd /build/output/modules/lib/modules
tar czf modules-6.6.137.tar.gz 6.6.137
# Then on target:
cd /lib/modules && tar xzf /tmp/modules-6.6.137.tar.gz
```

### Check before extracting:
```bash
# Always check tarball contents first!
tar tzf modules.tar.gz | head -20

# Look for dangerous top-level paths:
# lib/  <- DANGER if extracted at /
# usr/  <- DANGER
# bin/  <- DANGER
```

---

## Shell Built-ins When Nothing Works

If no busybox available, bash built-ins still work:

```bash
# List files (glob expansion)
echo /lib/*
echo /usr/lib/aarch64-linux-gnu/libc*

# Read file content
while IFS= read -r line; do echo "$line"; done < /etc/os-release

# Check if path exists
[[ -d /lib/aarch64-linux-gnu ]] && echo "exists" || echo "missing"

# Write to file
echo "test" > /tmp/test
```

---

## Last Resort: Rescue Boot

If no busybox and shell built-ins can't help:

1. Boot from USB/SD rescue media
2. Mount the broken rootfs:
   ```bash
   mount /dev/mmcblk0p2 /mnt
   ```
3. Fix the symlink:
   ```bash
   rm -rf /mnt/lib
   ln -s usr/lib /mnt/lib
   ```
4. Reboot normally

---

## Key Takeaways

1. **Always have busybox installed** (statically linked)
2. **Never extract tarballs blindly at /**
3. **Check tarball contents before extracting**
4. **Know your shell built-ins** (echo, read, [[ ]])
5. **Keep rescue media ready** for emergencies

---

*SecuBox-Deb Emergency Recovery Guide*
*CyberMind — https://cybermind.fr*
*Author: Gerald Kerma <gandalf@gk2.net>*
*Incident: 2026-05-08*
