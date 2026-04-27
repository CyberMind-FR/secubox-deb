## Testing Notes

- **Virtualization testing**: Use VirtualBox only (not QEMU)

---

## Wiki Sync Workflow

GitHub wiki is a **separate repository** from the main project. Files in `wiki/` folder must be synced manually.

### Quick Command
```bash
# Sync and push wiki to GitHub
bash scripts/sync-wiki.sh -p -m "Add Eye-Remote docs"

# Dry run (preview changes)
bash scripts/sync-wiki.sh -n
```

### Manual Workflow
```bash
# 1. Clone wiki repo
git clone git@github.com:CyberMind-FR/secubox-deb.wiki.git /tmp/wiki

# 2. Copy files
cp wiki/*.md /tmp/wiki/

# 3. Commit and push
cd /tmp/wiki
git add -A && git commit -m "Update wiki" && git push
```

### When to Sync
- After adding/editing any `wiki/*.md` file
- After bumping version in `wiki/_Sidebar.md`
- Before release (ensure docs match release)

### Red Links
If wiki links show as red on GitHub:
1. Verify file exists in `wiki/` folder
2. Run `scripts/sync-wiki.sh -p` to push to wiki repo
3. Check case sensitivity (GitHub wiki is case-sensitive)

---

## DSA Switch Loop Fix (ESPRESSObin)

**Problem:** mv88e6xxx driver infinite loop during boot
**Root Cause:** Live kernel has mv88e6xxx built-in (not module)
**Solution:** Use BOTH blacklists:
```bash
modprobe.blacklist=mv88e6xxx,mv88e6085,dsa_core initcall_blacklist=mv88e6xxx_driver_init
```

**Where to apply:**
- `boot.scr` — U-Boot boot script
- `extlinux/extlinux.conf` — fallback config
- `board/*/boot*.cmd` — source files
