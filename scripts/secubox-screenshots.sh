#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SecuBox Screenshots — Capture all module pages for documentation
#  Usage: bash scripts/secubox-screenshots.sh [--url URL] [--output DIR]
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────
BASE_URL="${SECUBOX_URL:-https://localhost:9443}"
OUTPUT_DIR="${OUTPUT_DIR:-docs/screenshots}"
USERNAME="${SECUBOX_USER:-admin}"
PASSWORD="${SECUBOX_PASS:-admin}"
VIEWPORT="1920x1080"
WAIT_TIME=3000  # ms to wait for page load
CHROMIUM=""

RED='\033[0;31m'; CYAN='\033[0;36m'; GOLD='\033[0;33m'
GREEN='\033[0;32m'; NC='\033[0m'

log()  { echo -e "${CYAN}[screenshot]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK ]${NC} $*"; }
err()  { echo -e "${RED}[FAIL ]${NC} $*" >&2; }
warn() { echo -e "${GOLD}[ WARN]${NC} $*"; }

# ── Parse args ────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --url)      BASE_URL="$2"; shift 2 ;;
        --output)   OUTPUT_DIR="$2"; shift 2 ;;
        --user)     USERNAME="$2"; shift 2 ;;
        --pass)     PASSWORD="$2"; shift 2 ;;
        --viewport) VIEWPORT="$2"; shift 2 ;;
        --wait)     WAIT_TIME="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --url URL        Base URL (default: https://localhost:9443)"
            echo "  --output DIR     Output directory (default: docs/screenshots)"
            echo "  --user USER      Username (default: admin)"
            echo "  --pass PASS      Password (default: admin)"
            echo "  --viewport WxH   Viewport size (default: 1920x1080)"
            echo "  --wait MS        Wait time per page in ms (default: 3000)"
            echo ""
            echo "Environment variables:"
            echo "  SECUBOX_URL, SECUBOX_USER, SECUBOX_PASS"
            exit 0
            ;;
        *) err "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Find Chromium ─────────────────────────────────────────────────
find_chromium() {
    for cmd in chromium chromium-browser google-chrome google-chrome-stable chrome; do
        if command -v "$cmd" &>/dev/null; then
            CHROMIUM="$cmd"
            return 0
        fi
    done
    # Check common paths
    for path in /usr/bin/chromium /usr/bin/chromium-browser /snap/bin/chromium \
                /usr/bin/google-chrome /opt/google/chrome/chrome; do
        if [[ -x "$path" ]]; then
            CHROMIUM="$path"
            return 0
        fi
    done
    return 1
}

if ! find_chromium; then
    err "Chromium not found. Install with: apt install chromium"
    exit 1
fi
log "Using browser: $CHROMIUM"

# ── Create output directory ───────────────────────────────────────
mkdir -p "$OUTPUT_DIR"
log "Output directory: $OUTPUT_DIR"

# ── Module URLs to capture ────────────────────────────────────────
# Format: "filename|path|description"
# These are the main SecuBox routes from the web interface

declare -a MODULES=(
    # Main SecuBox Hub pages
    "home|/|Home / Login page"
    "dashboard|/cgi-bin/luci/admin/secubox/dashboard|Main Dashboard"
    "wizard|/cgi-bin/luci/admin/secubox/wizard|Setup Wizard"
    "modules|/cgi-bin/luci/admin/secubox/modules|Modules Overview"
    "apps|/cgi-bin/luci/admin/secubox/apps|App Store"
    "monitoring|/cgi-bin/luci/admin/secubox/monitoring|Monitoring"
    "alerts|/cgi-bin/luci/admin/secubox/alerts|Alerts"
    "settings|/cgi-bin/luci/admin/secubox/settings|Settings"
    "help|/cgi-bin/luci/admin/secubox/help|Help / Bonus"

    # Security modules
    "crowdsec|/cgi-bin/luci/admin/services/crowdsec|CrowdSec Dashboard"
    "crowdsec-decisions|/cgi-bin/luci/admin/services/crowdsec/decisions|CrowdSec Decisions"
    "crowdsec-bouncers|/cgi-bin/luci/admin/services/crowdsec/bouncers|CrowdSec Bouncers"
    "crowdsec-scenarios|/cgi-bin/luci/admin/services/crowdsec/scenarios|CrowdSec Scenarios"
    "waf|/cgi-bin/luci/admin/services/waf|WAF Dashboard"
    "waf-rules|/cgi-bin/luci/admin/services/waf/rules|WAF Rules"
    "threats|/cgi-bin/luci/admin/services/threats|Threats Dashboard"
    "ipblock|/cgi-bin/luci/admin/services/ipblock|IP Blocklist"
    "mac-guard|/cgi-bin/luci/admin/services/mac-guard|MAC Guard"
    "nac|/cgi-bin/luci/admin/services/nac|Network Access Control"
    "auth|/cgi-bin/luci/admin/services/auth|Authentication"
    "hardening|/cgi-bin/luci/admin/services/hardening|System Hardening"

    # Network modules
    "wireguard|/cgi-bin/luci/admin/services/wireguard|WireGuard VPN"
    "wireguard-peers|/cgi-bin/luci/admin/services/wireguard/peers|WireGuard Peers"
    "haproxy|/cgi-bin/luci/admin/services/haproxy|HAProxy Load Balancer"
    "netmodes|/cgi-bin/luci/admin/services/netmodes|Network Modes"
    "dpi|/cgi-bin/luci/admin/services/dpi|Deep Packet Inspection"
    "qos|/cgi-bin/luci/admin/services/qos|QoS / Bandwidth"
    "vhost|/cgi-bin/luci/admin/services/vhost|Virtual Hosts"
    "cdn|/cgi-bin/luci/admin/services/cdn|CDN Cache"
    "dns|/cgi-bin/luci/admin/services/dns|DNS Management"
    "dns-guard|/cgi-bin/luci/admin/services/dns-guard|DNS Guard"
    "vortex-dns|/cgi-bin/luci/admin/services/vortex-dns|Vortex DNS"
    "vortex-firewall|/cgi-bin/luci/admin/services/vortex-firewall|Vortex Firewall"
    "routes|/cgi-bin/luci/admin/services/routes|Routing"
    "traffic|/cgi-bin/luci/admin/services/traffic|Traffic Monitor"
    "mesh|/cgi-bin/luci/admin/services/mesh|Mesh Network"
    "tor|/cgi-bin/luci/admin/services/tor|Tor Service"
    "exposure|/cgi-bin/luci/admin/services/exposure|Exposure Engine"

    # Monitoring modules
    "netdata|/cgi-bin/luci/admin/services/netdata|Netdata Metrics"
    "glances|/cgi-bin/luci/admin/services/glances|Glances"
    "metrics|/cgi-bin/luci/admin/services/metrics|System Metrics"
    "watchdog|/cgi-bin/luci/admin/services/watchdog|Watchdog"
    "netdiag|/cgi-bin/luci/admin/services/netdiag|Network Diagnostics"

    # System modules
    "system|/cgi-bin/luci/admin/services/system|System Management"
    "system-hub|/cgi-bin/luci/admin/services/system-hub|System Hub"
    "users|/cgi-bin/luci/admin/services/users|User Management"
    "backup|/cgi-bin/luci/admin/services/backup|Backup & Restore"
    "console|/cgi-bin/luci/admin/services/console|Web Console"

    # Application modules
    "mail|/cgi-bin/luci/admin/services/mail|Mail Server"
    "webmail|/cgi-bin/luci/admin/services/webmail|Webmail"
    "gitea|/cgi-bin/luci/admin/services/gitea|Gitea Git Server"
    "nextcloud|/cgi-bin/luci/admin/services/nextcloud|Nextcloud"
    "jellyfin|/cgi-bin/luci/admin/services/jellyfin|Jellyfin Media"
    "matrix|/cgi-bin/luci/admin/services/matrix|Matrix Chat"
    "jabber|/cgi-bin/luci/admin/services/jabber|XMPP/Jabber"
    "jitsi|/cgi-bin/luci/admin/services/jitsi|Jitsi Meet"
    "peertube|/cgi-bin/luci/admin/services/peertube|PeerTube"
    "photoprism|/cgi-bin/luci/admin/services/photoprism|PhotoPrism"
    "homeassistant|/cgi-bin/luci/admin/services/homeassistant|Home Assistant"
    "domoticz|/cgi-bin/luci/admin/services/domoticz|Domoticz"

    # AI modules
    "ollama|/cgi-bin/luci/admin/services/ollama|Ollama LLM"
    "localai|/cgi-bin/luci/admin/services/localai|LocalAI"
    "ai-gateway|/cgi-bin/luci/admin/services/ai-gateway|AI Gateway"
    "ai-insights|/cgi-bin/luci/admin/services/ai-insights|AI Insights"

    # Publishing modules
    "droplet|/cgi-bin/luci/admin/services/droplet|Droplet Publisher"
    "streamlit|/cgi-bin/luci/admin/services/streamlit|Streamlit Apps"
    "metablogizer|/cgi-bin/luci/admin/services/metablogizer|Metablogizer"
    "hexo|/cgi-bin/luci/admin/services/hexo|Hexo Blog"

    # SOC modules
    "soc|/cgi-bin/luci/admin/services/soc|SOC Dashboard"
    "soc-agent|/cgi-bin/luci/admin/services/soc-agent|SOC Agent"
    "device-intel|/cgi-bin/luci/admin/services/device-intel|Device Intelligence"
    "cve-triage|/cgi-bin/luci/admin/services/cve-triage|CVE Triage"
    "threat-analyst|/cgi-bin/luci/admin/services/threat-analyst|Threat Analyst"
    "network-anomaly|/cgi-bin/luci/admin/services/network-anomaly|Network Anomaly"

    # Other modules
    "identity|/cgi-bin/luci/admin/services/identity|Identity Manager"
    "vault|/cgi-bin/luci/admin/services/vault|Secrets Vault"
    "mcp-server|/cgi-bin/luci/admin/services/mcp-server|MCP Server"
    "c3box|/cgi-bin/luci/admin/services/c3box|C3BOX Terminal"
    "portal|/cgi-bin/luci/admin/services/portal|Captive Portal"
    "interceptor|/cgi-bin/luci/admin/services/interceptor|Traffic Interceptor"
    "mitmproxy|/cgi-bin/luci/admin/services/mitmproxy|MITMProxy"
    "mediaflow|/cgi-bin/luci/admin/services/mediaflow|Media Flow"
    "torrent|/cgi-bin/luci/admin/services/torrent|Torrent Client"
    "simplex|/cgi-bin/luci/admin/services/simplex|SimpleX Chat"
    "gotosocial|/cgi-bin/luci/admin/services/gotosocial|GoToSocial"
    "turn|/cgi-bin/luci/admin/services/turn|TURN Server"
    "voip|/cgi-bin/luci/admin/services/voip|VoIP"
    "mqtt|/cgi-bin/luci/admin/services/mqtt|MQTT Broker"
    "zigbee|/cgi-bin/luci/admin/services/zigbee|Zigbee Gateway"
    "iot-guard|/cgi-bin/luci/admin/services/iot-guard|IoT Guard"
    "ad-guard|/cgi-bin/luci/admin/services/ad-guard|AdGuard"
    "webradio|/cgi-bin/luci/admin/services/webradio|Web Radio"
    "lyrion|/cgi-bin/luci/admin/services/lyrion|Lyrion Music"
    "cyberfeed|/cgi-bin/luci/admin/services/cyberfeed|Cyber Feed"
    "newsbin|/cgi-bin/luci/admin/services/newsbin|Newsbin"
    "cloner|/cgi-bin/luci/admin/services/cloner|Site Cloner"
    "reporter|/cgi-bin/luci/admin/services/reporter|Reporter"
    "roadmap|/cgi-bin/luci/admin/services/roadmap|Roadmap"
    "zkp|/cgi-bin/luci/admin/services/zkp|ZKP Authentication"
    "p2p|/cgi-bin/luci/admin/services/p2p|P2P Network"
)

# ── Screenshot function using Chromium headless ───────────────────
take_screenshot() {
    local name="$1"
    local path="$2"
    local desc="$3"
    local url="${BASE_URL}${path}"
    local outfile="${OUTPUT_DIR}/${name}.png"

    log "Capturing: $desc"
    log "  URL: $url"

    # Chromium headless screenshot with SSL ignore
    timeout 30 "$CHROMIUM" \
        --headless=new \
        --disable-gpu \
        --no-sandbox \
        --disable-dev-shm-usage \
        --ignore-certificate-errors \
        --ignore-ssl-errors \
        --window-size="${VIEWPORT/x/,}" \
        --screenshot="$outfile" \
        --virtual-time-budget="$WAIT_TIME" \
        "$url" 2>/dev/null || {
            warn "Failed to capture: $name"
            return 1
        }

    if [[ -f "$outfile" ]]; then
        local size=$(du -h "$outfile" | cut -f1)
        ok "Saved: ${name}.png ($size)"
        return 0
    else
        warn "Screenshot not created: $name"
        return 1
    fi
}

# ── Alternative: Use Node.js puppeteer for authenticated screenshots ──
create_puppeteer_script() {
    cat > "${OUTPUT_DIR}/capture.js" << 'PUPPETEER'
const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');

const BASE_URL = process.env.SECUBOX_URL || 'https://localhost:9443';
const USERNAME = process.env.SECUBOX_USER || 'admin';
const PASSWORD = process.env.SECUBOX_PASS || 'admin';
const OUTPUT_DIR = process.env.OUTPUT_DIR || 'docs/screenshots';
const WAIT_TIME = parseInt(process.env.WAIT_TIME || '3000');

// Read modules from stdin or use defaults
const MODULES = JSON.parse(process.env.MODULES || '[]');

async function captureScreenshots() {
    const browser = await puppeteer.launch({
        headless: 'new',
        ignoreHTTPSErrors: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox', '--window-size=1920,1080']
    });

    const page = await browser.newPage();
    await page.setViewport({ width: 1920, height: 1080 });

    // Login first
    console.log('Logging in...');
    try {
        await page.goto(`${BASE_URL}/cgi-bin/luci/`, { waitUntil: 'networkidle2', timeout: 30000 });

        // Wait for login form
        await page.waitForSelector('input[name="luci_username"], input[name="username"], #username', { timeout: 5000 });

        // Fill credentials
        const usernameField = await page.$('input[name="luci_username"]') ||
                              await page.$('input[name="username"]') ||
                              await page.$('#username');
        const passwordField = await page.$('input[name="luci_password"]') ||
                              await page.$('input[name="password"]') ||
                              await page.$('#password');

        if (usernameField && passwordField) {
            await usernameField.type(USERNAME);
            await passwordField.type(PASSWORD);

            // Submit form
            const submitBtn = await page.$('input[type="submit"], button[type="submit"], .cbi-button-apply');
            if (submitBtn) {
                await submitBtn.click();
                await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 10000 }).catch(() => {});
            }
        }
        console.log('Login complete');
    } catch (e) {
        console.log('Login skipped or failed:', e.message);
    }

    // Capture each module
    let captured = 0;
    let failed = 0;

    for (const mod of MODULES) {
        const [name, urlPath, desc] = mod.split('|');
        const url = `${BASE_URL}${urlPath}`;
        const outfile = path.join(OUTPUT_DIR, `${name}.png`);

        console.log(`Capturing: ${desc || name}`);
        console.log(`  URL: ${url}`);

        try {
            await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
            await page.waitForTimeout(WAIT_TIME);
            await page.screenshot({ path: outfile, fullPage: false });

            const stats = fs.statSync(outfile);
            console.log(`  OK: ${name}.png (${Math.round(stats.size / 1024)}KB)`);
            captured++;
        } catch (e) {
            console.log(`  FAILED: ${name} - ${e.message}`);
            failed++;
        }
    }

    await browser.close();

    console.log(`\nComplete: ${captured} captured, ${failed} failed`);
    return { captured, failed };
}

captureScreenshots().catch(console.error);
PUPPETEER
    log "Created puppeteer script: ${OUTPUT_DIR}/capture.js"
}

# ── Main capture loop ─────────────────────────────────────────────
log "Starting SecuBox screenshot capture"
log "Base URL: $BASE_URL"
log "Modules to capture: ${#MODULES[@]}"
echo ""

# Check if we should use puppeteer (if available)
if command -v node &>/dev/null && command -v npm &>/dev/null; then
    if [[ -f "node_modules/puppeteer/package.json" ]] || npm list puppeteer &>/dev/null 2>&1; then
        log "Puppeteer available - using for authenticated capture"
        create_puppeteer_script

        # Convert modules array to JSON
        MODULES_JSON=$(printf '%s\n' "${MODULES[@]}" | jq -R -s -c 'split("\n") | map(select(length > 0))')

        SECUBOX_URL="$BASE_URL" \
        SECUBOX_USER="$USERNAME" \
        SECUBOX_PASS="$PASSWORD" \
        OUTPUT_DIR="$OUTPUT_DIR" \
        WAIT_TIME="$WAIT_TIME" \
        MODULES="$MODULES_JSON" \
        node "${OUTPUT_DIR}/capture.js"

        exit $?
    fi
fi

# Fallback to basic Chromium headless (no auth)
warn "Puppeteer not available - using basic Chromium headless (no auth)"
warn "For authenticated capture: npm install puppeteer"
echo ""

captured=0
failed=0

for module in "${MODULES[@]}"; do
    IFS='|' read -r name path desc <<< "$module"
    if take_screenshot "$name" "$path" "${desc:-$name}"; then
        ((captured++))
    else
        ((failed++))
    fi
done

echo ""
log "════════════════════════════════════════════════════════════"
log "Screenshot capture complete"
log "  Captured: $captured"
log "  Failed:   $failed"
log "  Output:   $OUTPUT_DIR/"
log "════════════════════════════════════════════════════════════"

# Generate index.html for easy viewing
cat > "${OUTPUT_DIR}/index.html" << 'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecuBox Module Screenshots</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0a0f;
            color: #e8e6d9;
            margin: 0;
            padding: 20px;
        }
        h1 {
            color: #c9a84c;
            text-align: center;
            margin-bottom: 30px;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
            gap: 20px;
            max-width: 1800px;
            margin: 0 auto;
        }
        .card {
            background: #151932;
            border: 1px solid #2d2d5a;
            border-radius: 12px;
            overflow: hidden;
        }
        .card img {
            width: 100%;
            height: auto;
            display: block;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .card img:hover {
            transform: scale(1.02);
        }
        .card-title {
            padding: 12px 16px;
            background: #1e2139;
            font-weight: 500;
            color: #00d4ff;
        }
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.9);
            z-index: 1000;
            cursor: pointer;
        }
        .modal img {
            max-width: 95%;
            max-height: 95%;
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
        }
        .modal.active { display: block; }
    </style>
</head>
<body>
    <h1>⚡ SecuBox Module Screenshots</h1>
    <div class="grid" id="gallery"></div>
    <div class="modal" id="modal" onclick="closeModal()">
        <img id="modal-img" src="" alt="">
    </div>
    <script>
        const modules = MODULES_PLACEHOLDER;
        const gallery = document.getElementById('gallery');
        const modal = document.getElementById('modal');
        const modalImg = document.getElementById('modal-img');

        modules.forEach(m => {
            const [name, path, desc] = m.split('|');
            const card = document.createElement('div');
            card.className = 'card';
            card.innerHTML = `
                <img src="${name}.png" alt="${desc || name}"
                     onerror="this.parentElement.style.display='none'"
                     onclick="openModal('${name}.png')">
                <div class="card-title">${desc || name}</div>
            `;
            gallery.appendChild(card);
        });

        function openModal(src) {
            modalImg.src = src;
            modal.classList.add('active');
        }
        function closeModal() {
            modal.classList.remove('active');
        }
        document.addEventListener('keydown', e => {
            if (e.key === 'Escape') closeModal();
        });
    </script>
</body>
</html>
HTML

# Replace placeholder with actual modules
MODULES_JS=$(printf '%s\n' "${MODULES[@]}" | jq -R -s -c 'split("\n") | map(select(length > 0))')
sed -i "s|MODULES_PLACEHOLDER|$MODULES_JS|" "${OUTPUT_DIR}/index.html"

ok "Generated index.html for viewing screenshots"
log "Open: file://${PWD}/${OUTPUT_DIR}/index.html"
