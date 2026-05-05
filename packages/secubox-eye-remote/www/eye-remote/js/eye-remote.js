/**
 * SecuBox Eye Remote — WebUI Management Dashboard
 * CyberMind — https://cybermind.fr
 * Author: Gérald Kerma <gandalf@gk2.net>
 *
 * Module JavaScript pour la gestion de l'interface Eye Remote.
 * Gère les interactions API, l'affichage des appareils et l'appairage QR.
 */

(function() {
    'use strict';

    // === Configuration ===
    const CONFIG = {
        apiBase: '/api/v1/eye-remote',
        refreshInterval: 10000,  // 10 secondes
        toastDuration: 4000,     // 4 secondes
        qrSize: 200              // Taille du QR code en pixels
    };

    // === État de l'application ===
    const state = {
        devices: [],
        isOnline: false,
        refreshTimer: null,
        countdownTimer: null,
        qrExpiration: null,
        refreshCountdown: CONFIG.refreshInterval / 1000
    };

    // === Éléments DOM (cache) ===
    const DOM = {};

    /**
     * Initialise le cache des éléments DOM.
     */
    function initDOM() {
        DOM.statusIndicator = document.getElementById('status-indicator');
        DOM.statusText = document.getElementById('status-text');
        DOM.deviceListContainer = document.getElementById('device-list-container');
        DOM.statTotal = document.getElementById('stat-total');
        DOM.statOtg = document.getElementById('stat-otg');
        DOM.statWifi = document.getElementById('stat-wifi');
        DOM.statOffline = document.getElementById('stat-offline');
        DOM.btnGenerateQr = document.getElementById('btn-generate-qr');
        DOM.btnRefreshQr = document.getElementById('btn-refresh-qr');
        DOM.qrContainer = document.getElementById('qr-container');
        DOM.qrCode = document.getElementById('qr-code');
        DOM.pairingCode = document.getElementById('pairing-code');
        DOM.pairingUrl = document.getElementById('pairing-url');
        DOM.countdown = document.getElementById('countdown');
        DOM.countdownTimer = document.getElementById('countdown-timer');
        DOM.toastContainer = document.getElementById('toast-container');
        DOM.refreshIndicator = document.getElementById('refresh-indicator');
        DOM.refreshCountdown = document.getElementById('refresh-countdown');
    }

    // === API Helpers ===

    /**
     * Effectue une requête API.
     * @param {string} endpoint - Endpoint relatif à apiBase
     * @param {Object} options - Options fetch additionnelles
     * @returns {Promise<Object>} Réponse JSON
     */
    async function apiRequest(endpoint, options = {}) {
        const url = `${CONFIG.apiBase}${endpoint}`;
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        };

        try {
            const response = await fetch(url, { ...defaultOptions, ...options });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.detail || `HTTP ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error(`API Error [${endpoint}]:`, error);
            throw error;
        }
    }

    /**
     * Vérifie l'état de santé de l'API.
     * @returns {Promise<boolean>} True si l'API répond
     */
    async function checkHealth() {
        try {
            const data = await apiRequest('/health');
            return data.status === 'ok';
        } catch {
            return false;
        }
    }

    /**
     * Récupère la liste des appareils appairés.
     * @returns {Promise<Object>} {devices: Array, count: number}
     */
    async function fetchDevices() {
        return await apiRequest('/devices');
    }

    /**
     * Supprime l'appairage d'un appareil.
     * @param {string} deviceId - ID de l'appareil
     * @returns {Promise<Object>} Réponse de suppression
     */
    async function unpairDevice(deviceId) {
        return await apiRequest(`/devices/${deviceId}`, { method: 'DELETE' });
    }

    /**
     * Génère un nouveau QR code d'appairage.
     * @returns {Promise<Object>} {code, url, host, expires_in}
     */
    async function generatePairingQR() {
        return await apiRequest('/pair/qr');
    }

    // === UI Helpers ===

    /**
     * Affiche une notification toast.
     * @param {string} message - Message à afficher
     * @param {string} type - Type: 'success', 'error', 'info'
     */
    function showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;

        const icons = {
            success: '✓',
            error: '✕',
            info: 'ℹ'
        };

        toast.innerHTML = `
            <span style="font-size: 1.2rem;">${icons[type] || icons.info}</span>
            <span>${escapeHtml(message)}</span>
        `;

        DOM.toastContainer.appendChild(toast);

        // Auto-suppression après délai
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            toast.style.transition = 'all 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, CONFIG.toastDuration);
    }

    /**
     * Échappe les caractères HTML pour prévenir XSS.
     * @param {string} text - Texte à échapper
     * @returns {string} Texte échappé
     */
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Formate un timestamp en date lisible.
     * @param {string} isoDate - Date ISO 8601
     * @returns {Object} {text: string, isRecent: boolean}
     */
    function formatTimestamp(isoDate) {
        if (!isoDate) {
            return { text: 'Jamais', isRecent: false };
        }

        const date = new Date(isoDate);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);

        let text;
        let isRecent = false;

        if (diffMins < 1) {
            text = 'À l\'instant';
            isRecent = true;
        } else if (diffMins < 60) {
            text = `Il y a ${diffMins} min`;
            isRecent = diffMins < 5;
        } else if (diffHours < 24) {
            text = `Il y a ${diffHours}h`;
        } else if (diffDays < 7) {
            text = `Il y a ${diffDays}j`;
        } else {
            text = date.toLocaleDateString('fr-FR', {
                day: 'numeric',
                month: 'short',
                year: date.getFullYear() !== now.getFullYear() ? 'numeric' : undefined
            });
        }

        return { text, isRecent };
    }

    /**
     * Retourne le badge HTML pour un type de transport.
     * @param {string} transport - Type: 'otg', 'wifi', 'none'
     * @returns {string} HTML du badge
     */
    function getTransportBadge(transport) {
        const badges = {
            otg: { class: 'badge-otg', icon: '⚡', label: 'OTG' },
            wifi: { class: 'badge-wifi', icon: '📶', label: 'WiFi' },
            none: { class: 'badge-none', icon: '○', label: 'Aucun' }
        };

        const badge = badges[transport] || badges.none;
        return `<span class="badge ${badge.class}">${badge.icon} ${badge.label}</span>`;
    }

    /**
     * Met à jour l'indicateur de statut de connexion.
     * @param {boolean} online - État de connexion
     */
    function updateStatusIndicator(online) {
        state.isOnline = online;

        if (online) {
            DOM.statusIndicator.classList.remove('offline');
            DOM.statusText.textContent = 'En ligne';
        } else {
            DOM.statusIndicator.classList.add('offline');
            DOM.statusText.textContent = 'Hors ligne';
        }
    }

    /**
     * Met à jour les statistiques affichées.
     */
    function updateStats() {
        const devices = state.devices;
        const total = devices.length;
        const otg = devices.filter(d => d.transport === 'otg').length;
        const wifi = devices.filter(d => d.transport === 'wifi').length;
        const offline = devices.filter(d => d.transport === 'none' || !d.transport).length;

        DOM.statTotal.textContent = total;
        DOM.statOtg.textContent = otg;
        DOM.statWifi.textContent = wifi;
        DOM.statOffline.textContent = offline;
    }

    /**
     * Rend la liste des appareils dans le DOM.
     */
    function renderDeviceList() {
        const devices = state.devices;

        if (devices.length === 0) {
            DOM.deviceListContainer.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">📱</div>
                    <p>Aucun appareil appairé</p>
                    <p style="font-size: 0.85rem;">
                        Générez un QR code pour appairer votre premier appareil Eye Remote.
                    </p>
                </div>
            `;
            return;
        }

        const tableHTML = `
            <table class="device-table">
                <thead>
                    <tr>
                        <th>Appareil</th>
                        <th class="col-id">ID</th>
                        <th>Transport</th>
                        <th>Dernière connexion</th>
                        <th class="col-firmware">Firmware</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${devices.map(device => renderDeviceRow(device)).join('')}
                </tbody>
            </table>
        `;

        DOM.deviceListContainer.innerHTML = tableHTML;

        // Attache les event listeners pour les boutons unpair
        document.querySelectorAll('[data-unpair]').forEach(btn => {
            btn.addEventListener('click', handleUnpair);
        });
    }

    /**
     * Rend une ligne de tableau pour un appareil.
     * @param {Object} device - Données de l'appareil
     * @returns {string} HTML de la ligne
     */
    function renderDeviceRow(device) {
        const lastSeen = formatTimestamp(device.last_seen);
        const timestampClass = lastSeen.isRecent ? 'timestamp timestamp-recent' : 'timestamp';

        return `
            <tr>
                <td>
                    <div class="device-name">${escapeHtml(device.name || 'Sans nom')}</div>
                </td>
                <td class="col-id">
                    <span class="device-id">${escapeHtml(device.device_id?.substring(0, 12) || '-')}...</span>
                </td>
                <td>${getTransportBadge(device.transport)}</td>
                <td>
                    <span class="${timestampClass}">${lastSeen.text}</span>
                </td>
                <td class="col-firmware">
                    <span style="color: var(--text-muted); font-size: 0.8rem;">
                        ${escapeHtml(device.firmware || '-')}
                    </span>
                </td>
                <td>
                    <button class="btn btn-danger btn-sm"
                            data-unpair="${escapeHtml(device.device_id)}"
                            title="Désappairer cet appareil">
                        ✕ Désappairer
                    </button>
                </td>
            </tr>
        `;
    }

    // === Event Handlers ===

    /**
     * Gère le clic sur le bouton de désappairage.
     * @param {Event} event - Événement click
     */
    async function handleUnpair(event) {
        const deviceId = event.target.dataset.unpair;
        if (!deviceId) return;

        // Confirmation utilisateur
        const device = state.devices.find(d => d.device_id === deviceId);
        const deviceName = device?.name || deviceId.substring(0, 12);

        if (!confirm(`Désappairer l'appareil "${deviceName}" ?`)) {
            return;
        }

        event.target.disabled = true;
        event.target.textContent = '...';

        try {
            await unpairDevice(deviceId);
            showToast(`Appareil "${deviceName}" désappairé`, 'success');
            await refreshDevices();
        } catch (error) {
            showToast(`Erreur: ${error.message}`, 'error');
            event.target.disabled = false;
            event.target.textContent = '✕ Désappairer';
        }
    }

    /**
     * Gère la génération d'un nouveau QR code.
     */
    async function handleGenerateQR() {
        DOM.btnGenerateQr.disabled = true;
        DOM.btnGenerateQr.innerHTML = '<span class="spinner" style="width:14px;height:14px;"></span> Génération...';

        try {
            const data = await generatePairingQR();
            displayQRCode(data);
            showToast('QR code généré', 'success');
        } catch (error) {
            showToast(`Erreur: ${error.message}`, 'error');
        } finally {
            DOM.btnGenerateQr.disabled = false;
            DOM.btnGenerateQr.innerHTML = '<span>⚙</span> Générer QR Code';
        }
    }

    /**
     * Affiche le QR code et les informations d'appairage.
     * @param {Object} data - Données de pairing {code, url, host, expires_in}
     */
    function displayQRCode(data) {
        // Affiche le conteneur
        DOM.qrContainer.classList.add('active');

        // Met à jour les informations
        DOM.pairingCode.textContent = data.code || '------';
        DOM.pairingUrl.textContent = data.url || data.host || '-';

        // Génère le QR code
        renderQRCode(data.url || `secubox://pair?code=${data.code}`);

        // Démarre le compte à rebours
        startCountdown(data.expires_in || 300);
    }

    /**
     * Génère et affiche le QR code.
     * @param {string} content - Contenu à encoder
     */
    function renderQRCode(content) {
        DOM.qrCode.innerHTML = '';

        // Utilise QRCode.js si disponible
        if (typeof QRCode !== 'undefined' && !window.QRCodeLibFailed) {
            try {
                QRCode.toCanvas(content, {
                    width: CONFIG.qrSize,
                    margin: 2,
                    color: {
                        dark: '#0a0a0f',
                        light: '#ffffff'
                    }
                }, (error, canvas) => {
                    if (error) {
                        console.error('QRCode generation error:', error);
                        renderQRCodeFallback(content);
                        return;
                    }
                    DOM.qrCode.appendChild(canvas);
                });
                return;
            } catch (e) {
                console.warn('QRCode.js failed, using fallback');
            }
        }

        // Fallback: génère un QR ASCII simple ou un placeholder
        renderQRCodeFallback(content);
    }

    /**
     * Fallback pour l'affichage du QR code (sans bibliothèque externe).
     * Affiche un placeholder avec instructions.
     * @param {string} content - Contenu du QR
     */
    function renderQRCodeFallback(content) {
        // Génère un pattern ASCII simulé (pas un vrai QR, juste visuel)
        const placeholder = document.createElement('div');
        placeholder.style.cssText = `
            width: ${CONFIG.qrSize}px;
            height: ${CONFIG.qrSize}px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            background: #fff;
            color: #0a0a0f;
            font-size: 12px;
            text-align: center;
            padding: 1rem;
        `;
        placeholder.innerHTML = `
            <div style="font-size: 2rem; margin-bottom: 0.5rem;">📱</div>
            <div style="font-weight: bold; margin-bottom: 0.5rem;">Code d'appairage</div>
            <div style="font-family: monospace; font-size: 14px; word-break: break-all;">
                ${escapeHtml(content.substring(0, 50))}${content.length > 50 ? '...' : ''}
            </div>
        `;
        DOM.qrCode.appendChild(placeholder);
    }

    /**
     * Démarre le compte à rebours d'expiration.
     * @param {number} seconds - Durée en secondes
     */
    function startCountdown(seconds) {
        // Arrête le timer précédent
        if (state.countdownTimer) {
            clearInterval(state.countdownTimer);
        }

        state.qrExpiration = Date.now() + (seconds * 1000);
        DOM.countdown.classList.remove('countdown-expired');

        function updateCountdown() {
            const remaining = Math.max(0, state.qrExpiration - Date.now());
            const secs = Math.floor(remaining / 1000);
            const mins = Math.floor(secs / 60);
            const displaySecs = secs % 60;

            DOM.countdownTimer.textContent = `${mins}:${displaySecs.toString().padStart(2, '0')}`;

            if (remaining <= 0) {
                clearInterval(state.countdownTimer);
                DOM.countdown.classList.add('countdown-expired');
                DOM.countdownTimer.textContent = 'Expiré';
                showToast('Le QR code a expiré', 'info');
            }
        }

        updateCountdown();
        state.countdownTimer = setInterval(updateCountdown, 1000);
    }

    /**
     * Rafraîchit la liste des appareils.
     */
    async function refreshDevices() {
        try {
            const data = await fetchDevices();
            state.devices = data.devices || [];
            updateStats();
            renderDeviceList();
        } catch (error) {
            console.error('Failed to refresh devices:', error);
            // Ne pas afficher d'erreur toast à chaque refresh auto
        }
    }

    /**
     * Démarre la boucle d'actualisation automatique.
     */
    function startAutoRefresh() {
        // Timer de refresh
        state.refreshTimer = setInterval(async () => {
            const spinner = DOM.refreshIndicator.querySelector('.spinner');
            spinner.style.display = 'block';
            DOM.refreshIndicator.classList.add('refreshing');

            try {
                const online = await checkHealth();
                updateStatusIndicator(online);

                if (online) {
                    await refreshDevices();
                }
            } catch (e) {
                updateStatusIndicator(false);
            } finally {
                spinner.style.display = 'none';
                DOM.refreshIndicator.classList.remove('refreshing');
                state.refreshCountdown = CONFIG.refreshInterval / 1000;
            }
        }, CONFIG.refreshInterval);

        // Timer du countdown visuel
        setInterval(() => {
            state.refreshCountdown = Math.max(0, state.refreshCountdown - 1);
            DOM.refreshCountdown.textContent = state.refreshCountdown;
            if (state.refreshCountdown === 0) {
                state.refreshCountdown = CONFIG.refreshInterval / 1000;
            }
        }, 1000);
    }

    // === Initialisation ===

    /**
     * Initialise l'application au chargement de la page.
     */
    async function init() {
        console.log('SecuBox Eye Remote WebUI v2.0.0');

        // Cache les éléments DOM
        initDOM();

        // Attache les event listeners
        DOM.btnGenerateQr.addEventListener('click', handleGenerateQR);
        DOM.btnRefreshQr.addEventListener('click', handleGenerateQR);

        // Vérifie la connexion initiale
        const online = await checkHealth();
        updateStatusIndicator(online);

        if (online) {
            // Charge les appareils
            await refreshDevices();
        } else {
            DOM.deviceListContainer.innerHTML = `
                <div class="error-message">
                    <span>⚠</span>
                    <span>Impossible de contacter l'API Eye Remote</span>
                </div>
            `;
        }

        // Démarre l'actualisation automatique
        startAutoRefresh();
    }

    // Lance l'initialisation au chargement du DOM
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
