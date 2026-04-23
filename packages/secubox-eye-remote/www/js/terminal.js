/**
 * SecuBox Eye Remote — Serial Console Terminal
 * Integration xterm.js pour console serie distante.
 *
 * CyberMind — https://cybermind.fr
 * Author: Gerald Kerma <gandalf@gk2.net>
 * License: Proprietary / ANSSI CSPN candidate
 *
 * Ce module gere:
 * - Initialisation de xterm.js avec theme SecuBox
 * - Connexion WebSocket au backend serie
 * - Transmission bidirectionnelle des donnees
 * - Gestion des reconnexions
 */

(function() {
    'use strict';

    // ==========================================================================
    // Configuration
    // ==========================================================================

    const CONFIG = {
        // Base URL de l'API
        apiBase: '/api/v1/eye-remote',
        // Timeout de reconnexion (ms)
        reconnectDelay: 3000,
        // Nombre max de tentatives de reconnexion
        maxReconnectAttempts: 5,
        // Taille du scrollback buffer
        scrollback: 10000,
        // Police du terminal
        fontFamily: 'JetBrains Mono, Consolas, Monaco, monospace',
        fontSize: 14,
        // Delai entre les mises a jour stats (ms)
        statsUpdateInterval: 1000
    };

    // Theme SecuBox Cyberpunk pour xterm.js
    const THEME = {
        background: '#0a0a0f',
        foreground: '#00ff41',
        cursor: '#c9a84c',
        cursorAccent: '#0a0a0f',
        selectionBackground: 'rgba(201, 168, 76, 0.3)',
        selectionForeground: '#e8e6d9',
        black: '#0a0a0f',
        red: '#e63946',
        green: '#00ff41',
        yellow: '#c9a84c',
        blue: '#00d4ff',
        magenta: '#6e40c9',
        cyan: '#00d4ff',
        white: '#e8e6d9',
        brightBlack: '#6b6b7a',
        brightRed: '#ff5a67',
        brightGreen: '#33ff66',
        brightYellow: '#d4b85a',
        brightBlue: '#33e0ff',
        brightMagenta: '#9966ff',
        brightCyan: '#33e0ff',
        brightWhite: '#ffffff'
    };

    // ==========================================================================
    // Etat de l'application
    // ==========================================================================

    const state = {
        // Terminal xterm.js
        terminal: null,
        // Addons xterm.js
        fitAddon: null,
        webLinksAddon: null,
        // Connexion WebSocket
        websocket: null,
        // Etat de connexion
        isConnected: false,
        isConnecting: false,
        // Compteur de reconnexion
        reconnectAttempts: 0,
        reconnectTimer: null,
        // Statistiques
        bytesReceived: 0,
        bytesSent: 0,
        connectedAt: null,
        // Mode d'acces (read-only ou read-write)
        accessMode: 'unknown',
        // Configuration courante
        currentDevice: null,
        currentBaud: 115200,
        currentPort: '/dev/ttyACM0',
        // Timer mise a jour stats
        statsTimer: null
    };

    // ==========================================================================
    // Elements DOM (cache)
    // ==========================================================================

    const DOM = {};

    /**
     * Initialiser le cache des elements DOM.
     */
    function initDOM() {
        // Header
        DOM.statusIndicator = document.getElementById('status-indicator');
        DOM.statusText = document.getElementById('status-text');
        DOM.btnConnect = document.getElementById('btn-connect');
        DOM.btnDisconnect = document.getElementById('btn-disconnect');

        // Toolbar
        DOM.selectDevice = document.getElementById('select-device');
        DOM.selectBaud = document.getElementById('select-baud');
        DOM.selectPort = document.getElementById('select-port');
        DOM.btnClear = document.getElementById('btn-clear');
        DOM.btnCopy = document.getElementById('btn-copy');

        // Terminal
        DOM.terminalContainer = document.getElementById('terminal');

        // Footer
        DOM.modeValue = document.getElementById('mode-value');
        DOM.rxValue = document.getElementById('rx-value');
        DOM.txValue = document.getElementById('tx-value');
        DOM.connectedTime = document.getElementById('connected-time');

        // Dialog
        DOM.connectDialog = document.getElementById('connect-dialog');
        DOM.connectForm = document.getElementById('connect-form');
        DOM.dialogError = document.getElementById('dialog-error');
        DOM.inputDeviceId = document.getElementById('input-device-id');
        DOM.inputToken = document.getElementById('input-token');
        DOM.inputBaud = document.getElementById('input-baud');
        DOM.inputPort = document.getElementById('input-port');
        DOM.btnDialogCancel = document.getElementById('btn-dialog-cancel');
        DOM.btnDialogConnect = document.getElementById('btn-dialog-connect');
    }

    // ==========================================================================
    // Initialisation Terminal xterm.js
    // ==========================================================================

    /**
     * Initialiser le terminal xterm.js.
     */
    function initTerminal() {
        // Creer l'instance Terminal
        state.terminal = new Terminal({
            theme: THEME,
            fontFamily: CONFIG.fontFamily,
            fontSize: CONFIG.fontSize,
            cursorBlink: true,
            cursorStyle: 'block',
            scrollback: CONFIG.scrollback,
            convertEol: true,
            disableStdin: false,
            allowProposedApi: true
        });

        // Initialiser l'addon Fit pour le redimensionnement
        state.fitAddon = new FitAddon.FitAddon();
        state.terminal.loadAddon(state.fitAddon);

        // Initialiser l'addon WebLinks pour les URLs cliquables
        state.webLinksAddon = new WebLinksAddon.WebLinksAddon();
        state.terminal.loadAddon(state.webLinksAddon);

        // Ouvrir le terminal dans le conteneur
        state.terminal.open(DOM.terminalContainer);

        // Adapter la taille au conteneur
        state.fitAddon.fit();

        // Message d'accueil
        writeWelcomeMessage();

        // Gestion des donnees saisies
        state.terminal.onData(handleTerminalInput);

        // Gestion du redimensionnement
        window.addEventListener('resize', handleResize);

        console.log('Terminal xterm.js initialise');
    }

    /**
     * Ecrire le message d'accueil dans le terminal.
     */
    function writeWelcomeMessage() {
        const t = state.terminal;
        t.writeln('\x1b[1;33m╔══════════════════════════════════════════════════════════╗\x1b[0m');
        t.writeln('\x1b[1;33m║\x1b[0m  \x1b[1;36mSecuBox Eye Remote\x1b[0m — \x1b[32mConsole Serie\x1b[0m                       \x1b[1;33m║\x1b[0m');
        t.writeln('\x1b[1;33m║\x1b[0m  \x1b[90mCyberMind — https://cybermind.fr\x1b[0m                         \x1b[1;33m║\x1b[0m');
        t.writeln('\x1b[1;33m╚══════════════════════════════════════════════════════════╝\x1b[0m');
        t.writeln('');
        t.writeln('\x1b[90mCliquez sur "Connecter" pour etablir la connexion serie.\x1b[0m');
        t.writeln('');
    }

    /**
     * Gerer le redimensionnement de la fenetre.
     */
    function handleResize() {
        if (state.fitAddon) {
            state.fitAddon.fit();
        }
    }

    /**
     * Gerer les donnees saisies dans le terminal.
     * @param {string} data - Donnees saisies
     */
    function handleTerminalInput(data) {
        if (!state.isConnected || !state.websocket) {
            return;
        }

        // Envoyer les donnees au WebSocket
        sendToSerial(data);
    }

    // ==========================================================================
    // Connexion WebSocket
    // ==========================================================================

    /**
     * Etablir la connexion WebSocket au port serie.
     * @param {Object} params - Parametres de connexion
     * @param {string} params.deviceId - ID de l'appareil
     * @param {string} params.token - Token d'authentification
     * @param {number} params.baud - Baud rate
     * @param {string} params.device - Chemin du device serie
     */
    async function connect(params) {
        if (state.isConnected || state.isConnecting) {
            return;
        }

        state.isConnecting = true;
        updateStatus('connecting', 'Connexion...');

        // Construire l'URL WebSocket
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}${CONFIG.apiBase}/serial/console/${params.deviceId}` +
            `?token=${encodeURIComponent(params.token)}` +
            `&baud=${params.baud}` +
            `&device=${encodeURIComponent(params.device)}`;

        try {
            state.websocket = new WebSocket(wsUrl);
            state.websocket.binaryType = 'arraybuffer';

            // Handlers WebSocket
            state.websocket.onopen = () => handleWebSocketOpen(params);
            state.websocket.onmessage = handleWebSocketMessage;
            state.websocket.onclose = handleWebSocketClose;
            state.websocket.onerror = handleWebSocketError;

            // Stocker la config courante
            state.currentDevice = params.deviceId;
            state.currentBaud = params.baud;
            state.currentPort = params.device;

        } catch (error) {
            console.error('Erreur connexion WebSocket:', error);
            state.isConnecting = false;
            updateStatus('disconnected', 'Erreur connexion');
            showDialogError('Impossible d\'etablir la connexion');
        }
    }

    /**
     * Handler: WebSocket ouvert.
     * @param {Object} params - Parametres de connexion
     */
    function handleWebSocketOpen(params) {
        console.log('WebSocket serie connecte');
        state.isConnected = true;
        state.isConnecting = false;
        state.reconnectAttempts = 0;
        state.connectedAt = new Date();
        state.bytesReceived = 0;
        state.bytesSent = 0;

        updateStatus('connected', 'Connecte');
        hideConnectDialog();
        updateUI(true);

        // Effacer et afficher message de connexion
        state.terminal.clear();
        state.terminal.writeln(`\x1b[1;32m[Connexion etablie]\x1b[0m`);
        state.terminal.writeln(`\x1b[90mDevice: ${params.device} @ ${params.baud} bauds\x1b[0m`);
        state.terminal.writeln('');

        // Demarrer la mise a jour des stats
        startStatsUpdate();
    }

    /**
     * Handler: Message WebSocket recu.
     * @param {MessageEvent} event - Evenement message
     */
    function handleWebSocketMessage(event) {
        let data;

        if (event.data instanceof ArrayBuffer) {
            // Donnees binaires
            data = new Uint8Array(event.data);
            state.bytesReceived += data.length;

            // Convertir en string et afficher
            const text = new TextDecoder('utf-8', { fatal: false }).decode(data);
            state.terminal.write(text);

            // Detecter le mode d'acces
            if (text.includes('read/write')) {
                state.accessMode = 'read-write';
                DOM.modeValue.textContent = 'R/W';
                DOM.modeValue.classList.remove('warning');
            } else if (text.includes('read-only')) {
                state.accessMode = 'read-only';
                DOM.modeValue.textContent = 'RO';
                DOM.modeValue.classList.add('warning');
            }
        } else {
            // Donnees texte (fallback)
            data = event.data;
            state.bytesReceived += data.length;
            state.terminal.write(data);
        }
    }

    /**
     * Handler: WebSocket ferme.
     * @param {CloseEvent} event - Evenement close
     */
    function handleWebSocketClose(event) {
        console.log('WebSocket serie ferme:', event.code, event.reason);

        const wasConnected = state.isConnected;
        state.isConnected = false;
        state.isConnecting = false;
        state.websocket = null;

        stopStatsUpdate();
        updateStatus('disconnected', 'Deconnecte');
        updateUI(false);

        // Message dans le terminal
        if (wasConnected) {
            state.terminal.writeln('');
            state.terminal.writeln(`\x1b[1;31m[Connexion fermee]\x1b[0m`);

            // Tentative de reconnexion si deconnexion inattendue
            if (event.code !== 1000 && event.code !== 1008) {
                scheduleReconnect();
            }
        }
    }

    /**
     * Handler: Erreur WebSocket.
     * @param {Event} event - Evenement erreur
     */
    function handleWebSocketError(event) {
        console.error('Erreur WebSocket serie:', event);

        if (state.isConnecting) {
            state.isConnecting = false;
            showDialogError('Erreur de connexion au serveur');
        }

        state.terminal.writeln(`\x1b[1;31m[Erreur connexion]\x1b[0m`);
    }

    /**
     * Deconnecter le WebSocket.
     */
    function disconnect() {
        if (state.reconnectTimer) {
            clearTimeout(state.reconnectTimer);
            state.reconnectTimer = null;
        }
        state.reconnectAttempts = CONFIG.maxReconnectAttempts; // Empecher reconnexion

        if (state.websocket) {
            state.websocket.close(1000, 'User disconnect');
        }
    }

    /**
     * Programmer une tentative de reconnexion.
     */
    function scheduleReconnect() {
        if (state.reconnectAttempts >= CONFIG.maxReconnectAttempts) {
            state.terminal.writeln(`\x1b[33m[Reconnexion abandonnee apres ${CONFIG.maxReconnectAttempts} tentatives]\x1b[0m`);
            return;
        }

        state.reconnectAttempts++;
        const delay = CONFIG.reconnectDelay * state.reconnectAttempts;

        state.terminal.writeln(`\x1b[33m[Reconnexion dans ${delay/1000}s... (tentative ${state.reconnectAttempts}/${CONFIG.maxReconnectAttempts})]\x1b[0m`);

        state.reconnectTimer = setTimeout(() => {
            if (state.currentDevice) {
                // Recuperer le token stocke (si disponible)
                const token = sessionStorage.getItem('serial_token_' + state.currentDevice);
                if (token) {
                    connect({
                        deviceId: state.currentDevice,
                        token: token,
                        baud: state.currentBaud,
                        device: state.currentPort
                    });
                } else {
                    state.terminal.writeln(`\x1b[31m[Token manquant, reconnexion impossible]\x1b[0m`);
                }
            }
        }, delay);
    }

    /**
     * Envoyer des donnees au port serie via WebSocket.
     * @param {string} data - Donnees a envoyer
     */
    function sendToSerial(data) {
        if (!state.websocket || state.websocket.readyState !== WebSocket.OPEN) {
            return false;
        }

        try {
            // Convertir en bytes et envoyer
            const encoder = new TextEncoder();
            const bytes = encoder.encode(data);
            state.websocket.send(bytes);
            state.bytesSent += bytes.length;
            return true;
        } catch (error) {
            console.error('Erreur envoi serie:', error);
            return false;
        }
    }

    // ==========================================================================
    // API Helpers
    // ==========================================================================

    /**
     * Recuperer la liste des appareils appaires.
     * @returns {Promise<Array>} Liste des appareils
     */
    async function fetchDevices() {
        try {
            const response = await fetch(`${CONFIG.apiBase}/devices`);
            if (!response.ok) throw new Error('HTTP ' + response.status);
            const data = await response.json();
            return data.devices || [];
        } catch (error) {
            console.error('Erreur chargement appareils:', error);
            return [];
        }
    }

    /**
     * Recuperer la liste des ports serie disponibles.
     * @returns {Promise<Array>} Liste des ports
     */
    async function fetchSerialPorts() {
        try {
            const response = await fetch(`${CONFIG.apiBase}/serial/devices`);
            if (!response.ok) throw new Error('HTTP ' + response.status);
            return await response.json();
        } catch (error) {
            console.error('Erreur chargement ports serie:', error);
            return [];
        }
    }

    // ==========================================================================
    // Interface Utilisateur
    // ==========================================================================

    /**
     * Mettre a jour l'indicateur de statut.
     * @param {string} status - Etat: 'connected', 'disconnected', 'connecting'
     * @param {string} text - Texte a afficher
     */
    function updateStatus(status, text) {
        DOM.statusIndicator.classList.remove('connected', 'disconnected', 'connecting');
        DOM.statusIndicator.classList.add(status);
        DOM.statusText.textContent = text;
    }

    /**
     * Mettre a jour l'interface selon l'etat de connexion.
     * @param {boolean} connected - Etat de connexion
     */
    function updateUI(connected) {
        DOM.btnConnect.disabled = connected;
        DOM.btnDisconnect.disabled = !connected;
        DOM.selectDevice.disabled = connected;
        DOM.selectBaud.disabled = connected;
        DOM.selectPort.disabled = connected;

        if (!connected) {
            DOM.modeValue.textContent = '--';
            DOM.modeValue.classList.remove('warning');
            DOM.connectedTime.textContent = '--';
        }
    }

    /**
     * Demarrer la mise a jour des statistiques.
     */
    function startStatsUpdate() {
        state.statsTimer = setInterval(updateStats, CONFIG.statsUpdateInterval);
        updateStats();
    }

    /**
     * Arreter la mise a jour des statistiques.
     */
    function stopStatsUpdate() {
        if (state.statsTimer) {
            clearInterval(state.statsTimer);
            state.statsTimer = null;
        }
    }

    /**
     * Mettre a jour l'affichage des statistiques.
     */
    function updateStats() {
        // Bytes RX/TX
        DOM.rxValue.textContent = formatBytes(state.bytesReceived);
        DOM.txValue.textContent = formatBytes(state.bytesSent);

        // Temps de connexion
        if (state.connectedAt) {
            const elapsed = Date.now() - state.connectedAt.getTime();
            DOM.connectedTime.textContent = formatDuration(elapsed);
        }
    }

    /**
     * Formater une taille en bytes.
     * @param {number} bytes - Nombre de bytes
     * @returns {string} Taille formatee
     */
    function formatBytes(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    }

    /**
     * Formater une duree en millisecondes.
     * @param {number} ms - Duree en ms
     * @returns {string} Duree formatee
     */
    function formatDuration(ms) {
        const secs = Math.floor(ms / 1000);
        const mins = Math.floor(secs / 60);
        const hours = Math.floor(mins / 60);

        if (hours > 0) {
            return `${hours}h ${mins % 60}m`;
        }
        if (mins > 0) {
            return `${mins}m ${secs % 60}s`;
        }
        return `${secs}s`;
    }

    // ==========================================================================
    // Dialog de Connexion
    // ==========================================================================

    /**
     * Afficher le dialog de connexion.
     */
    async function showConnectDialog() {
        DOM.connectDialog.classList.remove('hidden');
        hideDialogError();

        // Charger les appareils
        const devices = await fetchDevices();
        populateDeviceSelect(devices);

        // Charger les ports serie
        const ports = await fetchSerialPorts();
        populatePortSelect(ports);

        // Focus sur le premier champ
        DOM.inputToken.focus();
    }

    /**
     * Masquer le dialog de connexion.
     */
    function hideConnectDialog() {
        DOM.connectDialog.classList.add('hidden');
        DOM.inputToken.value = '';
        hideDialogError();
    }

    /**
     * Afficher une erreur dans le dialog.
     * @param {string} message - Message d'erreur
     */
    function showDialogError(message) {
        DOM.dialogError.textContent = message;
        DOM.dialogError.classList.remove('hidden');
    }

    /**
     * Masquer l'erreur du dialog.
     */
    function hideDialogError() {
        DOM.dialogError.classList.add('hidden');
    }

    /**
     * Peupler le select des appareils.
     * @param {Array} devices - Liste des appareils
     */
    function populateDeviceSelect(devices) {
        DOM.inputDeviceId.innerHTML = '';

        if (devices.length === 0) {
            const opt = document.createElement('option');
            opt.value = '';
            opt.textContent = 'Aucun appareil appaire';
            opt.disabled = true;
            opt.selected = true;
            DOM.inputDeviceId.appendChild(opt);
            return;
        }

        devices.forEach(device => {
            const opt = document.createElement('option');
            opt.value = device.device_id;
            opt.textContent = device.name || device.device_id.substring(0, 12);
            DOM.inputDeviceId.appendChild(opt);
        });

        // Mettre a jour aussi le select de la toolbar
        DOM.selectDevice.innerHTML = '';
        devices.forEach(device => {
            const opt = document.createElement('option');
            opt.value = device.device_id;
            opt.textContent = device.name || device.device_id.substring(0, 12);
            DOM.selectDevice.appendChild(opt);
        });
    }

    /**
     * Peupler le select des ports serie.
     * @param {Array} ports - Liste des ports
     */
    function populatePortSelect(ports) {
        if (ports.length === 0) {
            return; // Garder les options par defaut
        }

        DOM.inputPort.innerHTML = '';
        ports.forEach(port => {
            const opt = document.createElement('option');
            opt.value = port.path;
            opt.textContent = port.path;
            if (!port.readable || !port.writable) {
                opt.textContent += ' (non accessible)';
                opt.disabled = true;
            }
            DOM.inputPort.appendChild(opt);
        });
    }

    // ==========================================================================
    // Event Handlers
    // ==========================================================================

    /**
     * Handler: Clic bouton connecter.
     */
    function handleConnectClick() {
        showConnectDialog();
    }

    /**
     * Handler: Clic bouton deconnecter.
     */
    function handleDisconnectClick() {
        disconnect();
    }

    /**
     * Handler: Soumission formulaire de connexion.
     * @param {Event} event - Evenement submit
     */
    function handleConnectFormSubmit(event) {
        event.preventDefault();

        const deviceId = DOM.inputDeviceId.value;
        const token = DOM.inputToken.value.trim();
        const baud = parseInt(DOM.inputBaud.value, 10);
        const device = DOM.inputPort.value;

        if (!deviceId) {
            showDialogError('Selectionnez un appareil');
            return;
        }

        if (!token) {
            showDialogError('Entrez le token d\'authentification');
            return;
        }

        // Stocker le token pour reconnexion (session uniquement)
        sessionStorage.setItem('serial_token_' + deviceId, token);

        // Demarrer la connexion
        connect({
            deviceId: deviceId,
            token: token,
            baud: baud,
            device: device
        });

        // Desactiver le bouton pendant la connexion
        DOM.btnDialogConnect.disabled = true;
        DOM.btnDialogConnect.innerHTML = '<span class="spinner" style="width:12px;height:12px;border-width:2px;"></span> Connexion...';

        // Reset apres timeout
        setTimeout(() => {
            DOM.btnDialogConnect.disabled = false;
            DOM.btnDialogConnect.innerHTML = '<span>&#9654;</span> Connecter';
        }, 5000);
    }

    /**
     * Handler: Annulation du dialog.
     */
    function handleDialogCancel() {
        hideConnectDialog();
    }

    /**
     * Handler: Clic bouton effacer.
     */
    function handleClearClick() {
        if (state.terminal) {
            state.terminal.clear();
        }
    }

    /**
     * Handler: Clic bouton copier.
     */
    function handleCopyClick() {
        if (!state.terminal) return;

        const selection = state.terminal.getSelection();
        if (selection) {
            navigator.clipboard.writeText(selection).then(() => {
                // Feedback visuel
                const originalText = DOM.btnCopy.innerHTML;
                DOM.btnCopy.innerHTML = '<span>&#10003;</span> Copie!';
                setTimeout(() => {
                    DOM.btnCopy.innerHTML = originalText;
                }, 1500);
            }).catch(err => {
                console.error('Erreur copie:', err);
            });
        }
    }

    /**
     * Handler: Fermeture dialog avec Escape.
     * @param {KeyboardEvent} event - Evenement clavier
     */
    function handleKeyDown(event) {
        if (event.key === 'Escape' && !DOM.connectDialog.classList.contains('hidden')) {
            hideConnectDialog();
        }
    }

    // ==========================================================================
    // Initialisation
    // ==========================================================================

    /**
     * Initialiser l'application.
     */
    async function init() {
        console.log('SecuBox Eye Remote Terminal v2.0.0');

        // Cache DOM
        initDOM();

        // Initialiser le terminal
        initTerminal();

        // Event listeners
        DOM.btnConnect.addEventListener('click', handleConnectClick);
        DOM.btnDisconnect.addEventListener('click', handleDisconnectClick);
        DOM.connectForm.addEventListener('submit', handleConnectFormSubmit);
        DOM.btnDialogCancel.addEventListener('click', handleDialogCancel);
        DOM.btnClear.addEventListener('click', handleClearClick);
        DOM.btnCopy.addEventListener('click', handleCopyClick);
        document.addEventListener('keydown', handleKeyDown);

        // Clic sur overlay ferme le dialog
        DOM.connectDialog.addEventListener('click', (e) => {
            if (e.target === DOM.connectDialog) {
                hideConnectDialog();
            }
        });

        // Charger les appareils pour le select toolbar
        const devices = await fetchDevices();
        if (devices.length > 0) {
            DOM.selectDevice.innerHTML = '';
            devices.forEach(device => {
                const opt = document.createElement('option');
                opt.value = device.device_id;
                opt.textContent = device.name || device.device_id.substring(0, 12);
                DOM.selectDevice.appendChild(opt);
            });
        }

        // Verifier les parametres URL pour connexion automatique
        const urlParams = new URLSearchParams(window.location.search);
        const autoDeviceId = urlParams.get('device');
        const autoToken = urlParams.get('token');

        if (autoDeviceId && autoToken) {
            // Connexion automatique
            connect({
                deviceId: autoDeviceId,
                token: autoToken,
                baud: parseInt(urlParams.get('baud') || '115200', 10),
                device: urlParams.get('port') || '/dev/ttyACM0'
            });
        }
    }

    // Demarrer au chargement du DOM
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
