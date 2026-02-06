        // WebSocket connection for live updates
        let ws = null;
        let reconnectAttempts = 0;
        let wasConnected = false;
        const versionState = readVersionState();

        function readVersionState() {
            const node = document.getElementById('build-version');
            if (!node) return null;

            const backendHash = (node.dataset.backendHash || '').trim();
            const frontendHash = (node.dataset.frontendHash || '').trim();
            const backendEpoch = String(node.dataset.backendEpoch || '').trim();
            const frontendEpoch = String(node.dataset.frontendEpoch || '').trim();

            if (!backendHash && !frontendHash) {
                return null;
            }

            return {
                backendHash,
                frontendHash,
                backendEpoch,
                frontendEpoch,
            };
        }

        function isVersionDifferent(remoteGit) {
            if (!versionState || !remoteGit) return false;
            const backend = remoteGit.backend || {};
            const frontend = remoteGit.frontend || {};
            return String(backend.hash || '') !== versionState.backendHash ||
                   String(frontend.hash || '') !== versionState.frontendHash ||
                   String(backend.epoch || '') !== versionState.backendEpoch ||
                   String(frontend.epoch || '') !== versionState.frontendEpoch;
        }

        async function checkForBuildUpdate() {
            if (!versionState) return;

            try {
                const resp = await fetch('/api/status', {
                    cache: 'no-store',
                    headers: { 'Accept': 'application/json' },
                });
                if (!resp.ok) return;

                const data = await resp.json();
                if (isVersionDifferent(data.git)) {
                    window.location.reload();
                }
            } catch (_) {
                // Ignore network/transient parse errors and retry on next poll.
            }
        }

        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

            ws.onopen = () => {
                console.log('WebSocket connected');
                // Dispatch reconnect event instead of reloading (preserves modal state)
                if (wasConnected) {
                    console.log('Backend reconnected, dispatching event...');
                    document.dispatchEvent(new CustomEvent('ws-reconnected'));
                    checkForBuildUpdate();
                }
                wasConnected = true;
                reconnectAttempts = 0;
                const indicator = document.getElementById('backend-status');
                if (indicator) {
                    indicator.classList.add('connected');
                    indicator.title = 'Backend connected';
                }
            };

            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                handleMessage(data);
            };

            ws.onclose = () => {
                console.log('WebSocket disconnected');
                const indicator = document.getElementById('backend-status');
                if (indicator) {
                    indicator.classList.remove('connected');
                    indicator.title = 'Backend disconnected';
                }
                // Reconnect with exponential backoff
                const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
                reconnectAttempts++;
                setTimeout(connectWebSocket, delay);
            };

            ws.onerror = (error) => {
                console.error('WebSocket error:', error);
            };
        }

        function handleMessage(data) {
            if (data.type === 'status' || data.type === 'init') {
                updateStatus(data.is_running, data.task);
            }
            if (data.type === 'screenshot') {
                updateScreenshot(data.data, data.url);
            }
            if (data.type === 'message') {
                addMessage(data.role, data.content);
            }
            if (data.type === 'init' && data.messages) {
                data.messages.forEach(m => addMessage(m.role, m.content));
            }
        }

        function updateStatus(isRunning, task) {
            const dot = document.getElementById('status-dot');
            const text = document.getElementById('status-text');
            if (dot) {
                dot.className = 'status-dot' + (isRunning ? ' running' : '');
            }
            if (text) {
                text.textContent = isRunning ? (task || 'Running...') : 'Idle';
            }
        }

        function updateScreenshot(base64Data, url) {
            const img = document.getElementById('browser-screenshot');
            const urlEl = document.getElementById('browser-url');
            if (img) {
                img.src = 'data:image/png;base64,' + base64Data;
                img.style.display = 'block';
            }
            if (urlEl) {
                urlEl.textContent = url;
            }
            const placeholder = document.getElementById('browser-placeholder');
            if (placeholder) {
                placeholder.style.display = 'none';
            }
        }

        function addMessage(role, content) {
            const container = document.getElementById('messages');
            if (!container) return;

            const msg = document.createElement('div');
            msg.className = 'message';
            msg.innerHTML = `
                <span class="role">${role}</span>
                <div class="content">${escapeHtml(content)}</div>
            `;
            container.appendChild(msg);
            container.scrollTop = container.scrollHeight;
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Version relative time
        (function() {
            const nodes = Array.from(document.querySelectorAll('.version-relative[data-epoch]'));
            if (!nodes.length) return;
            function update() {
                const now = Date.now();
                for (const el of nodes) {
                    const epoch = parseInt(el.dataset.epoch, 10) * 1000;
                    if (!Number.isFinite(epoch)) continue;
                    const diff = now - epoch;
                    const sec = Math.floor(diff / 1000);
                    if (sec < 60) el.textContent = 'just now';
                    else if (sec < 3600) el.textContent = Math.floor(sec / 60) + 'm ago';
                    else if (sec < 86400) el.textContent = Math.floor(sec / 3600) + 'h ago';
                    else el.textContent = Math.floor(sec / 86400) + 'd ago';
                }
            }
            update();
            setInterval(update, 60000);
        })();

        // Connect on page load
        connectWebSocket();

        // Ping to keep connection alive
        setInterval(() => {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({type: 'ping'}));
            }
        }, 30000);

        setInterval(() => {
            checkForBuildUpdate();
        }, 30000);
