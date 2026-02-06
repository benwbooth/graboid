    function updateDashboardStatus(isRunning, task) {
        const dot = document.getElementById('dashboard-status-dot');
        const text = document.getElementById('dashboard-status-text');
        if (dot) {
            dot.className = 'status-dot' + (isRunning ? ' running' : '');
        }
        if (text) {
            text.textContent = isRunning ? ('Running: ' + (task || '...')) : 'Idle';
        }
    }

    // Override the base handleMessage to update dashboard
    const originalHandleMessage = handleMessage;
    handleMessage = function(data) {
        originalHandleMessage(data);
        if (data.type === 'status' || data.type === 'init') {
            updateDashboardStatus(data.is_running, data.task);
        }
    };
