async function testConnection(endpoint, resultId, buttonId, formData) {
    const btn = document.getElementById(buttonId);
    const result = document.getElementById(resultId);

    btn.disabled = true;
    btn.textContent = 'Testing...';
    result.innerHTML = '<span style="color: var(--text-dim);">Testing connection...</span>';

    try {
        const resp = await fetch(endpoint, {
            method: 'POST',
            body: formData
        });
        const data = await resp.json();

        if (data.success) {
            result.innerHTML = `<span style="color: var(--success);">✓ ${data.message}</span>`;
        } else {
            result.innerHTML = `<span style="color: var(--error);">✗ ${data.error}</span>`;
        }
    } catch (e) {
        result.innerHTML = `<span style="color: var(--error);">✗ ${e.message}</span>`;
    } finally {
        btn.disabled = false;
        btn.textContent = 'Test Connection';
    }
}

document.getElementById('test-torrent').addEventListener('click', () => {
    const form = document.querySelector('form');
    const formData = new FormData(form);
    testConnection('/api/test/torrent', 'torrent-result', 'test-torrent', formData);
});

document.getElementById('test-llm').addEventListener('click', () => {
    const form = document.querySelector('form');
    const formData = new FormData(form);
    testConnection('/api/test/llm', 'llm-result', 'test-llm', formData);
});

// Model autocomplete based on provider
const staticModelLists = {
    openai: ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'o1', 'o1-mini', 'o3-mini'],
    google: ['gemini-2.0-flash', 'gemini-1.5-pro', 'gemini-1.5-flash'],
    openrouter: ['anthropic/claude-3.5-sonnet', 'openai/gpt-4o', 'google/gemini-pro'],
};

function updateModelList(provider) {
    const datalist = document.getElementById('model-list');
    datalist.innerHTML = '';

    // Static lists for some providers
    if (staticModelLists[provider]) {
        staticModelLists[provider].forEach(model => {
            const option = document.createElement('option');
            option.value = model;
            datalist.appendChild(option);
        });
        return;
    }

    // Fetch dynamically for Ollama
    if (provider === 'ollama') {
        fetch('/api/ollama/models')
            .then(r => r.json())
            .then(data => {
                if (data.models) {
                    data.models.forEach(model => {
                        const option = document.createElement('option');
                        option.value = model;
                        datalist.appendChild(option);
                    });
                }
            })
            .catch(() => {});
        return;
    }

    // Fetch dynamically for Claude (claude_code and anthropic)
    if (provider === 'claude_code' || provider === 'anthropic') {
        fetch('/api/claude/models')
            .then(r => r.json())
            .then(data => {
                if (data.models) {
                    data.models.forEach(model => {
                        const option = document.createElement('option');
                        option.value = model;
                        datalist.appendChild(option);
                    });
                }
            })
            .catch(() => {});
    }
}

// Update on provider change
document.getElementById('llm_provider').addEventListener('change', (e) => {
    updateModelList(e.target.value);
});

// Initial load
updateModelList(document.getElementById('llm_provider').value);
