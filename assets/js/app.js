// Data from PHP
// const savedServers = ... (Defined in HTML)
const apiBasePath = window.location.pathname;
const apiUrl = (action) => `${apiBasePath}?action=${encodeURIComponent(action)}`;
async function runAction(action, formData, opts = { stream: false }) {
    if (opts.stream) {
        return streamResponse(apiUrl(action), formData);
    }
    const res = await fetch(apiUrl(action), { method: 'POST', body: formData });
    return res.json();
}

// Views
function showView(viewId) {
    document.getElementById('view-home').classList.add('hidden');
    document.getElementById('view-add-server').classList.add('hidden');
    document.getElementById('view-deploy').classList.add('hidden');
    document.getElementById('view-' + viewId).classList.remove('hidden');
}

// --- Add Server Logic ---
const addServerForm = document.getElementById('addServerForm');
const addServerBtn = document.getElementById('addServerBtn');
const addError = document.getElementById('add-error');

addServerForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    addServerBtn.disabled = true;
    addServerBtn.textContent = 'Connecting & Saving...';
    addError.classList.add('hidden');

    const formData = new FormData(addServerForm);
    try {
        const res = await fetch(apiUrl('add_server'), {
            method: 'POST',
            body: formData
        });
        const data = await res.json();
        
        if (data.status === 'success') {
            // Refresh page to show new server in list (simple way)
            window.location.reload();
        } else {
            addError.textContent = data.message;
            addError.classList.remove('hidden');
            addServerBtn.disabled = false;
            addServerBtn.textContent = 'Connect & Add Server';
        }
    } catch (err) {
        addError.textContent = 'Request failed: ' + err.message;
        addError.classList.remove('hidden');
        addServerBtn.disabled = false;
        addServerBtn.textContent = 'Connect & Add Server';
    }
});

// --- Delete Server (From Home List) ---
async function deleteServer(id) {
    if (!confirm('Remove this server from your list?')) return;
    const formData = new FormData();
    formData.append('server_id', id);
    
    try {
        await fetch(apiUrl('delete_server'), { method: 'POST', body: formData });
        window.location.reload();
    } catch (err) {
        alert('Delete failed');
    }
}

// --- Deploy Logic ---
const deployForm = document.getElementById('deployForm');
const term = document.getElementById('terminal');
const postActions = document.getElementById('postDeployActions');
const deployBtn = document.getElementById('deployBtn');
const updateBtn = document.getElementById('updateBtn');
const updateCodeBtn = document.getElementById('updateCodeBtn');
const saveBtn = document.getElementById('saveBtn');
const applyDomainsBtn = document.getElementById('applyDomainsBtn');
const removeDomainsBtn = document.getElementById('removeDomainsBtn');
const testBtn = document.getElementById('testBtn');
const sslBtn = document.getElementById('sslBtn');
const toolSslBtn = document.getElementById('toolSslBtn');
const adminBtn = document.getElementById('adminBtn');
const adminFooterBtn = document.getElementById('adminFooterBtn');
const deleteBtn = document.getElementById('deleteBtn');
const viewLogsBtn = document.getElementById('viewLogsBtn');
const installChromeBtn = document.getElementById('installChromeBtn');
const copyLogsBtn = document.getElementById('copyLogsBtn');
const deploySavedDomains = document.getElementById('deploySavedDomains');
const deployMainDomainInput = document.getElementById('deploy_main_domain');
const deployDomainsInput = document.getElementById('deploy_domains');
const deployAddDomainInput = document.getElementById('deploy_add_domain');
const deployAddDomainBtn = document.getElementById('deployAddDomainBtn');
const deployDomainsPills = document.getElementById('deployDomainsPills');
const loadActiveDomainsBtn = document.getElementById('loadActiveDomainsBtn');
const deployActiveDomains = document.getElementById('deployActiveDomains');

let latestDomainStatuses = {};

function normalizeDomainClient(value) {
    let v = String(value || '').trim().toLowerCase();
    v = v.replace(/^https?:\/\//, '');
    v = v.replace(/\/.*$/, '');
    v = v.replace(/\.$/, '');
    return v;
}

function parseDomainsText(value) {
    const raw = String(value || '');
    return raw
        .split(/[\s,]+/g)
        .map(s => s.trim())
        .filter(Boolean);
}

function getDomainsState() {
    const main = normalizeDomainClient(deployMainDomainInput?.value || '');
    const extras = parseDomainsText(deployDomainsInput?.value || '').map(normalizeDomainClient).filter(Boolean);
    const uniqueExtras = Array.from(new Set(extras)).filter(d => d !== main);
    return { main, extras: uniqueExtras };
}

function setDomainsState(state) {
    const main = state?.main || '';
    const extras = Array.isArray(state?.extras) ? state.extras : [];
    if (deployMainDomainInput) deployMainDomainInput.value = main;
    if (deployDomainsInput) deployDomainsInput.value = extras.join('\n');
    renderDomainsEditorPills();
}

function renderDomainPills(container, domains) {
    container.innerHTML = '';
    const unique = Array.from(new Set(domains.filter(Boolean)));
    if (unique.length === 0) {
        container.innerHTML = '<div class="text-xs text-slate-500">None</div>';
        return;
    }
    for (const d of unique) {
        const pill = document.createElement('div');
        pill.className = 'px-2 py-1 bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded';
        pill.textContent = d;
        container.appendChild(pill);
    }
}

function renderDomainsEditorPills() {
    if (!deployDomainsPills) return;
    const { main, extras } = getDomainsState();
    deployDomainsPills.innerHTML = '';
    const items = [];
    if (main) items.push({ domain: main, kind: 'main' });
    for (const d of extras) items.push({ domain: d, kind: 'extra' });

    if (items.length === 0) {
        deployDomainsPills.innerHTML = '<div class="text-xs text-slate-500">No domains yet</div>';
        return;
    }

    for (const item of items) {
        const pill = document.createElement('button');
        pill.type = 'button';
        pill.dataset.domain = item.domain;
        
        let baseClass = item.kind === 'main'
            ? 'bg-blue-500/10 border-blue-500/20 text-blue-300'
            : 'bg-slate-800 border-slate-700 text-slate-200';
        
        let content = item.kind === 'main' ? `${item.domain} (main)` : item.domain;

        // Apply status style if available
        const status = latestDomainStatuses[item.domain];
        if (status && status.live) {
            baseClass = 'bg-emerald-500/20 border-emerald-500/50 text-emerald-300 font-medium shadow-[0_0_10px_rgba(16,185,129,0.2)]';
            content += ' ✓';
        }

        pill.className = `px-2 py-1 border text-xs rounded transition-all duration-300 ${baseClass}`;
        pill.textContent = content;

        pill.addEventListener('click', () => {
            const state = getDomainsState();
            if (item.kind === 'main') {
                state.main = '';
            } else {
                state.extras = state.extras.filter(d => d !== item.domain);
            }
            setDomainsState(state);
        });
        deployDomainsPills.appendChild(pill);
    }
}


function renderInfoPill(container, text) {
    container.innerHTML = '';
    const pill = document.createElement('div');
    pill.className = 'px-2 py-1 bg-slate-800 border border-slate-700 text-slate-400 text-xs rounded';
    pill.textContent = text;
    container.appendChild(pill);
}

function openDeploy(index) {
    const server = savedServers[index];
    if (!server) return;

    // Fill form
    document.getElementById('deploy_server_id').value = server.id || '';
    document.getElementById('deploy_host').value = server.host;
    document.getElementById('deploy_user').value = server.user;
    document.getElementById('deploy_port').value = server.port;
    document.getElementById('deploy_password').value = server.password;
    // local_path is hidden but we set it
    const localPathInput = document.getElementById('deploy_local_path');
    if (localPathInput) {
        localPathInput.value = server.local_path || '';
    }
    document.getElementById('deploy_main_domain').value = server.main_domain || '';
    document.getElementById('deploy_domains').value = Array.isArray(server.domains) ? server.domains.join('\n') : '';
    // Rotation enabled is now always true and hidden
    // document.getElementById('deploy_rotation_enabled').checked = !!server.rotation_enabled;
    document.getElementById('deploy_wildcard_enabled').checked = !!server.wildcard_enabled;
    
    renderDomainsEditorPills();
    
    document.getElementById('deploy-target-name').textContent = server.host;
    
    // Reset status
    latestDomainStatuses = {};

    // Reset Terminal
    term.innerHTML = '<div class="text-brand-500/50 mb-4">Ready to deploy to ' + server.host + '...</div>';
    postActions.classList.add('hidden');
    deployActiveDomains.innerHTML = '<div class="text-xs text-slate-500">Checking...</div>';
    
    showView('deploy');
    
    // Auto check status
    setTimeout(() => {
        loadDomainStatus();
    }, 500);

    // Render Auto Links
    renderAutoLinks(server);

    try {
        const main = normalizeDomainClient(server?.main_domain || '');
        const host = server?.host || '';
        const target = main || host;
        if (target && adminFooterBtn) {
            adminFooterBtn.href = `http://${target}/admin.html`;
        }
    } catch (e) {}
}

// Sync inputs (Main Domain + Hidden Textarea) -> Editor Pills
deployMainDomainInput?.addEventListener('input', renderDomainsEditorPills);
// Note: deployDomainsInput is hidden but might change programmatically. 
// We rely on renderDomainsEditorPills to read it, but usually we write TO it.

deployAddDomainBtn?.addEventListener('click', () => {
    const next = normalizeDomainClient(deployAddDomainInput?.value || '');
    if (!next) return;
    const state = getDomainsState();
    if (!state.main) {
        state.main = next;
    } else if (next !== state.main) {
        state.extras = Array.from(new Set([...state.extras, next])).filter(d => d !== state.main);
    }
    setDomainsState(state);
    deployAddDomainInput.value = '';
    deployAddDomainInput.focus();
});

// Helper: Sync State -> Inputs (Main + Hidden Textarea)

loadActiveDomainsBtn?.addEventListener('click', async () => {
    await loadManagedDomains();
});

async function loadManagedDomains() {
    if (!loadActiveDomainsBtn) return;
    loadActiveDomainsBtn.disabled = true;
    renderInfoPill(deployActiveDomains, 'Loading...');
    const formData = new FormData(deployForm);
    try {
        const res = await fetch(apiUrl('list_managed_domains'), { method: 'POST', body: formData });
        const data = await res.json();
        if (data.status !== 'success') {
            renderInfoPill(deployActiveDomains, data.message || 'Failed');
        } else {
            renderDomainPills(deployActiveDomains, Array.isArray(data.domains) ? data.domains : []);
        }
    } catch (e) {
        renderInfoPill(deployActiveDomains, 'Request failed');
    } finally {
        loadActiveDomainsBtn.disabled = false;
    }
}

async function loadDomainStatus() {
    const btn = document.getElementById('checkStatusBtn');
    if (btn) btn.disabled = true;
    renderInfoPill(deployActiveDomains, 'Checking...');
    const formData = new FormData(deployForm);
    try {
        const res = await fetch(apiUrl('domain_status'), { method: 'POST', body: formData });
        const data = await res.json();
        if (data.status !== 'success') {
            renderInfoPill(deployActiveDomains, data.message || 'Failed');
            return;
        }
        const container = deployActiveDomains;
        container.innerHTML = '';
        const items = Array.isArray(data.statuses) ? data.statuses : [];
        
        // Update global status map
        latestDomainStatuses = {};
        for (const s of items) {
            latestDomainStatuses[s.domain] = s;
        }
        
        // Refresh editor pills to show status
        renderDomainsEditorPills();

        if (items.length === 0) {
            container.innerHTML = '<div class="text-xs text-slate-500">None</div>';
            return;
        }
        for (const s of items) {
            const pill = document.createElement('div');
            
            const isLive = !!s.live;
            const isLocal = !!s.local_live;
            const isMatch = !!s.matches_host;

            // Green if public live, Yellow if only local live, Red if neither
            let colorClass = 'bg-red-900/20 border-red-900/30 text-red-300';
            if (isLive) {
                colorClass = 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300';
            } else if (isLocal) {
                colorClass = 'bg-yellow-500/10 border-yellow-500/30 text-yellow-300';
            }

            pill.className = `px-2 py-1 border text-xs rounded ${colorClass}`;

            const code = s.https_code || s.http_code || s.local_code;
            const ip = s.dns_ip || '';
            
            let extra = '';
            if (!isMatch && ip) extra += ' (DNS ≠ Host)';
            else if (ip) extra += ' (' + ip + ')';
            
            pill.textContent = code ? `${s.domain} (${code})${extra}` : `${s.domain}${extra}`;
            container.appendChild(pill);
        }
    } catch (e) {
        renderInfoPill(deployActiveDomains, 'Request failed');
    } finally {
        if (btn) btn.disabled = false;
    }
}

applyDomainsBtn?.addEventListener('click', async () => {
    applyDomainsBtn.disabled = true;
    applyDomainsBtn.classList.add('opacity-50', 'cursor-not-allowed');
    postActions.classList.add('hidden');
    term.innerHTML += '<div class="text-emerald-500/50 mb-4">--- Apply Domains (Nginx) Initiated ---</div>';
    const formData = new FormData(deployForm);
    try {
        await streamResponse(apiUrl('apply_domains'), formData);
        await loadManagedDomains();
        await loadDomainStatus();
    } catch (e) {
    } finally {
        applyDomainsBtn.disabled = false;
        applyDomainsBtn.classList.remove('opacity-50', 'cursor-not-allowed');
    }
});

removeDomainsBtn?.addEventListener('click', async () => {
    if (!confirm('Remove ONLY the managed Nginx domain config from this VPS? (Files will stay)')) return;
    removeDomainsBtn.disabled = true;
    removeDomainsBtn.classList.add('opacity-50', 'cursor-not-allowed');
    postActions.classList.add('hidden');
    term.innerHTML += '<div class="text-orange-500/50 mb-4">--- Remove Domains (Nginx) Initiated ---</div>';
    const formData = new FormData(deployForm);
    try {
        await streamResponse(apiUrl('remove_domains_only'), formData);
        await loadManagedDomains();
        await loadDomainStatus();
    } catch (e) {
    } finally {
        removeDomainsBtn.disabled = false;
        removeDomainsBtn.classList.remove('opacity-50', 'cursor-not-allowed');
    }
});

function log(msg, type = 'info', time = null) {
    const div = document.createElement('div');
    div.className = `log-line log-${type}`;
    const timestamp = time ? `[${time}]` : `[${new Date().toLocaleTimeString()}]`;
    div.innerHTML = `<span class="text-gray-600 select-none mr-3 text-xs">${timestamp}</span><span class="break-words">${msg}</span>`;
    term.appendChild(div);
    term.scrollTop = term.scrollHeight;
}

async function streamResponse(url, formData) {
    try {
        const response = await fetch(url, { method: 'POST', body: formData });
        if (!response.ok || !response.body) {
            let msg = 'Server error: ' + response.status;
            try {
                const text = await response.text();
                if (text) {
                    msg += ' ' + text.substring(0, 200);
                }
            } catch (_) {}
            log(msg, 'error');
            throw new Error(msg);
        }
        const reader = response.body.getReader();
        const decoder = new TextDecoder();

        while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            
            const chunk = decoder.decode(value);
            const lines = chunk.split('\n\n');
            
            for (const line of lines) {
                if (line.startsWith('data: ')) {
                    const raw = line.substring(6).trim();
                    let data;
                    try {
                        data = JSON.parse(raw);
                    } catch (e) {
                        const m = raw.match(/\{[\s\S]*\}/);
                        if (m) {
                            try {
                                data = JSON.parse(m[0]);
                            } catch (e2) {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    }
                    if (data.message === 'DONE_DEPLOY') return 'DEPLOY_SUCCESS';
                    if (data.message === 'DONE_SSL') return 'SSL_SUCCESS';
                    log(data.message, data.type, data.time);
                }
            }
        }
    } catch (err) {
        log('Connection failed: ' + err.message, 'error');
        throw err;
    }
}

testBtn?.addEventListener('click', async () => {
    const originalText = testBtn.innerHTML;
    testBtn.disabled = true;
    testBtn.innerHTML = 'Connecting...';
    term.innerHTML += '<div class="text-yellow-500/50 mb-2">Initiating handshake...</div>';
    
    const formData = new FormData(deployForm);
    try {
        const data = await runAction('test_connection', formData);
        if (data.status === 'success') log('✅ ' + data.message, 'success');
        else log('❌ ' + data.message, 'error');
    } catch (err) {
        log('Connection Test Error: ' + err.message, 'error');
    } finally {
        testBtn.disabled = false;
        testBtn.innerHTML = originalText;
    }
});

saveBtn?.addEventListener('click', async () => {
    const originalText = saveBtn.innerText;
    saveBtn.disabled = true;
    saveBtn.textContent = 'Saving...';
    
    const formData = new FormData(deployForm);
    try {
        const data = await runAction('save_server', formData);
        if (data.status === 'success') log(data.message, 'success');
        else log('Save failed.', 'error');
    } catch (err) {
        log('Save Error: ' + err.message, 'error');
    } finally {
        saveBtn.disabled = false;
        saveBtn.textContent = originalText;
    }
});

updateBtn?.addEventListener('click', async () => {
    updateBtn.disabled = true;
    updateBtn.classList.add('opacity-50', 'cursor-not-allowed');
    saveBtn.disabled = true; 
    postActions.classList.add('hidden');
    term.innerHTML += '<div class="text-blue-500/50 mb-4">--- Update Sequence Initiated ---</div>';
    
    const formData = new FormData(deployForm);
    try {
        const result = await streamResponse(apiUrl('update'), formData);
        if (result === 'DEPLOY_SUCCESS') {
            postActions.classList.remove('hidden');
            const host = formData.get('host');
            const mainDomain = formData.get('main_domain');
            const target = mainDomain ? mainDomain : host;
            adminBtn.href = `http://${target}/admin.html`;
            adminBtn.classList.remove('hidden');
            postActions.scrollIntoView({ behavior: 'smooth' });
        }
    } catch (e) {
        // Already logged
    } finally {
        updateBtn.disabled = false;
        updateBtn.classList.remove('opacity-50', 'cursor-not-allowed');
        saveBtn.disabled = false;
    }
});

updateCodeBtn?.addEventListener('click', async () => {
    if (!confirm('Update page assets on the VPS? (This will zip and upload only page-related files)')) return;
    
    updateCodeBtn.disabled = true;
    updateCodeBtn.classList.add('opacity-50', 'cursor-not-allowed');
    // Hide post actions during update
    postActions.classList.add('hidden');
    term.innerHTML += '<div class="text-blue-500/50 mb-4">--- Code Update Initiated ---</div>';
    
    const formData = new FormData(deployForm);
    try {
        await streamResponse(apiUrl('update_page'), formData);
        // After success, show postActions again
        postActions.classList.remove('hidden');
    } catch (e) {
        // Logged
    } finally {
        updateCodeBtn.disabled = false;
        updateCodeBtn.classList.remove('opacity-50', 'cursor-not-allowed');
    }
});

deployForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    deployBtn.disabled = true;
    deployBtn.classList.add('opacity-50', 'cursor-not-allowed');
    saveBtn.disabled = true; 
    postActions.classList.add('hidden');
    term.innerHTML += '<div class="text-brand-500/50 mb-4">--- Deployment Sequence Initiated ---</div>';
    
    const formData = new FormData(deployForm);
    try {
        const result = await streamResponse(apiUrl('deploy'), formData);
        if (result === 'DEPLOY_SUCCESS') {
            postActions.classList.remove('hidden');
            const host = formData.get('host');
            const mainDomain = formData.get('main_domain');
            const target = mainDomain ? mainDomain : host;
            adminBtn.href = `http://${target}/admin.html`;
            adminBtn.classList.remove('hidden');
            postActions.scrollIntoView({ behavior: 'smooth' });
            await loadDomainStatus();
        }
    } catch (e) {
        // Already logged
    } finally {
        deployBtn.disabled = false;
        deployBtn.classList.remove('opacity-50', 'cursor-not-allowed');
        saveBtn.disabled = false;
    }
});

document.getElementById('checkStatusBtn')?.addEventListener('click', async () => {
    await fetchAndRenderLogs();
    await loadDomainStatus();
});

async function fetchAndRenderLogs() {
    const formData = new FormData(deployForm);
    try {
        const res = await fetch(apiUrl('view_logs'), { method: 'POST', body: formData });
        if (!res.ok) {
            throw new Error('HTTP ' + res.status);
        }
        const data = await res.json();
        if (data.status === 'success') {
            term.innerHTML += '<div class="text-sky-400/70 mb-1">--- Remote Logs ---</div>';
            for (const line of String(data.logs || '').split('\n')) {
                if (!line) continue;
                term.innerHTML += `<div class="text-xs text-slate-300 whitespace-pre-wrap">${line.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>`;
            }
            term.scrollTop = term.scrollHeight;
        } else {
            log(data.message || 'Failed to fetch logs', 'error');
        }
    } catch (e) {
        log('Error fetching logs: ' + e.message, 'error');
    }
}

async function handleSslConfig(btn) {
    if (!btn) return;
    btn.disabled = true;
    btn.classList.add('opacity-50', 'cursor-not-allowed');
    log('Starting SSL Configuration...', 'info');
    const formData = new FormData(deployForm);
    try {
        const result = await streamResponse(apiUrl('ssl'), formData);
        if (result === 'SSL_SUCCESS') {
            try {
                const currentUrl = new URL(adminBtn.href);
                currentUrl.protocol = 'https:';
                adminBtn.href = currentUrl.toString();
                try {
                    const fUrl = new URL(adminFooterBtn.href);
                    fUrl.protocol = 'https:';
                    adminFooterBtn.href = fUrl.toString();
                } catch (e) {}
                log('🔗 Admin link updated to HTTPS', 'success');
            } catch (e) {}
            await loadDomainStatus();
        }
    } catch (e) {
        // Already logged
    } finally {
        btn.disabled = false;
        btn.classList.remove('opacity-50', 'cursor-not-allowed');
    }
}

sslBtn?.addEventListener('click', () => handleSslConfig(sslBtn));
toolSslBtn?.addEventListener('click', () => handleSslConfig(toolSslBtn));

deleteBtn?.addEventListener('click', async () => {
    if (!confirm('This will DELETE project files and remove Nginx config on the VPS. Continue?')) return;
    deleteBtn.disabled = true;
    deleteBtn.classList.add('opacity-50', 'cursor-not-allowed');
    term.innerHTML += '<div class="text-red-500/50 mb-4">--- Cleanup Sequence Initiated ---</div>';
    const formData = new FormData(deployForm);
    try {
        await streamResponse(apiUrl('delete_uninstall'), formData);
    } catch (e) {
        log('Cleanup request failed: ' + e.message, 'error');
    } finally {
        deleteBtn.disabled = false;
        deleteBtn.classList.remove('opacity-50', 'cursor-not-allowed');
    }
});

viewLogsBtn?.addEventListener('click', fetchAndRenderLogs);
installChromeBtn?.addEventListener('click', async () => {
    installChromeBtn.disabled = true;
    installChromeBtn.classList.add('opacity-50', 'cursor-not-allowed');
    log('Starting Puppeteer Chrome install...', 'info');
    const formData = new FormData(deployForm);
    try {
        await streamResponse(apiUrl('puppeteer_install'), formData);
        await fetchAndRenderLogs();
    } catch (e) {
    } finally {
        installChromeBtn.disabled = false;
        installChromeBtn.classList.remove('opacity-50', 'cursor-not-allowed');
    }
});

copyLogsBtn?.addEventListener('click', async () => {
    const logEl = document.getElementById('log-terminal');
    if (!logEl) return;
    const text = logEl.textContent || '';
    if (!text) return;
    try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(text);
        } else {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
        }
    } catch (e) {
    }
});

function renderAutoLinks(server) {
    const container = document.getElementById('deployAutoLinks');
    if (!container) return;
    container.innerHTML = '';
    const main = normalizeDomainClient(server?.main_domain || server?.domain || '');
    const slugs = Array.isArray(server?.rotation_slugs) ? server.rotation_slugs : [];
    const path = server?.rotation_path || 'admg';

    if (!main || slugs.length === 0) {
        container.innerHTML = '<div class="text-xs text-slate-500">None</div>';
        return;
    }
    for (const s of slugs) {
        const url = `https://${main}/${path}/${s}`;
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'px-2 py-1 bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded';
        btn.textContent = url;
        btn.addEventListener('click', () => {
            window.open(url, '_blank');
        });
        container.appendChild(btn);
    }
}

function getCurrentServer() {
    const id = document.getElementById('deploy_server_id')?.value || '';
    return savedServers.find(s => s.id === id);
}
