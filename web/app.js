/**
 * SBOM Scanner — Dashboard JavaScript
 * Vanilla JS: API client, SSE, dashboard logic, scan detail modal
 * Icons: Lucide (re-initialized after DOM updates)
 */
console.log('[SBOM] app.js loaded');
window.__SBOM_LOADED = true;

// ─── Config ────────────────────────────────────────────────────────────
var API = '/api';
var REFRESH_MS = 30000;

// ─── Lucide helper ─────────────────────────────────────────────────────
function refreshIcons() {
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }
}

// ─── API helpers ───────────────────────────────────────────────────────
function api(endpoint, opts) {
    opts = opts || {};
    return fetch(API + endpoint, opts).then(function (res) {
        if (!res.ok) throw new Error('HTTP ' + res.status + ': ' + res.statusText);
        return res.json();
    });
}

function post(endpoint, data) {
    return api(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
    });
}

// ─── Formatters ────────────────────────────────────────────────────────
function fmtTime(iso) {
    if (!iso) return '–';
    return new Date(iso).toLocaleString(undefined, {
        month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit',
    });
}

function fmtDuration(start, end) {
    if (!start || !end) return '–';
    var ms = new Date(end) - new Date(start);
    var s = Math.floor(ms / 1000);
    var m = Math.floor(s / 60);
    return m > 0 ? m + 'm ' + (s % 60) + 's' : s + 's';
}

function toast(elId, msg, type) {
    type = type || 'info';
    var el = document.getElementById(elId);
    if (!el) return;
    el.textContent = msg;
    el.className = 'toast toast-' + type;
    el.hidden = false;
    setTimeout(function () { el.hidden = true; }, 5000);
}

function setText(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = val;
}

// ─── Dashboard Updates ─────────────────────────────────────────────────
function updateStats() {
    api('/stats').then(function (s) {
        setText('total-agents', s.total_agents || 0);
        setText('active-agents', s.active_agents || 0);
        setText('total-scans', s.total_scans || 0);
        setText('scans-24h', s.scans_last_24h || 0);
        var completed = (s.scans_by_status && s.scans_by_status.completed) ? s.scans_by_status.completed : 0;
        setText('completed-scans', completed);
        setText('total-vulns', s.total_vulnerabilities || 0);
        var critical = (s.vulnerabilities_by_severity && s.vulnerabilities_by_severity.CRITICAL) ? s.vulnerabilities_by_severity.CRITICAL : 0;
        setText('critical-vulns', critical);
        setText('last-update', new Date().toLocaleTimeString());
    }).catch(function (e) {
        console.error('[SBOM] Stats error:', e);
        setText('total-agents', 'ERR');
    });
}

function updateRecentScans() {
    api('/scans?limit=10').then(function (scans) {
        var tbody = document.querySelector('#recent-scans tbody');

        if (!scans || scans.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="state-msg">No scans yet — trigger one below</td></tr>';
            return;
        }

        tbody.innerHTML = scans.map(function (s) {
            return '<tr class="scan-row" onclick="showScanDetail(\'' + s.scan_id + '\')">'
                + '<td class="mono">' + s.scan_id + '</td>'
                + '<td>' + (s.hostname || s.agent_id) + '</td>'
                + '<td><span class="badge">' + (s.scan_type || '').toUpperCase() + '</span></td>'
                + '<td><span class="status status-' + s.status + '">' + s.status + '</span></td>'
                + '<td>' + fmtTime(s.started_at) + '</td>'
                + '<td>' + fmtDuration(s.started_at, s.completed_at) + '</td>'
                + '</tr>';
        }).join('');
    }).catch(function (e) {
        console.error('[SBOM] Scans error:', e);
        var tbody = document.querySelector('#recent-scans tbody');
        tbody.innerHTML = '<tr><td colspan="6" class="state-msg state-error">Failed to load scans</td></tr>';
    });
}

function loadAgents() {
    api('/agents').then(function (agents) {
        var sel = document.getElementById('agent-select');

        if (!agents || agents.length === 0) {
            sel.innerHTML = '<option value="">No agents registered</option>';
            sel.disabled = true;
            return;
        }

        var active = agents.filter(function (a) { return a.status === 'active'; });

        if (active.length === 0) {
            sel.innerHTML = '<option value="">No active agents</option>';
            sel.disabled = true;
            return;
        }

        sel.innerHTML = active.map(function (a) {
            return '<option value="' + a.agent_id + '">' + (a.hostname || a.agent_id) + '</option>';
        }).join('');
        sel.disabled = false;
    }).catch(function (e) {
        console.error('[SBOM] Agents error:', e);
        var sel = document.getElementById('agent-select');
        sel.innerHTML = '<option value="">Error loading agents</option>';
        sel.disabled = true;
    });
}

// ─── Scan Detail Modal ─────────────────────────────────────────────────
function showScanDetail(scanId) {
    var modal = document.getElementById('scan-modal');
    var body = document.getElementById('scan-modal-body');
    modal.hidden = false;
    body.innerHTML = '<p class="state-msg">Loading…</p>';

    api('/scans/' + scanId).then(function (s) {
        var vulnHtml = '';
        if (s.vulnerabilities && s.vulnerabilities.length > 0) {
            var vulnRows = s.vulnerabilities.map(function (v) {
                return '<tr>'
                    + '<td class="mono">' + (v.cve_id || '–') + '</td>'
                    + '<td><span class="status status-sev-' + (v.severity || '').toLowerCase() + '">' + (v.severity || '–') + '</span></td>'
                    + '<td>' + (v.package_name || '–') + '</td>'
                    + '<td class="mono">' + (v.package_version || '–') + '</td>'
                    + '<td class="mono">' + (v.fixed_version || '–') + '</td>'
                    + '</tr>';
            }).join('');

            vulnHtml = '<h3><i data-lucide="shield-alert" style="width:16px;height:16px"></i> Vulnerabilities (' + s.vulnerabilities.length + ')</h3>'
                + '<div class="table-wrap"><table class="detail-table">'
                + '<thead><tr><th>CVE</th><th>Severity</th><th>Package</th><th>Version</th><th>Fixed</th></tr></thead>'
                + '<tbody>' + vulnRows + '</tbody></table></div>';
        }

        var pkgHtml = '';
        if (s.packages && s.packages.length > 0) {
            var pkgRows = s.packages.slice(0, 100).map(function (p) {
                return '<tr>'
                    + '<td>' + p.name + '</td>'
                    + '<td class="mono">' + (p.version || '–') + '</td>'
                    + '<td>' + (p.package_manager || '–') + '</td>'
                    + '<td>' + (p.architecture || '–') + '</td>'
                    + '</tr>';
            }).join('');

            var moreRow = s.packages.length > 100
                ? '<tr><td colspan="4" class="state-msg">…and ' + (s.packages.length - 100) + ' more</td></tr>'
                : '';

            pkgHtml = '<h3><i data-lucide="package" style="width:16px;height:16px"></i> Packages (' + s.packages.length + ')</h3>'
                + '<div class="table-wrap" style="max-height:300px;overflow-y:auto"><table class="detail-table">'
                + '<thead><tr><th>Name</th><th>Version</th><th>Manager</th><th>Arch</th></tr></thead>'
                + '<tbody>' + pkgRows + moreRow + '</tbody></table></div>';
        }

        var sevBar = '';
        if (s.stats) {
            var bars = '';
            if (s.stats.critical_count) bars += '<div class="sev sev-critical" style="flex:' + s.stats.critical_count + '">' + s.stats.critical_count + ' C</div>';
            if (s.stats.high_count) bars += '<div class="sev sev-high" style="flex:' + s.stats.high_count + '">' + s.stats.high_count + ' H</div>';
            if (s.stats.medium_count) bars += '<div class="sev sev-medium" style="flex:' + s.stats.medium_count + '">' + s.stats.medium_count + ' M</div>';
            if (s.stats.low_count) bars += '<div class="sev sev-low" style="flex:' + s.stats.low_count + '">' + s.stats.low_count + ' L</div>';
            if (s.stats.vulnerability_count === 0) bars = '<div class="sev sev-none" style="flex:1">No vulnerabilities</div>';
            sevBar = '<div class="severity-bar">' + bars + '</div>';
        }

        var errorHtml = s.error_message ? '<div class="toast toast-error">' + s.error_message + '</div>' : '';

        body.innerHTML = '<div class="detail-grid">'
            + '<div class="detail-item"><span>Scan ID</span><strong class="mono">' + s.scan_id + '</strong></div>'
            + '<div class="detail-item"><span>Agent</span><strong>' + (s.hostname || s.agent_identifier || '–') + '</strong></div>'
            + '<div class="detail-item"><span>Type</span><strong>' + (s.scan_type || '').toUpperCase() + '</strong></div>'
            + '<div class="detail-item"><span>Status</span><strong><span class="status status-' + s.status + '">' + s.status + '</span></strong></div>'
            + '<div class="detail-item"><span>Started</span><strong>' + fmtTime(s.started_at) + '</strong></div>'
            + '<div class="detail-item"><span>Completed</span><strong>' + fmtTime(s.completed_at) + '</strong></div>'
            + '</div>'
            + sevBar + errorHtml + vulnHtml + pkgHtml;

        refreshIcons();
    }).catch(function (e) {
        body.innerHTML = '<p class="state-msg state-error">Failed to load: ' + e.message + '</p>';
    });
}

function closeScanModal() {
    document.getElementById('scan-modal').hidden = true;
}

// Close modal on overlay click
var modalEl = document.getElementById('scan-modal');
if (modalEl) {
    modalEl.addEventListener('click', function (e) {
        if (e.target.classList.contains('modal-overlay')) closeScanModal();
    });
}

// ─── Trigger Scan ──────────────────────────────────────────────────────
var triggerForm = document.getElementById('trigger-form');
if (triggerForm) {
    triggerForm.addEventListener('submit', function (e) {
        e.preventDefault();

        var agentId = document.getElementById('agent-select').value;
        var scanType = document.getElementById('scan-type').value;

        if (!agentId) {
            toast('trigger-status', 'Please select an agent', 'error');
            return;
        }

        var btn = document.getElementById('trigger-btn');
        var orig = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<i data-lucide="loader" class="btn-icon-svg" style="animation:spin 1s linear infinite"></i> Triggering…';
        refreshIcons();

        post('/scans/trigger', {
            agent_id: agentId,
            scan_type: scanType,
        }).then(function (result) {
            toast('trigger-status', 'Scan triggered: ' + result.scan_id, 'success');
            setTimeout(function () { updateRecentScans(); updateStats(); }, 2000);
        }).catch(function (err) {
            toast('trigger-status', 'Error: ' + err.message, 'error');
        }).finally(function () {
            btn.disabled = false;
            btn.innerHTML = orig;
            refreshIcons();
        });
    });
}

// ─── SSE ───────────────────────────────────────────────────────────────
function connectSSE() {
    var statusEl = document.getElementById('connection-status');
    var dotEl = document.querySelector('.pulse-dot');
    var es = new EventSource('/api/events');

    es.onopen = function () {
        statusEl.textContent = 'Live';
        dotEl.classList.add('live');
    };

    es.onmessage = function (evt) {
        try {
            var data = JSON.parse(evt.data);
            if (data.type === 'scan_update') {
                updateRecentScans();
                updateStats();
            }
        } catch (_) { /* ignore */ }
    };

    es.onerror = function () {
        statusEl.textContent = 'Reconnecting…';
        dotEl.classList.remove('live');
        es.close();
        setTimeout(connectSSE, 5000);
    };
}

// ─── Init (runs immediately — script is at bottom of <body>) ──────────
console.log('[SBOM] Initializing dashboard...');
try {
    updateStats();
    updateRecentScans();
    loadAgents();
    connectSSE();
    setInterval(function () { updateStats(); updateRecentScans(); }, REFRESH_MS);
    refreshIcons();
    console.log('[SBOM] Dashboard initialized');
} catch (e) {
    console.error('[SBOM] Init error:', e);
}
