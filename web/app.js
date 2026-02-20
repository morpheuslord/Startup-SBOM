/**
 * SBOM Scanner — Dashboard JavaScript v2.0
 * Tabbed dashboard with vulnerability, Docker, misconfiguration, and agent views.
 */
console.log('[SBOM] app.js v2.0 loaded');
window.__SBOM_LOADED = true;

// ─── Config ────────────────────────────────────────────────────────────
var API = '/api';
var REFRESH_MS = 30000;
var currentTab = 'overview';

// ─── Lucide helper ─────────────────────────────────────────────────────
function refreshIcons() {
    if (typeof lucide !== 'undefined') { lucide.createIcons(); }
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

function escHtml(s) {
    if (!s) return '';
    var d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

function scanTypeBadge(type) {
    var labels = { apt: 'APT', rpm: 'RPM', docker: 'Docker', 'trivy-fs': 'Filesystem', prowler: 'Prowler' };
    var cls = { apt: 'badge-apt', rpm: 'badge-rpm', docker: 'badge-docker', 'trivy-fs': 'badge-trivy', prowler: 'badge-prowler' };
    return '<span class="badge ' + (cls[type] || '') + '">' + (labels[type] || (type || '').toUpperCase()) + '</span>';
}

// ─── Tab Navigation ────────────────────────────────────────────────────
function switchTab(tabName) {
    currentTab = tabName;
    // Update nav links
    document.querySelectorAll('.nav-links a').forEach(function (a) {
        a.classList.toggle('active', a.getAttribute('data-tab') === tabName);
    });
    // Update tab content
    document.querySelectorAll('.tab-content').forEach(function (el) {
        el.classList.toggle('active', el.id === 'tab-' + tabName);
    });
    // Load data for the tab
    if (tabName === 'vulnerabilities') fetchVulnerabilities();
    else if (tabName === 'docker') fetchDockerImages();
    else if (tabName === 'misconfigs') fetchMisconfigurations();
    else if (tabName === 'agents') { fetchAgents(); loadAgentSelect(); }
    else if (tabName === 'scans') fetchAllScans();
    else if (tabName === 'overview') { updateStats(); updateRecentScans(); }
}

// Bind tab clicks
document.querySelectorAll('.nav-links a[data-tab]').forEach(function (a) {
    a.addEventListener('click', function (e) {
        e.preventDefault();
        switchTab(this.getAttribute('data-tab'));
    });
});

// ─── Overview: Stats ───────────────────────────────────────────────────
function updateStats() {
    api('/stats').then(function (s) {
        setText('active-agents', s.active_agents || 0);
        setText('total-agents', s.total_agents || 0);
        setText('total-scans', s.total_scans || 0);
        setText('scans-24h', s.scans_last_24h || 0);
        var completed = (s.scans_by_status && s.scans_by_status.completed) ? s.scans_by_status.completed : 0;
        setText('completed-scans', completed);
        setText('total-vulns', s.total_vulnerabilities || 0);
        var critical = (s.vulnerabilities_by_severity && s.vulnerabilities_by_severity.CRITICAL) ? s.vulnerabilities_by_severity.CRITICAL : 0;
        setText('critical-vulns', critical);
        setText('total-misconfigs', s.total_misconfigurations || 0);
        var mcFails = (s.misconfigs_by_status && s.misconfigs_by_status.FAIL) ? s.misconfigs_by_status.FAIL : 0;
        setText('misconfig-fails', mcFails);
        setText('total-docker-images', s.total_docker_images || 0);
        setText('docker-vulns', s.total_docker_vulns || 0);
        setText('last-update', new Date().toLocaleTimeString());

        // Update severity chart
        updateSeverityChart(s.vulnerabilities_by_severity || {});
    }).catch(function (e) {
        console.error('[SBOM] Stats error:', e);
    });
}

function updateSeverityChart(bySev) {
    var total = 0;
    var counts = { CRITICAL: bySev.CRITICAL || 0, HIGH: bySev.HIGH || 0, MEDIUM: bySev.MEDIUM || 0, LOW: bySev.LOW || 0 };
    Object.keys(counts).forEach(function (k) { total += counts[k]; });

    ['critical', 'high', 'medium', 'low'].forEach(function (sev) {
        var count = counts[sev.toUpperCase()] || 0;
        var pct = total > 0 ? Math.max((count / total) * 100, count > 0 ? 2 : 0) : 0;
        var bar = document.getElementById('sev-bar-' + sev);
        var cnt = document.getElementById('sev-count-' + sev);
        if (bar) bar.style.width = pct + '%';
        if (cnt) cnt.textContent = count;
    });
}

// ─── Overview: Recent Scans ────────────────────────────────────────────
function updateRecentScans() {
    api('/scans?limit=10').then(function (scans) {
        var tbody = document.querySelector('#recent-scans tbody');
        if (!scans || scans.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="state-msg">No scans yet — trigger one from the Agents tab</td></tr>';
            return;
        }
        tbody.innerHTML = scans.map(function (s) {
            return '<tr class="scan-row" onclick="showScanDetail(\'' + s.scan_id + '\')">'
                + '<td class="mono">' + escHtml(s.scan_id) + '</td>'
                + '<td>' + escHtml(s.hostname || s.agent_id) + '</td>'
                + '<td>' + scanTypeBadge(s.scan_type) + '</td>'
                + '<td><span class="status status-' + s.status + '">' + s.status + '</span></td>'
                + '<td>' + fmtTime(s.started_at) + '</td>'
                + '<td>' + fmtDuration(s.started_at, s.completed_at) + '</td>'
                + '</tr>';
        }).join('');
    }).catch(function (e) {
        console.error('[SBOM] Scans error:', e);
        document.querySelector('#recent-scans tbody').innerHTML = '<tr><td colspan="6" class="state-msg state-error">Failed to load scans</td></tr>';
    });
}

// ─── Vulnerabilities Tab ───────────────────────────────────────────────
function fetchVulnerabilities() {
    var severity = document.getElementById('vuln-severity-filter').value;
    var search = document.getElementById('vuln-search').value;
    var q = '?limit=200';
    if (severity) q += '&severity=' + severity;
    if (search) q += '&search=' + encodeURIComponent(search);

    api('/vulnerabilities' + q).then(function (vulns) {
        var tbody = document.getElementById('vulns-tbody');
        if (!vulns || vulns.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="state-msg">No vulnerabilities found</td></tr>';
            return;
        }
        tbody.innerHTML = vulns.map(function (v) {
            return '<tr>'
                + '<td class="mono">' + escHtml(v.cve_id || '–') + '</td>'
                + '<td><span class="status status-sev-' + (v.severity || '').toLowerCase() + '">' + escHtml(v.severity || '–') + '</span></td>'
                + '<td>' + escHtml(v.package_name || '–') + '</td>'
                + '<td class="mono">' + escHtml(v.package_version || '–') + '</td>'
                + '<td class="mono">' + escHtml(v.fixed_version || '–') + '</td>'
                + '<td class="mono">' + escHtml(v.cvss_score || '–') + '</td>'
                + '<td>' + scanTypeBadge(v.scan_type) + '</td>'
                + '</tr>';
        }).join('');
        refreshIcons();
    }).catch(function (e) {
        document.getElementById('vulns-tbody').innerHTML = '<tr><td colspan="7" class="state-msg state-error">Failed: ' + e.message + '</td></tr>';
    });
}

// Debounced search
var vulnSearchTimer;
var vulnSearchEl = document.getElementById('vuln-search');
if (vulnSearchEl) {
    vulnSearchEl.addEventListener('input', function () {
        clearTimeout(vulnSearchTimer);
        vulnSearchTimer = setTimeout(fetchVulnerabilities, 400);
    });
}
var vulnSevFilter = document.getElementById('vuln-severity-filter');
if (vulnSevFilter) vulnSevFilter.addEventListener('change', fetchVulnerabilities);

function exportVulnsCSV() {
    var severity = document.getElementById('vuln-severity-filter').value;
    var search = document.getElementById('vuln-search').value;
    var q = '?limit=5000';
    if (severity) q += '&severity=' + severity;
    if (search) q += '&search=' + encodeURIComponent(search);

    api('/vulnerabilities' + q).then(function (vulns) {
        if (!vulns || vulns.length === 0) return;
        var rows = [['CVE', 'Severity', 'Package', 'Version', 'Fixed', 'CVSS', 'Scan Type']];
        vulns.forEach(function (v) {
            rows.push([
                v.cve_id || '', v.severity || '', v.package_name || '',
                v.package_version || '', v.fixed_version || '', v.cvss_score || '',
                v.scan_type || ''
            ]);
        });
        var csv = rows.map(function (r) { return r.map(function (c) { return '"' + (c + '').replace(/"/g, '""') + '"'; }).join(','); }).join('\n');
        var blob = new Blob([csv], { type: 'text/csv' });
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'vulnerabilities_' + new Date().toISOString().slice(0, 10) + '.csv';
        a.click();
    });
}

// ─── Docker Tab ────────────────────────────────────────────────────────
function fetchDockerImages() {
    api('/docker-images?limit=100').then(function (images) {
        var grid = document.getElementById('docker-grid');
        if (!images || images.length === 0) {
            grid.innerHTML = '<p class="state-msg">No Docker images scanned yet. Trigger a Docker scan from the Agents tab.</p>';
            return;
        }
        grid.innerHTML = images.map(function (img) {
            var totalVulns = img.vulnerability_count || 0;
            var riskClass = totalVulns === 0 ? 'risk-clean' :
                (img.critical_count > 0 ? 'risk-critical' :
                    (img.high_count > 0 ? 'risk-high' : 'risk-medium'));

            return '<div class="docker-card ' + riskClass + '">'
                + '<div class="docker-card-header">'
                + '<i data-lucide="container" class="docker-card-icon"></i>'
                + '<div><strong>' + escHtml(img.image_name || '–') + '</strong>'
                + '<span class="docker-tag">' + escHtml(img.tag || 'latest') + '</span></div>'
                + '</div>'
                + '<div class="docker-card-stats">'
                + '<div class="docker-stat"><span class="sev-dot sev-critical"></span>' + (img.critical_count || 0) + ' Critical</div>'
                + '<div class="docker-stat"><span class="sev-dot sev-high"></span>' + (img.high_count || 0) + ' High</div>'
                + '<div class="docker-stat"><span class="sev-dot sev-medium"></span>' + (img.medium_count || 0) + ' Medium</div>'
                + '<div class="docker-stat"><span class="sev-dot sev-low"></span>' + (img.low_count || 0) + ' Low</div>'
                + '</div>'
                + '<div class="docker-card-footer">'
                + '<span class="docker-total">' + totalVulns + ' total vulnerabilities</span>'
                + '<span class="docker-time">' + fmtTime(img.scanned_at) + '</span>'
                + '</div>'
                + '</div>';
        }).join('');
        refreshIcons();
    }).catch(function (e) {
        document.getElementById('docker-grid').innerHTML = '<p class="state-msg state-error">Failed: ' + e.message + '</p>';
    });
}

// ─── Misconfigurations Tab ─────────────────────────────────────────────
function fetchMisconfigurations() {
    var severity = document.getElementById('mc-severity-filter').value;
    var status = document.getElementById('mc-status-filter').value;
    var source = document.getElementById('mc-source-filter').value;
    var q = '?limit=200';
    if (severity) q += '&severity=' + severity;
    if (status) q += '&status=' + status;
    if (source) q += '&source=' + source;

    api('/misconfigurations' + q).then(function (mcs) {
        var tbody = document.getElementById('misconfigs-tbody');
        if (!mcs || mcs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="state-msg">No misconfigurations found</td></tr>';
            document.getElementById('misconfig-summary').innerHTML = '';
            return;
        }

        // Summary counts
        var counts = { FAIL: 0, PASS: 0, WARN: 0 };
        mcs.forEach(function (m) { if (counts[m.status] !== undefined) counts[m.status]++; });
        document.getElementById('misconfig-summary').innerHTML =
            '<div class="mc-summary-pills">'
            + '<span class="mc-pill mc-fail"><i data-lucide="x-circle" style="width:14px;height:14px"></i> ' + counts.FAIL + ' Fail</span>'
            + '<span class="mc-pill mc-pass"><i data-lucide="check-circle" style="width:14px;height:14px"></i> ' + counts.PASS + ' Pass</span>'
            + '<span class="mc-pill mc-warn"><i data-lucide="alert-triangle" style="width:14px;height:14px"></i> ' + counts.WARN + ' Warn</span>'
            + '</div>';

        tbody.innerHTML = mcs.map(function (m, idx) {
            return '<tr class="mc-row" onclick="showMcDetail(' + idx + ')" data-mc-idx="' + idx + '">'
                + '<td class="mono">' + escHtml(m.check_id || '–') + '</td>'
                + '<td>' + escHtml(m.check_title || '–') + '</td>'
                + '<td><span class="status status-sev-' + (m.severity || '').toLowerCase() + '">' + escHtml(m.severity || '–') + '</span></td>'
                + '<td><span class="mc-status mc-status-' + (m.status || '').toLowerCase() + '">' + escHtml(m.status || '–') + '</span></td>'
                + '<td class="mono">' + escHtml((m.resource || '–').substring(0, 50)) + '</td>'
                + '<td>' + scanTypeBadge(m.source) + '</td>'
                + '</tr>';
        }).join('');

        // Store current data for detail view
        window.__mcData = mcs;
        refreshIcons();
    }).catch(function (e) {
        document.getElementById('misconfigs-tbody').innerHTML = '<tr><td colspan="6" class="state-msg state-error">Failed: ' + e.message + '</td></tr>';
    });
}

// Misconfig filter bindings
['mc-severity-filter', 'mc-status-filter', 'mc-source-filter'].forEach(function (id) {
    var el = document.getElementById(id);
    if (el) el.addEventListener('change', fetchMisconfigurations);
});

function showMcDetail(idx) {
    var mcs = window.__mcData;
    if (!mcs || !mcs[idx]) return;
    var m = mcs[idx];
    var modal = document.getElementById('mc-modal');
    var body = document.getElementById('mc-modal-body');
    modal.hidden = false;

    body.innerHTML = '<div class="detail-grid">'
        + '<div class="detail-item"><span>Check ID</span><strong class="mono">' + escHtml(m.check_id) + '</strong></div>'
        + '<div class="detail-item"><span>Title</span><strong>' + escHtml(m.check_title) + '</strong></div>'
        + '<div class="detail-item"><span>Severity</span><strong><span class="status status-sev-' + (m.severity || '').toLowerCase() + '">' + escHtml(m.severity) + '</span></strong></div>'
        + '<div class="detail-item"><span>Status</span><strong><span class="mc-status mc-status-' + (m.status || '').toLowerCase() + '">' + escHtml(m.status) + '</span></strong></div>'
        + '<div class="detail-item"><span>Resource</span><strong class="mono">' + escHtml(m.resource) + '</strong></div>'
        + '<div class="detail-item"><span>Source</span><strong>' + escHtml(m.source) + '</strong></div>'
        + '</div>'
        + (m.description ? '<div class="detail-block"><h4>Description</h4><p>' + escHtml(m.description) + '</p></div>' : '')
        + (m.remediation ? '<div class="detail-block"><h4>Remediation</h4><p>' + escHtml(m.remediation) + '</p></div>' : '');
    refreshIcons();
}

function closeMcModal() {
    document.getElementById('mc-modal').hidden = true;
}

var mcModalEl = document.getElementById('mc-modal');
if (mcModalEl) {
    mcModalEl.addEventListener('click', function (e) {
        if (e.target.classList.contains('modal-overlay')) closeMcModal();
    });
}

// ─── Agents Tab ────────────────────────────────────────────────────────
function fetchAgents() {
    api('/agents').then(function (agents) {
        var grid = document.getElementById('agents-grid');
        if (!agents || agents.length === 0) {
            grid.innerHTML = '<p class="state-msg">No agents registered yet.</p>';
            return;
        }
        grid.innerHTML = agents.map(function (a) {
            var scanners = [];
            if (a.config && a.config.scanners) scanners = a.config.scanners;
            var scannersHtml = scanners.length > 0
                ? scanners.map(function (s) { return scanTypeBadge(s); }).join(' ')
                : '<span class="badge">Unknown</span>';

            return '<div class="agent-card">'
                + '<div class="agent-card-header">'
                + '<div class="agent-status-dot ' + (a.status === 'active' ? 'agent-active' : 'agent-inactive') + '"></div>'
                + '<div><strong>' + escHtml(a.hostname || a.agent_id) + '</strong>'
                + '<span class="agent-id mono">' + escHtml(a.agent_id) + '</span></div>'
                + '</div>'
                + '<div class="agent-card-body">'
                + '<div class="agent-info-row"><span>Status</span><span class="status status-' + a.status + '">' + a.status + '</span></div>'
                + '<div class="agent-info-row"><span>OS</span><span>' + escHtml(a.os_info || '–') + '</span></div>'
                + '<div class="agent-info-row"><span>IP</span><span class="mono">' + escHtml(a.ip_address || '–') + '</span></div>'
                + '<div class="agent-info-row"><span>Last Seen</span><span>' + fmtTime(a.last_heartbeat) + '</span></div>'
                + '<div class="agent-info-row"><span>Scanners</span><span>' + scannersHtml + '</span></div>'
                + '</div>'
                + '<div class="agent-card-footer">'
                + '<span>Registered ' + fmtTime(a.registered_at) + '</span>'
                + '<button class="btn-ghost btn-sm" onclick="event.stopPropagation();deleteAgent(\'' + a.agent_id + '\')">'
                + '<i data-lucide="trash-2" style="width:14px;height:14px"></i></button>'
                + '</div>'
                + '</div>';
        }).join('');
        refreshIcons();
    }).catch(function (e) {
        document.getElementById('agents-grid').innerHTML = '<p class="state-msg state-error">Failed: ' + e.message + '</p>';
    });
}

function deleteAgent(agentId) {
    if (!confirm('Delete agent ' + agentId + '?')) return;
    fetch(API + '/agents/' + agentId, { method: 'DELETE' })
        .then(function () { fetchAgents(); loadAgentSelect(); })
        .catch(function (e) { alert('Failed: ' + e.message); });
}

function loadAgentSelect() {
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
            return '<option value="' + a.agent_id + '">' + escHtml(a.hostname || a.agent_id) + '</option>';
        }).join('');
        sel.disabled = false;
    }).catch(function () {
        var sel = document.getElementById('agent-select');
        sel.innerHTML = '<option value="">Error loading agents</option>';
        sel.disabled = true;
    });
}

// ─── Scans Tab ─────────────────────────────────────────────────────────
function fetchAllScans() {
    var status = document.getElementById('scan-status-filter').value;
    var type = document.getElementById('scan-type-filter').value;
    var q = '?limit=50';
    if (status) q += '&status=' + status;
    if (type) q += '&scan_type=' + type;

    api('/scans' + q).then(function (scans) {
        var tbody = document.getElementById('all-scans-tbody');
        if (!scans || scans.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="state-msg">No scans found</td></tr>';
            return;
        }
        tbody.innerHTML = scans.map(function (s) {
            return '<tr class="scan-row" onclick="showScanDetail(\'' + s.scan_id + '\')">'
                + '<td class="mono">' + escHtml(s.scan_id) + '</td>'
                + '<td>' + escHtml(s.hostname || s.agent_id) + '</td>'
                + '<td>' + scanTypeBadge(s.scan_type) + '</td>'
                + '<td><span class="status status-' + s.status + '">' + s.status + '</span></td>'
                + '<td>' + fmtTime(s.started_at) + '</td>'
                + '<td>' + fmtDuration(s.started_at, s.completed_at) + '</td>'
                + '</tr>';
        }).join('');
    }).catch(function (e) {
        document.getElementById('all-scans-tbody').innerHTML = '<tr><td colspan="6" class="state-msg state-error">Failed: ' + e.message + '</td></tr>';
    });
}

['scan-status-filter', 'scan-type-filter'].forEach(function (id) {
    var el = document.getElementById(id);
    if (el) el.addEventListener('change', fetchAllScans);
});

// ─── Scan Detail Modal ─────────────────────────────────────────────────
function showScanDetail(scanId) {
    var modal = document.getElementById('scan-modal');
    var body = document.getElementById('scan-modal-body');
    modal.hidden = false;
    body.innerHTML = '<p class="state-msg">Loading…</p>';

    api('/scans/' + scanId).then(function (s) {
        // Severity bar
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

        // Vulnerabilities table
        var vulnHtml = '';
        if (s.vulnerabilities && s.vulnerabilities.length > 0) {
            var vulnRows = s.vulnerabilities.slice(0, 100).map(function (v) {
                return '<tr>'
                    + '<td class="mono">' + escHtml(v.cve_id || '–') + '</td>'
                    + '<td><span class="status status-sev-' + (v.severity || '').toLowerCase() + '">' + escHtml(v.severity || '–') + '</span></td>'
                    + '<td>' + escHtml(v.package_name || '–') + '</td>'
                    + '<td class="mono">' + escHtml(v.package_version || '–') + '</td>'
                    + '<td class="mono">' + escHtml(v.fixed_version || '–') + '</td>'
                    + '</tr>';
            }).join('');
            var moreVulns = s.vulnerabilities.length > 100 ? '<tr><td colspan="5" class="state-msg">…and ' + (s.vulnerabilities.length - 100) + ' more</td></tr>' : '';
            vulnHtml = '<h3><i data-lucide="shield-alert" style="width:16px;height:16px"></i> Vulnerabilities (' + s.vulnerabilities.length + ')</h3>'
                + '<div class="table-wrap"><table class="detail-table"><thead><tr><th>CVE</th><th>Severity</th><th>Package</th><th>Version</th><th>Fixed</th></tr></thead>'
                + '<tbody>' + vulnRows + moreVulns + '</tbody></table></div>';
        }

        // Docker images
        var dockerHtml = '';
        if (s.docker_images && s.docker_images.length > 0) {
            var dockerRows = s.docker_images.map(function (d) {
                return '<tr>'
                    + '<td>' + escHtml(d.image_name || '–') + '</td>'
                    + '<td class="mono">' + escHtml(d.tag || '–') + '</td>'
                    + '<td>' + (d.vulnerability_count || 0) + '</td>'
                    + '<td><span class="sev-dot sev-critical"></span>' + (d.critical_count || 0) + '</td>'
                    + '<td><span class="sev-dot sev-high"></span>' + (d.high_count || 0) + '</td>'
                    + '</tr>';
            }).join('');
            dockerHtml = '<h3><i data-lucide="container" style="width:16px;height:16px"></i> Docker Images (' + s.docker_images.length + ')</h3>'
                + '<div class="table-wrap"><table class="detail-table"><thead><tr><th>Image</th><th>Tag</th><th>Total</th><th>Critical</th><th>High</th></tr></thead>'
                + '<tbody>' + dockerRows + '</tbody></table></div>';
        }

        // Misconfigurations
        var mcHtml = '';
        if (s.misconfigurations && s.misconfigurations.length > 0) {
            var mcRows = s.misconfigurations.slice(0, 50).map(function (m) {
                return '<tr>'
                    + '<td class="mono">' + escHtml(m.check_id || '–') + '</td>'
                    + '<td>' + escHtml((m.check_title || '–').substring(0, 60)) + '</td>'
                    + '<td><span class="status status-sev-' + (m.severity || '').toLowerCase() + '">' + escHtml(m.severity || '–') + '</span></td>'
                    + '<td><span class="mc-status mc-status-' + (m.status || '').toLowerCase() + '">' + escHtml(m.status || '–') + '</span></td>'
                    + '</tr>';
            }).join('');
            mcHtml = '<h3><i data-lucide="alert-octagon" style="width:16px;height:16px"></i> Misconfigurations (' + s.misconfigurations.length + ')</h3>'
                + '<div class="table-wrap" style="max-height:300px;overflow-y:auto"><table class="detail-table"><thead><tr><th>Check</th><th>Title</th><th>Severity</th><th>Status</th></tr></thead>'
                + '<tbody>' + mcRows + '</tbody></table></div>';
        }

        // Packages table
        var pkgHtml = '';
        if (s.packages && s.packages.length > 0) {
            var pkgRows = s.packages.slice(0, 100).map(function (p) {
                return '<tr><td>' + escHtml(p.name) + '</td><td class="mono">' + escHtml(p.version || '–') + '</td>'
                    + '<td>' + escHtml(p.package_manager || '–') + '</td><td>' + escHtml(p.architecture || '–') + '</td></tr>';
            }).join('');
            var morePkg = s.packages.length > 100 ? '<tr><td colspan="4" class="state-msg">…and ' + (s.packages.length - 100) + ' more</td></tr>' : '';
            pkgHtml = '<h3><i data-lucide="package" style="width:16px;height:16px"></i> Packages (' + s.packages.length + ')</h3>'
                + '<div class="table-wrap" style="max-height:300px;overflow-y:auto"><table class="detail-table"><thead><tr><th>Name</th><th>Version</th><th>Manager</th><th>Arch</th></tr></thead>'
                + '<tbody>' + pkgRows + morePkg + '</tbody></table></div>';
        }

        var errorHtml = s.error_message ? '<div class="toast toast-error">' + escHtml(s.error_message) + '</div>' : '';

        body.innerHTML = '<div class="detail-grid">'
            + '<div class="detail-item"><span>Scan ID</span><strong class="mono">' + escHtml(s.scan_id) + '</strong></div>'
            + '<div class="detail-item"><span>Agent</span><strong>' + escHtml(s.hostname || s.agent_identifier || '–') + '</strong></div>'
            + '<div class="detail-item"><span>Type</span><strong>' + scanTypeBadge(s.scan_type) + '</strong></div>'
            + '<div class="detail-item"><span>Status</span><strong><span class="status status-' + s.status + '">' + s.status + '</span></strong></div>'
            + '<div class="detail-item"><span>Started</span><strong>' + fmtTime(s.started_at) + '</strong></div>'
            + '<div class="detail-item"><span>Completed</span><strong>' + fmtTime(s.completed_at) + '</strong></div>'
            + '</div>'
            + sevBar + errorHtml + vulnHtml + dockerHtml + mcHtml + pkgHtml;

        refreshIcons();
    }).catch(function (e) {
        body.innerHTML = '<p class="state-msg state-error">Failed to load: ' + e.message + '</p>';
    });
}

function closeScanModal() {
    document.getElementById('scan-modal').hidden = true;
}

var scanModalEl = document.getElementById('scan-modal');
if (scanModalEl) {
    scanModalEl.addEventListener('click', function (e) {
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
        if (!agentId) { toast('trigger-status', 'Please select an agent', 'error'); return; }

        var btn = document.getElementById('trigger-btn');
        var orig = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<i data-lucide="loader" class="btn-icon-svg" style="animation:spin 1s linear infinite"></i> Triggering…';
        refreshIcons();

        post('/scans/trigger', { agent_id: agentId, scan_type: scanType })
            .then(function (result) {
                toast('trigger-status', 'Scan triggered: ' + result.scan_id, 'success');
                setTimeout(function () { updateRecentScans(); updateStats(); }, 2000);
            })
            .catch(function (err) { toast('trigger-status', 'Error: ' + err.message, 'error'); })
            .finally(function () { btn.disabled = false; btn.innerHTML = orig; refreshIcons(); });
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
                updateStats();
                updateRecentScans();
                // Refresh current tab if relevant
                if (currentTab === 'vulnerabilities') fetchVulnerabilities();
                else if (currentTab === 'docker') fetchDockerImages();
                else if (currentTab === 'misconfigs') fetchMisconfigurations();
                else if (currentTab === 'scans') fetchAllScans();
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

// ─── Init ──────────────────────────────────────────────────────────────
console.log('[SBOM] Initializing dashboard v2.0...');
try {
    updateStats();
    updateRecentScans();
    loadAgentSelect();
    connectSSE();
    setInterval(function () {
        updateStats();
        if (currentTab === 'overview') updateRecentScans();
    }, REFRESH_MS);
    refreshIcons();
    console.log('[SBOM] Dashboard initialized');
} catch (e) {
    console.error('[SBOM] Init error:', e);
}
