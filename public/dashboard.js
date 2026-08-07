/* ═══════════════════════════════════════════
   mona.expert — Dashboard v3
   Radical transparency · MonaExpert-powered security
   ═══════════════════════════════════════════ */

const mx = (() => {
  'use strict';

  /* ─── Helpers ─── */
  const $ = (s, p = document) => p.querySelector(s);
  const $$ = (s, p = document) => [...p.querySelectorAll(s)];
  const MX_API = '/api';

  const api = async (action, body = {}) => {
    const res = await fetch(`api.php?action=${action}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return res.json();
  };
  const authApi = async (action, body = {}) => {
    const token = localStorage.getItem('mx_token');
    const res = await fetch(`api.php?action=${action}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { 'X-Auth-Token': token } : {}) },
      body: JSON.stringify(body),
    });
    return res.json();
  };

  /* ─── Real system data API ─── */
  const systemApi = async (path) => {
    try {
      const res = await fetch(MX_API + '/' + path.replace(/^\//, ''));
      return res.ok ? res.json() : null;
    } catch (e) { return null; }
  };

  /* ─── Format helpers for real data ─── */
  const fmtBytes = (b) => {
    if (!b) return '—';
    const units = ['B', 'KB', 'MB', 'GB'];
    let i = 0;
    let v = b;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return v.toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
  };
  const fmtUptime = (s) => {
    if (!s) return '—';
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    let parts = [];
    if (d > 0) parts.push(d + 'd');
    if (h > 0) parts.push(h + 'h');
    parts.push(m + 'm');
    return parts.join(' ');
  };
  const esc = (s) => {
    const d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
  };
  const ago = (d) => {
    const s = Math.floor((Date.now() - new Date(d).getTime()) / 1000);
    if (s < 5) return 'gerade eben';
    if (s < 60) return `vor ${s}s`;
    const m = Math.floor(s / 60);
    if (m < 60) return `vor ${m}m`;
    const h = Math.floor(m / 60);
    if (h < 24) return `vor ${h}h`;
    const days = Math.floor(h / 24);
    return `vor ${days}d`;
  };
  const fmt = (d) => new Date(d).toLocaleString('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const fmtDate = (d) => new Date(d).toISOString().split('T')[0];
  const toast = (msg, type = 'info') => {
    const tc = document.getElementById('toastContainer');
    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    el.textContent = msg;
    tc.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; el.style.transform = 'translateX(30px)'; el.style.transition = 'all 0.3s'; setTimeout(() => el.remove(), 300); }, 4000);
  };

  /* ─── State ─── */
  const state = {
    user: null, userInfo: null,
    overview: { stats: null, recentLog: [], todayCount: 0, barData: [] },
    wrappers: [], agents: [],
    audit: { entries: [], total: 0, offset: 0, limit: 100, loading: false, allLoaded: false, q: '', from: '', to: '', type: '' },
    chat: { conversations: [], activeId: null, loading: false, loaded: false },
    live: { entries: [], count: 0, timer: null, telemetry: null, system: null, metrics: null },
    timers: [],
  };

  /* ─── Tab system ─── */
  const tabs = {
    overview: { title: 'Übersicht', render: renderOverview, init: initOverview },
    wrappers: { title: 'Wrapper', render: renderWrappers },
    agents: { title: 'Agenten', render: renderAgents },
    audit: { title: 'Audit-Log', render: renderAudit, init: initAudit },
    chat: { title: 'Chat', render: renderChat, init: initChat },
    live: { title: 'Live', render: renderLive, init: initLive, cleanup: cleanupLive },
    connect: { title: 'Verbinden', render: renderConnect },
    account: { title: 'Konto', render: renderAccount, init: initAccount },
    admin: { title: 'Admin', render: (el) => { el.innerHTML = '<iframe src="admin.html" style="width:100%;height:calc(100vh - 2rem);border:none;border-radius:var(--radius)"></iframe>'; } },
  };

  let currentTab = 'overview';
  let initialized = {};

  function switchTab(name) {
    currentTab = name;
    $$('.dash-sidebar a').forEach(a => a.classList.toggle('active', a.dataset.tab === name));
    $$('.dash-tab').forEach(t => t.style.display = t.id === `tab${capitalize(name)}` ? 'block' : 'none');
    const tab = tabs[name];
    if (!tab) return;
    const el = $(`#tab${capitalize(name)}`);
    if (!initialized[name]) {
      el.innerHTML = '';
      tab.render(el);
      if (tab.init) tab.init(el);
      initialized[name] = true;
    } else {
      // Re-render certain tabs
      if (name === 'audit' || name === 'live' || name === 'overview') {
        el.innerHTML = '';
        tab.render(el);
      }
    }
  }

  function capitalize(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

  /* ─── Init ─── */
  async function init() {
    $$('.dash-sidebar a').forEach(a => {
      a.addEventListener('click', (e) => { e.preventDefault(); switchTab(a.dataset.tab); });
    });

    // Mobile sidebar toggle
    const toggle = document.getElementById('sidebarToggle');
    const sidebar = document.querySelector('.dash-sidebar');
    if (toggle && sidebar) {
      toggle.addEventListener('click', () => sidebar.classList.toggle('open'));
      $$('.dash-sidebar a').forEach(a => a.addEventListener('click', () => sidebar.classList.remove('open')));
    }

    // Logout
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) logoutBtn.addEventListener('click', logout);

    // Auto-refresh overview every 30s
    state.timers.push(setInterval(() => {
      if (currentTab === 'overview') switchTab('overview');
    }, 30000));

    // Auto-refresh audit every 60s if on audit tab
    state.timers.push(setInterval(() => {
      if (currentTab === 'audit') { initialized.audit = false; switchTab('audit'); }
    }, 60000));

    // Initial load
    await fetchUser();
    switchTab('overview');
  }

  async function fetchUser() {
    try {
      const data = await authApi('me');
      if (data.status === 'ok') {
        state.user = data.user;
        state.userInfo = data;
        document.querySelector('.dash-user-name').textContent = data.user.name || data.user.email;
        // Show admin link for admin users
        const adminLink = document.getElementById('adminLink');
        if (adminLink) {
          adminLink.style.display = data.user.role === 'admin' ? '' : 'none';
        }
        return true;
      }
    } catch (e) { /* ignore */ }
    // Token invalid → redirect
    localStorage.removeItem('mx_token');
    window.location.href = 'login.html';
    return false;
  }

  function logout() {
    localStorage.removeItem('mx_token');
    state.timers.forEach(t => clearInterval(t));
    if (state.live.timer) clearInterval(state.live.timer);
    window.location.href = 'login.html';
  }

  /* ═══════════════════════════════════════════
     TAB: OVERVIEW — Activity Timeline + Stats + Security Cards
     ═══════════════════════════════════════════ */
  async function initOverview(el) { await renderOverview(el); }
  async function renderOverview(el) {
    el.innerHTML = '<div class="dash-loading"><svg class="ico" aria-hidden="true"><use href="#i-chart"/></svg> Lade Übersicht …</div>';

    // Fetch real system data + PHP data in parallel
    let systemData = null;
    let metricsData = null;
    try {
      const [sys, met] = await Promise.allSettled([
        systemApi('system'),
        systemApi('system/metrics'),
      ]);
      if (sys.status === 'fulfilled') systemData = sys.value;
      if (met.status === 'fulfilled') metricsData = met.value;
    } catch (e) { /* system data optional */ }

    try {
      const [statsRes, auditRes] = await Promise.all([
        authApi('get_audit_stats'),
        authApi('get_audit_log', { limit: 50, offset: 0 }),
      ]);
      state.overview.stats = statsRes.status === 'ok' ? statsRes : null;
      state.overview.recentLog = auditRes.status === 'ok' ? auditRes.log : [];
      state.overview.totalCount = auditRes.total || state.overview.recentLog.length;

      // Bar data from stats
      if (statsRes.status === 'ok' && statsRes.daily) {
        state.overview.barData = Object.entries(statsRes.daily).sort((a, b) => a[0].localeCompare(b[0]));
      }
    } catch (e) { /* use empty state */ }

    // Use real system data if available
    const hostname = systemData?.hostname || '—';
    const platform = systemData?.platform ? (systemData.platform === 'darwin' ? 'macOS' : systemData.platform) : '—';
    const realCpu = metricsData?.cpu || 0;
    const realMemPct = metricsData?.memory?.percent || 0;
    const realMemTotal = metricsData?.memory?.totalBytes || 0;
    const realMemUsed = metricsData?.memory?.usedBytes || 0;
    const realCpus = metricsData?.cpus || systemData?.cpus || 1;
    const realLoad = metricsData?.loadavg ? metricsData.loadavg[0] : (systemData?.loadavg ? systemData.loadavg[0] : 0);
    const cpuModel = systemData?.cpuModel || '';

    // Try PHP telemetry as fallback
    let tel = null;
    try {
      const telRes = await authApi('get_latest_telemetry', { limit: 1 }).catch(() => null);
      if (telRes?.status === 'ok' && telRes.latest) {
        tel = telRes.latest;
        state.overview.telemetry = tel;
      }
    } catch (e) { /* telemetry optional */ }

    const telDetails = tel?.details ? (typeof tel.details === 'string' ? JSON.parse(tel.details) : tel.details) : {};
    const disk = telDetails.disk || {};
    const diskTotalGb = disk.total_gb || '—';
    const diskUsedGb = disk.used_gb || '—';
    const diskPct = disk.pct || 0;

    const cpuPct = realCpu;
    const memPct = realMemPct;
    const memTotalGb = realMemTotal ? (realMemTotal / 1e9).toFixed(1) : '—';
    const memUsedGb = realMemUsed ? (realMemUsed / 1e9).toFixed(1) : '—';

    function barColor(pct) { return pct > 80 ? 'var(--red)' : pct > 50 ? 'var(--orange)' : 'var(--green)'; }

    /* ─── Sec Cards (MonaExpert-powered) ─── */
    el.innerHTML = `
      <!-- System Ressourcen -->
      <div class="dash-section">
        <div class="dash-section-title">
          <svg class="ico" aria-hidden="true"><use href="#i-zap"/></svg> Systemauslastung
          <span class="badge badge-blue">${hostname}</span>
        </div>
        <div class="stats-row">
          <div class="stat-tile">
            <div class="stat-tile-label" style="margin-bottom:6px"><svg class="ico" aria-hidden="true"><use href="#i-zap"/></svg> CPU</div>
            <div class="stat-tile-value" style="color:${barColor(cpuPct)}">${cpuPct}%</div>
            <div style="margin-top:8px;background:var(--surface2);border-radius:6px;height:6px;overflow:hidden">
              <div style="width:${Math.min(cpuPct, 100)}%;height:100%;background:${barColor(cpuPct)};border-radius:6px;transition:width 0.5s ease"></div>
            </div>
            <div class="stat-tile-label" style="margin-top:4px">${realCpus || '?'} Cores · Load ${realLoad ? Number(realLoad).toFixed(2) : '?'}</div>
          </div>
          <div class="stat-tile">
            <div class="stat-tile-label" style="margin-bottom:6px"><svg class="ico" aria-hidden="true"><use href="#i-package"/></svg> RAM</div>
            <div class="stat-tile-value" style="color:${barColor(memPct)};font-size:1.1rem">${memUsedGb} GB / ${memTotalGb} GB</div>
            <div style="margin-top:8px;background:var(--surface2);border-radius:6px;height:6px;overflow:hidden">
              <div style="width:${Math.min(memPct, 100)}%;height:100%;background:${barColor(memPct)};border-radius:6px;transition:width 0.5s ease"></div>
            </div>
            <div class="stat-tile-label" style="margin-top:4px">${memPct}% ausgelastet</div>
          </div>
          <div class="stat-tile">
            <div class="stat-tile-label" style="margin-bottom:6px"><svg class="ico" aria-hidden="true"><use href="#i-package"/></svg> Disk</div>
            <div class="stat-tile-value" style="color:${barColor(diskPct)};font-size:1.1rem">${diskUsedGb} GB / ${diskTotalGb} GB</div>
            <div style="margin-top:8px;background:var(--surface2);border-radius:6px;height:6px;overflow:hidden">
              <div style="width:${Math.min(diskPct, 100)}%;height:100%;background:${barColor(diskPct)};border-radius:6px;transition:width 0.5s ease"></div>
            </div>
            <div class="stat-tile-label" style="margin-top:4px">${diskPct}% belegt</div>
          </div>
          <div class="stat-tile">
            <div class="stat-tile-label" style="margin-bottom:6px"><svg class="ico" aria-hidden="true"><use href="#i-shield"/></svg> OpenClaw</div>
            <div class="stat-tile-value" style="color:var(--green);font-size:1.1rem">Online</div>
            <div class="stat-tile-label" style="margin-top:8px">Host: ${hostname} · ${realCpus || '?'} Cores · Uptime ${telDetails?.uptime ? Math.floor(telDetails.uptime / 86400) + 'd' : '—'}</div>
            <div class="stat-tile-label">Letzte Aktualisierung: ${tel?.created_at ? ago(tel.created_at) : '—'}</div>
          </div>
        </div>
      </div>

      <div class="dash-section">
        <div class="dash-section-title">
          <svg class="ico" aria-hidden="true"><use href="#i-shield"/></svg> MonaExpert‑Powered Security
          <span class="badge badge-green">ACTIVE</span>
        </div>
        <div class="security-cards">
          <div class="sec-card">
            <div class="sec-card-icon"><svg class="ico" aria-hidden="true"><use href="#i-zap"/></svg></div>
            <div class="sec-card-body">
              <div class="sec-card-title">Prompt Injection Protection</div>
              <div class="sec-card-desc">Jede LLM‑Interaktion wird durch MonaExperts Injection Guard analysiert – mehrstufige Erkennung von Keywords, Struktur‑Anomalien und Encoding‑Tricks.</div>
              <div class="sec-card-status"><span class="badge badge-green">Aktiv</span> ${state.overview.stats?.stats?.injection_blocks || 0} Blocks</div>
            </div>
          </div>
          <div class="sec-card">
            <div class="sec-card-icon"><svg class="ico" aria-hidden="true"><use href="#i-key"/></svg></div>
            <div class="sec-card-body">
              <div class="sec-card-title">Least‑Privilege API Keys</div>
              <div class="sec-card-desc">Wrapper‑API‑Keys sind auf minimale Berechtigungen beschränkt. Jeder Call wird auditiert und kann per Scope gefiltert werden.</div>
              <div class="sec-card-status"><span class="badge badge-green">Aktiv</span> Scope‑basiert</div>
            </div>
          </div>
          <div class="sec-card">
            <div class="sec-card-icon"><svg class="ico" aria-hidden="true"><use href="#i-clipboard"/></svg></div>
            <div class="sec-card-body">
              <div class="sec-card-title">Vollständiger Audit Trail</div>
              <div class="sec-card-desc">Sämtliche Operationen werden unveränderlich protokolliert – Login, Chat, API‑Calls, Wrapper‑Aktivität. Zeitmaschine inklusive.</div>
              <div class="sec-card-status"><span class="badge badge-green">Aktiv</span> ${state.overview.totalCount || 0} Einträge</div>
            </div>
          </div>
          <div class="sec-card">
            <div class="sec-card-icon"><svg class="ico" aria-hidden="true"><use href="#i-refresh"/></svg></div>
            <div class="sec-card-body">
              <div class="sec-card-title">Environment Sanitisation</div>
              <div class="sec-card-desc">MonaExpert säubert Umgebungsvariablen vor LLM‑Kontakt. Keine Secrets, keine System‑Prompts im Klartext – null Leakage.</div>
              <div class="sec-card-status"><span class="badge badge-green">Aktiv</span> Zero‑Trust</div>
            </div>
          </div>
        </div>
      </div>

      <div class="dash-section">
        <div class="dash-section-title"><svg class="ico" aria-hidden="true"><use href="#i-chart"/></svg> Aktivität (7 Tage)</div>
        <div class="chart-bars" id="ovChartBars"></div>
      </div>

      <div class="dash-section">
        <div class="dash-section-title">⏱ Live‑Timeline <span class="badge badge-blue">Letzte 50</span></div>
        <div class="timeline" id="ovTimeline"></div>
      </div>
    `;

    // Chart bars
    const chartEl = document.getElementById('ovChartBars');
    if (chartEl && state.overview.barData.length) {
      const maxVal = Math.max(...state.overview.barData.map(([, v]) => v), 1);
      chartEl.innerHTML = state.overview.barData.map(([day, count]) => {
        const h = (count / maxVal) * 100;
        const d = new Date(day).toLocaleDateString('de-DE', { weekday: 'short' });
        return `<div class="chart-col"><div class="chart-bar" style="height:${Math.max(h, 4)}%"></div><span class="chart-label">${d}</span><span class="chart-value">${count}</span></div>`;
      }).join('');
    } else if (chartEl) {
      chartEl.innerHTML = '<div class="empty-state">Noch keine Aktivität</div>';
    }

    // Timeline
    const tlEl = document.getElementById('ovTimeline');
    if (tlEl) {
      if (!state.overview.recentLog.length) {
        tlEl.innerHTML = '<div class="empty-state">Keine Ereignisse – lege los!</div>';
      } else {
        tlEl.innerHTML = state.overview.recentLog.map(e => {
          const icon = e.event_type === 'auth' ? '<svg class="ico" aria-hidden="true"><use href="#i-lock"/></svg>' : e.event_type === 'llm' ? '<svg class="ico" aria-hidden="true"><use href="#i-bot"/></svg>' : e.event_type === 'wrapper' ? '<svg class="ico" aria-hidden="true"><use href="#i-link"/></svg>' : e.event_type === 'agent' ? '<svg class="ico" aria-hidden="true"><use href="#i-zap"/></svg>' : e.event_type === 'api' ? '<svg class="ico" aria-hidden="true"><use href="#i-broadcast"/></svg>' : '<svg class="ico" aria-hidden="true"><use href="#i-plus"/></svg>';
          const statusIcon = e.status === 'success' ? '<svg class="ico" aria-hidden="true"><use href="#i-check"/></svg>' : e.status === 'blocked' ? '<svg class="ico" aria-hidden="true"><use href="#i-ban"/></svg>' : e.status === 'error' ? '<svg class="ico" aria-hidden="true"><use href="#i-x"/></svg>' : '⏳';
          return `<div class="timeline-item"><span class="tl-time">${ago(e.created_at)}</span><span class="tl-icon">${icon}</span><span class="tl-action">${esc(e.action)}</span><span class="tl-status">${statusIcon}</span><span class="tl-detail">${esc((JSON.parse(e.details || '{}')).conversation_id ? 'Chat-Konversation' : e.details ? e.details.substring(0, 80) : '')}</span></div>`;
        }).join('');
      }
    }
  }

  /* ═══════════════════════════════════════════
     TAB: WRAPPERS
     ═══════════════════════════════════════════ */
  async function renderWrappers(el) {
    el.innerHTML = '<div class="dash-loading"><svg class="ico" aria-hidden="true"><use href="#i-link"/></svg> Lade Wrapper …</div>';
    try {
      const data = await authApi('list_wrappers');
      state.wrappers = data.status === 'ok' ? data.wrappers || [] : [];
    } catch (e) { state.wrappers = []; }

    if (!state.wrappers.length) {
      el.innerHTML = `
        <div class="dash-section">
          <div class="dash-section-title"><svg class="ico" aria-hidden="true"><use href="#i-link"/></svg> Wrapper</div>
          <div class="empty-state">
            <p>Keine Wrapper installiert</p>
            <p class="empty-sub">Installiere den mona‑wrapper auf deinem Rechner für vollständige Transparenz:</p>
            <pre class="install-cmd">curl -sL https://mona.expert/download/install.sh | bash</pre>
            <p class="empty-sub">Danach: <code>mona-wrapper init</code> → <code>mona-wrapper start</code></p>
          </div>
        </div>`;
      return;
    }

    el.innerHTML = `<div class="dash-section"><div class="dash-section-title"><svg class="ico" aria-hidden="true"><use href="#i-link"/></svg> Wrapper (${state.wrappers.length})</div><div class="wrapper-grid">${state.wrappers.map(w => {
      const online = w.last_heartbeat && (Date.now() - new Date(w.last_heartbeat).getTime()) < 60000;
      return `<div class="wrapper-card"><div class="wrap-header"><span class="wrap-name">${esc(w.name || 'Unbenannt')}</span><span class="badge ${online ? 'badge-green' : 'badge-amber'}">${online ? '<svg class="ico" aria-hidden="true"><use href="#i-check"/></svg> Online' : '<svg class="ico" aria-hidden="true"><use href="#i-alert"/></svg> Offline'}</span></div><div class="wrap-meta"><span>ID: ${esc(w.wrapper_id || w.id || '—').substring(0, 16)}…</span><span>Letzter Ping: ${w.last_heartbeat ? ago(w.last_heartbeat) : '–'}</span></div>${w.version ? `<div class="wrap-version">v${esc(w.version)}</div>` : ''}</div>`;
    }).join('')}</div></div>`;
  }

  /* ═══════════════════════════════════════════
     TAB: AGENTS
     ═══════════════════════════════════════════ */
  async function renderAgents(el) {
    el.innerHTML = '<div class="dash-loading"><svg class="ico" aria-hidden="true"><use href="#i-bot"/></svg> Lade Agenten …</div>';
    try {
      const data = await authApi('list_agents');
      state.agents = data.status === 'ok' ? data.agents || [] : [];
    } catch (e) { state.agents = []; }

    if (!state.agents.length) {
      el.innerHTML = `<div class="dash-section"><div class="dash-section-title"><svg class="ico" aria-hidden="true"><use href="#i-bot"/></svg> Agenten</div><div class="empty-state"><p>Keine Agenten registriert</p><p class="empty-sub">Agenten erscheinen hier, sobald ein Wrapper sie registriert.</p></div></div>`;
      return;
    }

    el.innerHTML = `<div class="dash-section"><div class="dash-section-title"><svg class="ico" aria-hidden="true"><use href="#i-bot"/></svg> Agenten (${state.agents.length})</div><div class="agent-grid">${state.agents.map(a => {
      const statusIcon = a.status === 'running' ? '<svg class="ico" aria-hidden="true"><use href="#i-check"/></svg>' : a.status === 'error' ? '<svg class="ico" aria-hidden="true"><use href="#i-alert"/></svg>' : '<svg class="ico" aria-hidden="true"><use href="#i-refresh"/></svg>';
      return `<div class="agent-card"><div class="agent-header"><span class="agent-name">${esc(a.name || 'Unbenannt')}</span><span class="badge badge-purple">${esc(a.type || '—')}</span></div><div class="agent-status">${statusIcon} ${esc(a.status || 'unknown')} ${a.pid ? `· PID ${a.pid}` : ''}</div>${a.wrapper_name ? `<div class="agent-wrapper"><svg class="ico" aria-hidden="true"><use href="#i-link"/></svg> ${esc(a.wrapper_name)}</div>` : ''}${a.config ? `<div class="agent-config"><code>${esc(JSON.stringify(a.config).substring(0, 120))}</code></div>` : ''}</div>`;
    }).join('')}</div></div>`;
  }

  /* ═══════════════════════════════════════════
     TAB: AUDIT — Paginated, Searchable, Time Machine
     ═══════════════════════════════════════════ */
  async function initAudit(el) { await renderAudit(el); }

  async function loadAudit(append = false) {
    if (state.audit.loading) return;
    state.audit.loading = true;

    if (!append) {
      state.audit.offset = 0;
      state.audit.entries = [];
      state.audit.allLoaded = false;
    }

    try {
      const data = await authApi('search_logs', {
        q: state.audit.q,
        limit: state.audit.limit,
        offset: state.audit.offset,
      });
      if (data.status === 'ok') {
        if (append) state.audit.entries = state.audit.entries.concat(data.log);
        else state.audit.entries = data.log;
        state.audit.total = data.total || state.audit.entries.length;
        state.audit.offset += data.log.length;
        if (data.log.length < state.audit.limit) state.audit.allLoaded = true;
      }
    } catch (e) { /* ignore */ }
    state.audit.loading = false;
  }

  async function renderAudit(el) {
    el.innerHTML = `
      <div class="dash-section">
        <div class="dash-section-title">
          <svg class="ico" aria-hidden="true"><use href="#i-clipboard"/></svg> Audit-Log
          <span class="badge badge-blue" id="auditCountBadge">0 Einträge</span>
        </div>
        <div class="audit-controls">
          <div class="audit-search-wrap">
            <input type="text" id="auditSearch" placeholder="<svg class="ico" aria-hidden="true"><use href="#i-search"/></svg> Durchsuchen …" value="${esc(state.audit.q)}">
            <button id="auditSearchBtn" class="audit-btn">Suchen</button>
            ${state.audit.q ? '<button id="auditClearBtn" class="audit-btn audit-btn-outline"><svg class="ico" aria-hidden="true"><use href="#i-x"/></svg></button>' : ''}
          </div>
          <div class="audit-filters">
            <input type="date" id="auditFrom" value="${state.audit.from}">
            <span>→</span>
            <input type="date" id="auditTo" value="${state.audit.to}">
            <select id="auditType">
              <option value="">Alle Typen</option>
              <option value="auth" ${state.audit.type === 'auth' ? 'selected' : ''}>Auth</option>
              <option value="llm" ${state.audit.type === 'llm' ? 'selected' : ''}>LLM</option>
              <option value="wrapper" ${state.audit.type === 'wrapper' ? 'selected' : ''}>Wrapper</option>
              <option value="agent" ${state.audit.type === 'agent' ? 'selected' : ''}>Agent</option>
              <option value="api" ${state.audit.type === 'api' ? 'selected' : ''}>API</option>
            </select>
          </div>
        </div>
        <div class="audit-log-list" id="auditLogList">
          <div class="dash-loading"><svg class="ico" aria-hidden="true"><use href="#i-clipboard"/></svg> Lade …</div>
        </div>
      </div>`;

    // Bind filters
    const searchBtn = document.getElementById('auditSearchBtn');
    const searchInput = document.getElementById('auditSearch');
    const clearBtn = document.getElementById('auditClearBtn');
    const fromEl = document.getElementById('auditFrom');
    const toEl = document.getElementById('auditTo');
    const typeEl = document.getElementById('auditType');

    const doSearch = async () => {
      state.audit.q = searchInput.value.trim();
      state.audit.from = fromEl.value;
      state.audit.to = toEl.value;
      state.audit.type = typeEl.value;
      await loadAudit(false);
      renderAuditList();
    };

    searchBtn.addEventListener('click', doSearch);
    searchInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') doSearch(); });
    if (clearBtn) clearBtn.addEventListener('click', async () => { searchInput.value = ''; state.audit.q = ''; await doSearch(); });
    fromEl.addEventListener('change', doSearch);
    toEl.addEventListener('change', doSearch);
    typeEl.addEventListener('change', doSearch);

    await loadAudit(false);
    renderAuditList();
  }

  function renderAuditList() {
    const list = document.getElementById('auditLogList');
    const badge = document.getElementById('auditCountBadge');
    if (!list) return;
    if (badge) badge.textContent = `${state.audit.total} Einträge`;

    if (!state.audit.entries.length) {
      list.innerHTML = '<div class="empty-state">Keine Einträge gefunden</div>';
      return;
    }

    list.innerHTML = state.audit.entries.map(e => {
      const icon = e.event_type === 'auth' ? '<svg class="ico" aria-hidden="true"><use href="#i-lock"/></svg>' : e.event_type === 'llm' ? '<svg class="ico" aria-hidden="true"><use href="#i-bot"/></svg>' : e.event_type === 'wrapper' ? '<svg class="ico" aria-hidden="true"><use href="#i-link"/></svg>' : e.event_type === 'agent' ? '<svg class="ico" aria-hidden="true"><use href="#i-zap"/></svg>' : e.event_type === 'api' ? '<svg class="ico" aria-hidden="true"><use href="#i-broadcast"/></svg>' : '<svg class="ico" aria-hidden="true"><use href="#i-plus"/></svg>';
      const statusIcon = e.status === 'success' ? '<svg class="ico" aria-hidden="true"><use href="#i-check"/></svg>' : e.status === 'blocked' ? '<svg class="ico" aria-hidden="true"><use href="#i-ban"/></svg>' : e.status === 'error' ? '<svg class="ico" aria-hidden="true"><use href="#i-x"/></svg>' : '⏳';
      const details = (() => { try { const d = JSON.parse(e.details || '{}'); return d.conversation_id ? `Konv: ${d.conversation_id.substring(0, 8)}…` : JSON.stringify(d).substring(0, 60); } catch { return esc(e.details || '').substring(0, 60); } })();
      return `<div class="audit-row"><span class="audit-time" title="${fmt(e.created_at)}">${ago(e.created_at)}</span><span class="audit-icon">${icon}</span><span class="audit-event">${esc(e.event_type)}</span><span class="audit-action">${esc(e.action)}</span><span class="audit-status">${statusIcon}</span><span class="audit-detail">${details}</span></div>`;
    }).join('') + (state.audit.allLoaded ? '' : '<div class="audit-load-more" id="auditLoadMore"><button class="audit-btn">Mehr laden …</button></div>');

    // Bind load more
    const loadMore = document.getElementById('auditLoadMore');
    if (loadMore) {
      const btn = loadMore.querySelector('button');
      btn.addEventListener('click', async () => {
        await loadAudit(true);
        renderAuditList();
      });
      // Infinite scroll via IntersectionObserver
      const obs = new IntersectionObserver((entries) => {
        if (entries[0].isIntersecting && !state.audit.allLoaded && !state.audit.loading) {
          btn.click();
        }
      }, { rootMargin: '200px' });
      obs.observe(loadMore);
      // Also store obs for cleanup
      loadMore._observer = obs;
    }
  }

  /* ═══════════════════════════════════════════
     TAB: CHAT — MonaExpert-powered LLM Chat
     ═══════════════════════════════════════════ */
  function initChat(el) { renderChat(el); }

  function saveConversations() {
    localStorage.setItem('mx_conv', JSON.stringify(state.chat.conversations));
  }

  function renderChat(el) {
    el.innerHTML = `
      <div class="dash-chat-layout">
        <div class="chat-sidebar" id="chatSidebar">
          <div class="chat-sidebar-header">
            <span><svg class="ico" aria-hidden="true"><use href="#i-message"/></svg> Konversationen</span>
            <button id="chatNewBtn" class="chat-new-btn" title="Neue Konversation">+</button>
          </div>
          <div class="chat-conv-list" id="chatConvList"></div>
        </div>
        <div class="chat-main" id="chatMain">
          <div class="chat-placeholder" id="chatPlaceholder">
            <div class="chat-placeholder-icon"><svg class="ico" aria-hidden="true"><use href="#i-message"/></svg></div>
            <h3>MonaExpert Chat</h3>
            <p>Starte eine neue Konversation oder wähle eine bestehende aus.</p>
            <p class="chat-placeholder-sub">Jede Nachricht wird durch den <strong>Injection Guard</strong> geprüft und vollständig auditiert.</p>
            <button id="chatStartBtn" class="auth-btn" style="max-width:260px;margin:20px auto"><svg class="ico" aria-hidden="true"><use href="#i-message"/></svg> Neue Konversation</button>
          </div>
          <div class="chat-messages" id="chatMessages" style="display:none">
            <div class="chat-messages-list" id="chatMessagesList"></div>
            <div class="chat-input-bar">
              <div class="chat-injection-info" id="chatInjectionInfo" style="display:none"></div>
              <textarea id="chatInput" rows="2" placeholder="Nachricht eingeben …" maxlength="10000"></textarea>
              <button id="chatSendBtn" class="chat-send-btn"><svg class="ico" aria-hidden="true"><use href="#i-arrow-right"/></svg></button>
            </div>
          </div>
        </div>
      </div>`;

    renderConvList();

    // New conversation
    const newBtn = document.getElementById('chatNewBtn');
    const startBtn = document.getElementById('chatStartBtn');
    const handler = () => newConversation();
    if (newBtn) newBtn.addEventListener('click', handler);
    if (startBtn) startBtn.addEventListener('click', handler);

    // Send
    const sendBtn = document.getElementById('chatSendBtn');
    const chatInput = document.getElementById('chatInput');
    const sendHandler = () => sendMessage();
    if (sendBtn) sendBtn.addEventListener('click', sendHandler);
    if (chatInput) {
      chatInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
      });
    }

    // Open active conversation if exists
    if (state.chat.activeId) {
      openConversation(state.chat.activeId);
    }
  }

  function renderConvList() {
    const list = document.getElementById('chatConvList');
    if (!list) return;
    if (!state.chat.conversations.length) {
      list.innerHTML = '<div class="chat-conv-empty">Noch keine Konversationen</div>';
      return;
    }
    list.innerHTML = state.chat.conversations.map(c => {
      const lastMsg = c.messages && c.messages.length ? c.messages[c.messages.length - 1] : null;
      const preview = lastMsg ? (lastMsg.role === 'user' ? 'Du: ' : 'Bot: ') + (lastMsg.content ? lastMsg.content.substring(0, 40) : '…') : 'Neu';
      const blocked = lastMsg && lastMsg.injection_analysis && lastMsg.injection_analysis.blocked;
      return `<div class="chat-conv-item ${c.id === state.chat.activeId ? 'active' : ''} ${blocked ? 'conv-blocked' : ''}" data-conv-id="${c.id}"><div class="conv-title">${esc(c.title || 'Neue Konversation')}</div><div class="conv-preview">${esc(preview)}</div><div class="conv-meta">${c.messages.length} Nachrichten · ${c.created_at ? ago(c.created_at) : ''}</div></div>`;
    }).join('');

    $$('.chat-conv-item', list).forEach(item => {
      item.addEventListener('click', () => openConversation(item.dataset.convId));
    });
  }

  function newConversation() {
    const conv = {
      id: 'conv_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6),
      title: 'Neue Konversation',
      messages: [],
      created_at: new Date().toISOString(),
    };
    state.chat.conversations.unshift(conv);
    state.chat.activeId = conv.id;
    saveConversations();
    renderConvList();
    openConversation(conv.id);
  }

  function openConversation(id) {
    const conv = state.chat.conversations.find(c => c.id === id);
    if (!conv) return;
    state.chat.activeId = id;
    state.chat.conversations.filter(c => c.id !== id);

    // Update sidebar active
    renderConvList();

    const placeholder = document.getElementById('chatPlaceholder');
    const messages = document.getElementById('chatMessages');
    if (placeholder) placeholder.style.display = 'none';
    if (messages) messages.style.display = 'flex';

    renderMessages(conv);
  }

  function renderMessages(conv) {
    const list = document.getElementById('chatMessagesList');
    const input = document.getElementById('chatInput');
    if (!list) return;

    // Update title
    const convTitle = conv.title;
    // Auto-title from first user message
    if (conv.messages.length && conv.messages[0].role === 'user' && conv.title === 'Neue Konversation') {
      conv.title = conv.messages[0].content.substring(0, 50) + (conv.messages[0].content.length > 50 ? '…' : '');
      saveConversations();
    }

    if (!conv.messages.length) {
      list.innerHTML = '<div class="chat-empty-msg">Sende deine erste Nachricht an MonaExpert <svg class="ico" aria-hidden="true"><use href="#i-bot"/></svg></div>';
      return;
    }

    list.innerHTML = conv.messages.map((msg, i) => {
      const isUser = msg.role === 'user';
      const inj = msg.injection_analysis;
      const showAnalysis = inj && !isUser;
      const showBlocked = inj && inj.blocked && isUser;

      return `<div class="chat-msg ${isUser ? 'chat-msg-user' : 'chat-msg-bot'} ${showBlocked ? 'chat-msg-blocked' : ''}">
        <div class="chat-msg-avatar">${isUser ? '<svg class="ico" aria-hidden="true"><use href="#i-user"/></svg>' : '<svg class="ico" aria-hidden="true"><use href="#i-shield"/></svg>'}</div>
        <div class="chat-msg-content">
          ${showBlocked ? '<div class="chat-msg-blocked-badge"><svg class="ico" aria-hidden="true"><use href="#i-ban"/></svg> Geblockt durch Injection Guard</div>' : ''}
          <div class="chat-msg-text">${esc(msg.content).replace(/\n/g, '<br>')}</div>
          ${showAnalysis ? `<div class="chat-analysis"><details><summary><svg class="ico" aria-hidden="true"><use href="#i-zap"/></svg> Injection Analysis</summary><pre>${esc(JSON.stringify(inj, null, 2))}</pre></details></div>` : ''}
          ${msg.timestamp ? `<div class="chat-msg-time">${ago(msg.timestamp)}</div>` : ''}
          ${msg.audit_logged ? `<div class="chat-msg-audit"><svg class="ico" aria-hidden="true"><use href="#i-check"/></svg> Auditiert</div>` : ''}
        </div>
      </div>`;
    }).join('');

    // Scroll to bottom
    list.scrollTop = list.scrollHeight;

    // Focus input
    if (input) input.focus();
  }

  async function sendMessage() {
    const input = document.getElementById('chatInput');
    const sendBtn = document.getElementById('chatSendBtn');
    if (!input || !sendBtn) return;

    const text = input.value.trim();
    if (!text) return;

    // Ensure conversation exists
    if (!state.chat.activeId) await newConversation();

    // Disable input
    input.disabled = true;
    sendBtn.disabled = true;
    sendBtn.textContent = '⏳';

    // Show user message immediately
    renderMessages([{ role: 'user', content: text, created_at: new Date().toISOString() }]);

    // Show injection analysis info bar
    const injInfo = document.getElementById('chatInjectionInfo');
    if (injInfo) {
      injInfo.style.display = 'block';
      injInfo.innerHTML = '<span class="btn-spinner"></span> MonaExpert Injection Guard prüft …';
    }

    try {
      const data = await authApi('llm_chat', {
        message: text,
        conversation_id: state.chat.activeId,
      });

      const responseText = data.response || '<svg class="ico" aria-hidden="true"><use href="#i-alert"/></svg> Keine Antwort erhalten';
      const injAnalysis = data.injection_analysis || null;

      // Reload messages from DB
      const convData = await loadConversation(state.chat.activeId);
      const allMsgs = convData && convData.messages ? convData.messages : [];
      renderMessages(allMsgs);

      // Update injection info
      if (injInfo && injAnalysis) {
        if (injAnalysis.blocked) {
          injInfo.style.background = 'rgba(248,81,73,0.1)';
          injInfo.style.borderColor = 'rgba(248,81,73,0.3)';
          injInfo.innerHTML = `<svg class="ico" aria-hidden="true"><use href="#i-ban"/></svg> <strong>Injection erkannt!</strong> ${injAnalysis.matches.length} Treffer, ${injAnalysis.anomalies.length} Anomalien`;
        } else {
          injInfo.style.background = 'rgba(63,185,80,0.1)';
          injInfo.style.borderColor = 'rgba(63,185,80,0.3)';
          injInfo.innerHTML = `<svg class="ico" aria-hidden="true"><use href="#i-check"/></svg> <strong>Injection Guard:</strong> Sicher — ${injAnalysis.matches.length} Matches, ${injAnalysis.anomalies.length} Anomalien, ${injAnalysis.encoding_checks.length} Encoding-Checks`;
        }
        setTimeout(() => { injInfo.style.display = 'none'; }, 5000);
      }

      // Refresh conversation list
      await loadConvList();
      renderConvList();
    } catch (e) {
      renderMessages([{ role: 'assistant', content: '<svg class="ico" aria-hidden="true"><use href="#i-x"/></svg> Fehler: ' + e.message, created_at: new Date().toISOString() }]);
      if (injInfo) { injInfo.style.display = 'none'; }
    }

    // Re-enable input
    input.value = '';
    input.disabled = false;
    sendBtn.disabled = false;
    sendBtn.textContent = '<svg class="ico" aria-hidden="true"><use href="#i-arrow-right"/></svg>';
    input.focus();
  }

  /* ═══════════════════════════════════════════
     TAB: LIVE — Real-Time Stream
     ═══════════════════════════════════════════ */
  function initLive(el) {
    renderLive(el);
    // Start polling
    state.live.timer = setInterval(() => {
      refreshLive();
    }, 5000);
    refreshLive();
  }

  function cleanupLive() {
    if (state.live.timer) { clearInterval(state.live.timer); state.live.timer = null; }
  }

  async function refreshLive() {
    try {
      // Fetch real system metrics + PHP auth data in parallel
      const [auditRes, statsRes, telRes, systemRes, metricsRes] = await Promise.allSettled([
        authApi('get_audit_log', { limit: 30, offset: 0 }),
        authApi('get_audit_stats'),
        authApi('get_latest_telemetry'),
        systemApi('system'),
        systemApi('system/metrics'),
      ]);

      // --- Audit feed (PHP) ---
      if (auditRes.status === 'fulfilled' && auditRes.value.status === 'ok') {
        const newEntries = auditRes.value.log.filter(e => !state.live.entries.some(x => x.id === e.id));
        state.live.entries = auditRes.value.log;
        if (newEntries.length) {
          state.live.count += newEntries.length;
          renderLiveFeed();
        }
      }

      // --- Stats (PHP) ---
      if (statsRes.status === 'fulfilled' && statsRes.value.status === 'ok') {
        renderLiveStats(statsRes.value);
      }

      // --- Telemetry (PHP) ---
      if (telRes.status === 'fulfilled' && telRes.value.status === 'ok') {
        state.live.telemetry = telRes.value.latest;
        renderDeviceTelemetry(telRes.value.latest);
      }

      // --- Real system info ---
      if (systemRes.status === 'fulfilled' && systemRes.value) {
        state.live.system = systemRes.value;
      }

      // --- Real metrics ---
      if (metricsRes.status === 'fulfilled' && metricsRes.value) {
        state.live.metrics = metricsRes.value;
        renderRealMetrics(metricsRes.value);
        renderProcessInfo(metricsRes.value);
      }

    } catch (e) { /* keep old data */ }
  }

  function renderLive(el) {
    el.innerHTML = `
      <div class="dash-section">
        <div class="dash-section-title">
          <svg class="ico" aria-hidden="true"><use href="#i-broadcast"/></svg> Live‑Monitor
          <span class="badge badge-green" id="liveBadge"><svg class="ico" aria-hidden="true"><use href="#i-check"/></svg> Live</span>
          <span class="badge badge-blue" id="liveCount">0 Neu</span>
        </div>
        <div class="live-grid">
          <div class="live-panel live-panel-telemetry">
            <div class="live-panel-header"><svg class="ico" aria-hidden="true"><use href="#i-monitor"/></svg> Gerät</div>
            <div class="telemetry-grid" id="telemetryGrid">
              <div class="telemetry-item" id="telCpu"><span class="tel-label">CPU</span><span class="tel-value">—</span><span class="tel-bar"><span class="tel-bar-fill" style="width:0%"></span></span></div>
              <div class="telemetry-item" id="telMem"><span class="tel-label">RAM</span><span class="tel-value">—</span><span class="tel-bar"><span class="tel-bar-fill" style="width:0%"></span></span></div>
              <div class="telemetry-item" id="telDisk"><span class="tel-label">Disk</span><span class="tel-value">—</span><span class="tel-bar"><span class="tel-bar-fill" style="width:0%"></span></span></div>
              <div class="telemetry-item" id="telTemp"><span class="tel-label"><svg class="ico" aria-hidden="true"><use href="#i-chart"/></svg></span><span class="tel-value">—</span></div>
              <div class="telemetry-item" id="telHost"><span class="tel-label">Host</span><span class="tel-value mono">—</span></div>
              <div class="telemetry-item" id="telUptime"><span class="tel-label">Uptime</span><span class="tel-value">—</span></div>
              <div class="telemetry-item" id="telUpdated" style="grid-column:1/-1;text-align:center;border:none;padding:0;font-size:.75rem;color:var(--muted)"><span class="tel-value">Warte auf Telemetrie …</span></div>
            </div>
          </div>
          <div class="live-panel live-panel-audit">
            <div class="live-panel-header"><svg class="ico" aria-hidden="true"><use href="#i-clipboard"/></svg> Ereignis‑Feed <span class="badge badge-blue" id="liveFeedCount">0</span></div>
            <div class="live-feed" id="liveFeed"></div>
          </div>
          <div class="live-panel live-panel-stats">
            <div class="live-panel-header"><svg class="ico" aria-hidden="true"><use href="#i-chart"/></svg> Live‑Statistiken</div>
            <div class="live-stats" id="liveStats">
              <div class="live-stat"><span class="live-stat-label">Heute</span><span class="live-stat-value" id="liveTodayCount">0</span></div>
              <div class="live-stat"><span class="live-stat-label">Gesamt</span><span class="live-stat-value" id="liveTotalCount">0</span></div>
              <div class="live-stat"><span class="live-stat-label">Injection Blocks</span><span class="live-stat-value" id="liveBlockedCount">0</span></div>
              <div class="live-stat"><span class="live-stat-label">Letzte Akt.</span><span class="live-stat-value" id="liveLastUpdate">—</span></div>
            </div>
          </div>
        </div>
      </div>`;

    // Initial empty state
    const feed = document.getElementById('liveFeed');
    if (feed) feed.innerHTML = '<div class="empty-state">Warte auf Ereignisse …</div>';
  }

  function renderLiveFeed() {
    const feed = document.getElementById('liveFeed');
    const count = document.getElementById('liveFeedCount');
    const badge = document.getElementById('liveCount');
    if (!feed) return;

    if (!state.live.entries.length) {
      feed.innerHTML = '<div class="empty-state">Warte auf Ereignisse …</div>';
      return;
    }

    if (badge) badge.textContent = `+${state.live.count} Neu`;

    feed.innerHTML = state.live.entries.slice(0, 30).map(e => {
      const icon = e.event_type === 'auth' ? '<svg class="ico" aria-hidden="true"><use href="#i-lock"/></svg>' : e.event_type === 'llm' ? '<svg class="ico" aria-hidden="true"><use href="#i-bot"/></svg>' : e.event_type === 'wrapper' ? '<svg class="ico" aria-hidden="true"><use href="#i-link"/></svg>' : e.event_type === 'agent' ? '<svg class="ico" aria-hidden="true"><use href="#i-zap"/></svg>' : '<svg class="ico" aria-hidden="true"><use href="#i-plus"/></svg>';
      const statusIcon = e.status === 'success' ? '<svg class="ico" aria-hidden="true"><use href="#i-check"/></svg>' : e.status === 'blocked' ? '<svg class="ico" aria-hidden="true"><use href="#i-ban"/></svg>' : '<svg class="ico" aria-hidden="true"><use href="#i-x"/></svg>';
      return `<div class="live-entry ${e.status === 'blocked' ? 'live-entry-danger' : ''}"><span class="live-entry-time">${fmt(e.created_at)}</span><span class="live-entry-icon">${icon}</span><span class="live-entry-action">${esc(e.action)}</span><span class="live-entry-status">${statusIcon}</span></div>`;
    }).join('');

    if (count) count.textContent = state.live.entries.length;
  }

  function renderLiveStats(stats) {
    const today = document.getElementById('liveTodayCount');
    const total = document.getElementById('liveTotalCount');
    const blocked = document.getElementById('liveBlockedCount');
    const last = document.getElementById('liveLastUpdate');
    if (today) today.textContent = stats.stats?.today_count || 0;
    if (total) total.textContent = stats.stats?.total_count || 0;
    if (blocked) blocked.textContent = stats.stats?.injection_blocks || 0;
    if (last) last.textContent = new Date().toLocaleTimeString('de-DE');
  }

  function renderDeviceTelemetry(tel) {
    if (!tel) return;
    const d = tel.details ? (typeof tel.details === 'string' ? JSON.parse(tel.details) : tel.details) : {};
    const cpu = d.cpu || {};
    const mem = d.memory || {};
    const disk = d.disk || {};
    const hostname = d.hostname || '—';
    const uptime = d.uptime || '—';

    // CPU
    const cpuEl = document.getElementById('telCpu');
    if (cpuEl) {
      const pct = cpu.pct || cpu.load_1m ? Math.round((cpu.load_1m || 0) / (cpu.cores || 1) * 100) : 0;
      const val = pct ? `${pct}%` : `${cpu.load_1m || '?'} / ${cpu.cores || '?'} cores`;
      cpuEl.querySelector('.tel-value').textContent = val;
      const fill = cpuEl.querySelector('.tel-bar-fill');
      if (fill) { fill.style.width = Math.min(pct, 100) + '%'; fill.style.background = pct > 80 ? 'var(--red)' : pct > 50 ? 'var(--orange)' : 'var(--green)'; }
    }

    // Memory
    const memEl = document.getElementById('telMem');
    if (memEl && mem.total_bytes) {
      const pct = mem.pct || Math.round((mem.used_bytes / mem.total_bytes) * 100);
      const totalGb = (mem.total_bytes / 1e9).toFixed(1);
      const usedGb = (mem.used_bytes / 1e9).toFixed(1);
      memEl.querySelector('.tel-value').textContent = `${usedGb} GB / ${totalGb} GB  (${pct}%)`;
      const fill = memEl.querySelector('.tel-bar-fill');
      if (fill) { fill.style.width = Math.min(pct, 100) + '%'; fill.style.background = pct > 80 ? 'var(--red)' : pct > 50 ? 'var(--orange)' : 'var(--green)'; }
    }

    // Disk
    const diskEl = document.getElementById('telDisk');
    if (diskEl && disk.total_gb) {
      const pct = disk.pct || Math.round((disk.used_gb / disk.total_gb) * 100);
      diskEl.querySelector('.tel-value').textContent = `${disk.used_gb} GB / ${disk.total_gb} GB  (${pct}%)`;
      const fill = diskEl.querySelector('.tel-bar-fill');
      if (fill) { fill.style.width = Math.min(pct, 100) + '%'; fill.style.background = pct > 90 ? 'var(--red)' : pct > 70 ? 'var(--orange)' : 'var(--green)'; }
    }

    // Update the panel
    const hostEl = document.getElementById('telHost');
    if (hostEl) hostEl.querySelector('.tel-value').textContent = hostname;

    const uptEl = document.getElementById('telUptime');
    if (uptEl) uptEl.querySelector('.tel-value').textContent = typeof uptime === 'string' ? uptime.replace(/^.*up\s+/,'').replace(/,.*$/,'').trim() : '—';

    const updatedEl = document.getElementById('telUpdated');
    if (updatedEl) updatedEl.textContent = 'Letzte Akt.: ' + new Date().toLocaleTimeString('de-DE');
  }

  /* ═══ Real system metrics gauges ═══ */
  function renderRealMetrics(m) {
    if (!m) return;

    const osCpus = m.cpus || 1;

    // CPU gauge
    const gaugeCpu = document.getElementById('gaugeCpu');
    const gaugeCpuBar = document.getElementById('gaugeCpuBar');
    if (gaugeCpu) {
      const cpu = m.cpu || 0;
      gaugeCpu.textContent = cpu + '%';
      gaugeCpu.style.color = cpu > 80 ? 'var(--red)' : cpu > 60 ? 'var(--orange)' : 'var(--blue)';
      if (gaugeCpuBar) {
        gaugeCpuBar.style.width = cpu + '%';
        gaugeCpuBar.style.background = cpu > 80 ? 'var(--red)' : cpu > 60 ? 'var(--orange)' : 'var(--blue)';
      }
    }

    // Memory gauge
    const gaugeMem = document.getElementById('gaugeMem');
    const gaugeMemBar = document.getElementById('gaugeMemBar');
    if (gaugeMem && m.memory) {
      const pct = m.memory.percent || 0;
      gaugeMem.textContent = pct + '%';
      gaugeMem.style.color = pct > 80 ? 'var(--red)' : pct > 60 ? 'var(--orange)' : 'var(--green)';
      if (gaugeMemBar) {
        gaugeMemBar.style.width = pct + '%';
        gaugeMemBar.style.background = pct > 80 ? 'var(--red)' : pct > 60 ? 'var(--orange)' : 'var(--green)';
      }
    }

    // Load gauge
    const gaugeLoad = document.getElementById('gaugeLoad');
    const gaugeLoadBar = document.getElementById('gaugeLoadBar');
    if (gaugeLoad && m.loadavg) {
      const load = m.loadavg[0] || 0;
      const loadPct = Math.min(Math.round((load / osCpus) * 100), 100);
      gaugeLoad.textContent = load.toFixed(2);
      gaugeLoad.style.color = loadPct > 80 ? 'var(--red)' : loadPct > 60 ? 'var(--orange)' : 'var(--yellow)';
      if (gaugeLoadBar) {
        gaugeLoadBar.style.width = loadPct + '%';
        gaugeLoadBar.style.background = loadPct > 80 ? 'var(--red)' : loadPct > 60 ? 'var(--orange)' : 'var(--yellow)';
      }
    }

    // Heap gauge
    const gaugeProcess = document.getElementById('gaugeProcess');
    const gaugeHeapBar = document.getElementById('gaugeHeapBar');
    if (gaugeProcess && m.process) {
      const heapPct = m.process.heapTotal > 0
        ? Math.round((m.process.heapUsed / m.process.heapTotal) * 100)
        : 0;
      gaugeProcess.textContent = heapPct + '%';
      gaugeProcess.style.color = heapPct > 80 ? 'var(--red)' : heapPct > 60 ? 'var(--orange)' : 'var(--purple)';
      if (gaugeHeapBar) {
        gaugeHeapBar.style.width = heapPct + '%';
        gaugeHeapBar.style.background = heapPct > 80 ? 'var(--red)' : heapPct > 60 ? 'var(--orange)' : 'var(--purple)';
      }
    }

    // Updating the live event feed
    const feed = document.getElementById('liveEventFeed');
    if (feed) {
      const entry = document.createElement('div');
      entry.className = 'live-entry fade-in-entry';
      const now = new Date().toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      const memFree = m.memory ? m.memory.freePercent + '%' : '—';
      entry.innerHTML = '<span class="live-entry-time">' + now + '</span>' +
        '<span class="live-entry-icon"><svg class="ico" aria-hidden="true"><use href="#i-chart"/></svg></span>' +
        '<span class="live-entry-action">CPU ' + (m.cpu || 0) + '% · Mem ' + (m.memory ? m.memory.percent : '?') + '% · Free ' + memFree + '</span>';
      feed.insertBefore(entry, feed.firstChild);
      while (feed.children.length > 50) {
        feed.removeChild(feed.lastChild);
      }
    }
  }

  /* ═══ Process Info ═══ */
  function renderProcessInfo(m) {
    if (!m) return;

    const pid = document.getElementById('procPid');
    const rss = document.getElementById('procRss');
    const heap = document.getElementById('procHeap');
    const cores = document.getElementById('procCores');

    if (pid && m.process) pid.textContent = m.process.pid || '—';
    if (rss && m.process) rss.textContent = fmtBytes(m.process.memoryRss);
    if (heap && m.process) {
      heap.textContent = fmtBytes(m.process.heapUsed) + ' / ' + fmtBytes(m.process.heapTotal);
    }
    if (cores) cores.textContent = m.cpus || '—';

    // Heartbeat & boss
    const liveHb = document.getElementById('liveHeartbeat');
    const liveBoss = document.getElementById('liveBoss');
    const liveAgents = document.getElementById('liveAgents');
    const liveUptime = document.getElementById('liveUptime');

    if (liveUptime && m.process) liveUptime.textContent = fmtUptime(m.process.uptime);
    if (liveUptime && !m.process && m.uptime) liveUptime.textContent = fmtUptime(m.uptime);

    // Fetch heartbeat & boss async
    Promise.allSettled([
      systemApi('heartbeat'),
      systemApi('boss'),
      systemApi('agents/running'),
    ]).then(([hb, boss, agents]) => {
      if (liveHb && hb.value) {
        liveHb.textContent = hb.value.running ? '<svg class="ico" aria-hidden="true"><use href="#i-heartbeat"/></svg> Tick #' + (hb.value.tick || 0) : '<svg class="ico" aria-hidden="true"><use href="#i-heart"/></svg> Stopped';
      }
      if (liveBoss && boss.value) {
        liveBoss.textContent = boss.value.running ? '<svg class="ico" aria-hidden="true"><use href="#i-refresh"/></svg> Cycle #' + (boss.value.cycles || 0) : '⏹ Stopped';
      }
      if (liveAgents && agents.value) {
        liveAgents.textContent = agents.value.running ? agents.value.running.length : 0;
      }
    });
  }

  /* ═══════════════════════════════════════════
     TAB: ACCOUNT
     ═══════════════════════════════════════════ */
  function initAccount(el) { renderAccount(el); }

  function renderAccount(el) {
    const u = state.user;
    if (!u) { el.innerHTML = '<div class="dash-loading"><svg class="ico" aria-hidden="true"><use href="#i-user"/></svg> Lade …</div>'; return; }

    el.innerHTML = `
      <div class="dash-section">
        <div class="dash-section-title"><svg class="ico" aria-hidden="true"><use href="#i-user"/></svg> Konto</div>
        <div class="account-info">
          <div class="account-row"><span class="account-label">Name</span><span class="account-value">${esc(u.name || '—')}</span></div>
          <div class="account-row"><span class="account-label">E-Mail</span><span class="account-value">${esc(u.email)}</span></div>
          <div class="account-row"><span class="account-label">Mitglied seit</span><span class="account-value">${u.created_at ? fmt(u.created_at) : '—'}</span></div>
        </div>
        <div class="account-actions">
          <button id="exportBtn" class="auth-btn" style="max-width:200px"><svg class="ico" aria-hidden="true"><use href="#i-download"/></svg> Daten exportieren</button>
          <button id="deleteBtn" class="auth-btn" style="max-width:200px;background:var(--red);background-image:none"><svg class="ico" aria-hidden="true"><use href="#i-x"/></svg> Konto löschen</button>
        </div>
      </div>`;

    document.getElementById('exportBtn').addEventListener('click', exportData);
    document.getElementById('deleteBtn').addEventListener('click', () => showDeleteModal());
  }

  async function exportData() {
    const btn = document.getElementById('exportBtn');
    btn.disabled = true;
    btn.textContent = '⏳ Exportiere …';
    try {
      const data = await authApi('export_data');
      if (data.status === 'ok') {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `mona-expert-export-${fmtDate(new Date())}.json`;
        a.click();
        URL.revokeObjectURL(url);
        toast('<svg class="ico" aria-hidden="true"><use href="#i-download"/></svg> Daten exportiert', 'success');
      } else {
        toast('<svg class="ico" aria-hidden="true"><use href="#i-x"/></svg> Export fehlgeschlagen: ' + (data.message || ''), 'error');
      }
    } catch (e) {
      toast('<svg class="ico" aria-hidden="true"><use href="#i-x"/></svg> Fehler beim Export', 'error');
    }
    btn.disabled = false;
    btn.textContent = '<svg class="ico" aria-hidden="true"><use href="#i-download"/></svg> Daten exportieren';
  }

  function showDeleteModal() {
    document.getElementById('modalOverlay').style.display = 'flex';
    document.getElementById('modalConfirmText').textContent = 'Möchtest du dein Konto wirklich löschen? Alle Daten werden unwiderruflich entfernt.';
    document.getElementById('modalConfirmBtn').onclick = async () => {
      document.getElementById('modalOverlay').style.display = 'none';
      const data = await authApi('delete_account');
      if (data.status === 'ok') {
        toast('<svg class="ico" aria-hidden="true"><use href="#i-heart"/></svg> Konto gelöscht', 'success');
        setTimeout(() => logout(), 1500);
      } else {
        toast('<svg class="ico" aria-hidden="true"><use href="#i-x"/></svg> Löschen fehlgeschlagen: ' + (data.message || ''), 'error');
      }
    };
    document.getElementById('modalCancelBtn').onclick = () => {
      document.getElementById('modalOverlay').style.display = 'none';
    };
  }

  /* ─── TAB: CONNECT — Wrapper-Verbindungsanleitung ─── */
  function renderConnect(el) {
    el.innerHTML = `
      <div class="dash-section">
        <div class="dash-section-title"><svg class="ico" aria-hidden="true"><use href="#i-plug"/></svg> Wrapper verbinden</div>
        <div class="connect-flow">
          <div class="connect-step">
            <div class="connect-step-num">1</div>
            <div class="connect-step-body">
              <div class="connect-step-title">Wrapper installieren</div>
              <div class="connect-step-desc">Lade den aktuellen Wrapper aus dem Repository und installiere die Abhängigkeiten.</div>
              <pre class="connect-code"><code>git clone https://github.com/mona-experts/mona-wrapper.git
cd mona-wrapper
npm install</code></pre>
            </div>
          </div>
          <div class="connect-step">
            <div class="connect-step-num">2</div>
            <div class="connect-step-body">
              <div class="connect-step-title">API-Key generieren</div>
              <div class="connect-step-desc">Erstelle einen neuen API-Key für den Wrapper unter <strong>Konto → API-Keys</strong> oder via CLI:</div>
              <pre class="connect-code"><code>npm run generate-key</code></pre>
            </div>
          </div>
          <div class="connect-step">
            <div class="connect-step-num">3</div>
            <div class="connect-step-body">
              <div class="connect-step-title">Wrapper konfigurieren</div>
              <div class="connect-step-desc">Setze die Umgebungsvariablen in der <code>.env</code>-Datei:</div>
              <pre class="connect-code"><code>MONA_API_URL=http://localhost:4188
MONA_API_KEY=dein_generierter_key
MONA_WRAPPER_ID=mein-wrapper-1</code></pre>
            </div>
          </div>
          <div class="connect-step">
            <div class="connect-step-num">4</div>
            <div class="connect-step-body">
              <div class="connect-step-title">Wrapper starten</div>
              <div class="connect-step-desc">Starte den Wrapper und prüfe die Verbindung:</div>
              <pre class="connect-code"><code>npm start
# Sollte „Verbunden mit mona.expert" anzeigen</code></pre>
            </div>
          </div>
        </div>
      </div>
      <div class="dash-section">
        <div class="dash-section-title"><svg class="ico" aria-hidden="true"><use href="#i-broadcast"/></svg> Status</div>
        <div class="wrapper-card">
          <div class="wrapper-status online"></div>
          <div class="wrapper-info">
            <div class="wrapper-name">Lokaler Server</div>
            <div class="wrapper-id">PID ${'N/A'} · Port 4188</div>
          </div>
          <span class="badge badge-green">Online</span>
        </div>
      </div>
    `;
  }

  /* ─── Start ─── */
  document.addEventListener('DOMContentLoaded', init);
  return { switchTab, logout };
})();
