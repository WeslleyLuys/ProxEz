/* ─── SIP Proxy Admin — Frontend ──────────────────────────────────── */

const API = '';
let currentPage = 'dashboard';
let statusInterval = null;
let captureInterval = null;
let captureLastIndex = 0;

// ─── Init ────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Nav
  document.querySelectorAll('.nav-item').forEach(el => {
    el.addEventListener('click', e => {
      e.preventDefault();
      navigateTo(el.dataset.page);
    });
  });

  navigateTo('dashboard');
  startStatusPolling();
});

function navigateTo(page) {
  if (f2bInterval) { clearInterval(f2bInterval); f2bInterval = null; }
  if (captureInterval) { clearInterval(captureInterval); captureInterval = null; }
  if (monitorInterval) { clearInterval(monitorInterval); monitorInterval = null; }
  currentPage = page;
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.page === page);
  });

  const titles = {
    'dashboard':    'Dashboard',
    'config-geral': 'Configurações Gerais',
    'api-backend':  'API de Roteamento',
    'rotas':        'Rotas Estáticas',
    'certificados': 'Certificados TLS',
    'cache':        'Cache de Roteamento',
    'routing-cache': 'Registro de Ramais',
    'firewall':     'Firewall / Fail2Ban',
    'monitor':      'Monitor SIP — Tempo Real',
    'logs':         'Logs do Kamailio',
    'editor':       'Editor de Configuração',
    'backups':      'Backups',
    'webphone':     'WebPhone SIP',
    'lxd-servers':  'Servidores LXD',
    'sip-capture':  'SIP Capture — Containers',
    'docs':         'Documentação',
  };
  document.getElementById('page-title').textContent = titles[page] || page;
  renderPage(page);
}

function refreshPage() { navigateTo(currentPage); }

// ─── Status Polling ──────────────────────────────────────────────────
function startStatusPolling() {
  loadStatus();
  clearInterval(statusInterval);
  statusInterval = setInterval(loadStatus, 10000);
}

async function loadStatus() {
  try {
    const data = await apiFetch('/api/status');
    const dot  = document.getElementById('status-dot');
    const text = document.getElementById('status-text');
    if (data.running) {
      dot.className  = 'status-dot running';
      text.textContent = 'Rodando';
    } else {
      dot.className  = 'status-dot stopped';
      text.textContent = 'Parado';
    }
    return data;
  } catch {
    document.getElementById('status-dot').className = 'status-dot';
    document.getElementById('status-text').textContent = 'Erro';
    return null;
  }
}

// ─── API Helper ───────────────────────────────────────────────────────
async function apiFetch(path, opts = {}) {
  const r = await fetch(API + path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  if (r.status === 403) {
    throw new Error('Sem permissão para acessar este recurso');
  }
  if (!r.ok) {
    const err = await r.json().catch(() => ({ error: r.statusText }));
    throw new Error(err.error || r.statusText);
  }
  return r.json();
}

async function apiPost(path, body) {
  return apiFetch(path, { method: 'POST', body: JSON.stringify(body) });
}

// ─── Pages ──────────────────────────────────────────────────────────
async function renderPage(page) {
  const el = document.getElementById('content');
  el.innerHTML = `<div class="loading-state"><div class="loader"></div><div style="margin-top:12px">Carregando...</div></div>`;

  switch (page) {
    case 'dashboard':    await renderDashboard(el); break;
    case 'config-geral': await renderConfigGeral(el); break;
    case 'api-backend':  await renderApiBackend(el); break;
    case 'rotas':        await renderRotas(el); break;
    case 'certificados': await renderCertificados(el); break;
    case 'cache':        await renderCache(el); break;
    case 'routing-cache': await renderRoutingCache(el); break;
    case 'firewall':     await renderFirewall(el); break;
    case 'monitor':      await renderMonitor(el); break;
    case 'logs':         await renderLogs(el); break;
    case 'editor':       await renderEditor(el); break;
    case 'backups':      await renderBackups(el); break;
    case 'webphone':     renderWebPhone(el); break;
    case 'lxd-servers': await renderLxdServers(el); break;
    case 'sip-capture': await renderSipCapture(el); break;
    case 'docs': await renderDocs(el); break;
    default: el.innerHTML = '<div class="empty-state"><div class="empty-state-icon">?</div><div>Página não encontrada</div></div>';
  }
}

// ── DASHBOARD ────────────────────────────────────────────────────────
async function renderDashboard(el) {
  const data = await loadStatus();
  if (!data) {
    el.innerHTML = '<div class="alert alert-error">⚠ Não foi possível conectar ao backend.</div>';
    return;
  }

  const runBadge = data.running
    ? '<span class="badge badge-green">● RODANDO</span>'
    : '<span class="badge badge-red">● PARADO</span>';

  el.innerHTML = `
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Status</div>
        <div class="stat-value ${data.running ? 'green' : 'red'}">${data.running ? 'OK' : 'STOP'}</div>
        <div class="stat-sub">${runBadge}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Processos</div>
        <div class="stat-value blue">${data.pids}</div>
        <div class="stat-sub">workers ativos</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Memória</div>
        <div class="stat-value">${data.memory_mb}</div>
        <div class="stat-sub">MB (RSS)</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Cache Rotas</div>
        <div class="stat-value blue">${data.cache_entries}</div>
        <div class="stat-sub">entradas htable</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Transações SIP</div>
        <div class="stat-value">${data.current_transactions}</div>
        <div class="stat-sub">ativas agora</div>
      </div>
    </div>

    <div class="card">
      <div class="card-title">ℹ Informações do Servidor</div>
      <div class="form-row">
        <div>
          <div class="form-label">Versão Kamailio</div>
          <div class="version-badge">${data.version || 'N/A'}</div>
        </div>
        <div>
          <div class="form-label">Ativo desde</div>
          <div style="color:var(--text2);font-size:13px">${data.uptime || 'N/A'}</div>
        </div>
      </div>
    </div>

    ${(!window.userPermissions || window.userPermissions.includes('*')) ? `<div class="card">
      <div class="card-title">⚡ Ações Rápidas</div>
      <div class="btn-group">
        <button class="btn btn-outline" onclick="navigateTo('config-geral')">⚙ Config Geral</button>
        <button class="btn btn-outline" onclick="navigateTo('api-backend')">⇄ API Backend</button>
        <button class="btn btn-outline" onclick="navigateTo('certificados')">🔒 Certificados</button>
        <button class="btn btn-outline" onclick="navigateTo('logs')">≡ Ver Logs</button>
        <button class="btn btn-success" onclick="reloadKamailio()">↺ Reload Config</button>
      </div>
    </div>` : ''}
  `;
}

// ── CONFIG GERAL ─────────────────────────────────────────────────────
async function renderConfigGeral(el) {
  let cfg = {};
  try {
    cfg = await apiFetch('/api/config/general');
  } catch(e) {
    el.innerHTML = `<div class="alert alert-error">Erro: ${e.message}</div>`;
    return;
  }

  const listens = Array.isArray(cfg.listen) ? cfg.listen.join('\n') : (cfg.listen || '');

  el.innerHTML = `
    <div class="card">
      <div class="card-title">⚙ Parâmetros Gerais</div>
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">Debug Level</label>
          <select id="cfg-debug">
            ${[0,1,2,3,4,5].map(v => `<option value="${v}" ${cfg.debug==v?'selected':''}>${v} ${v==2?'(padrão)':v==5?'(máximo)':''}</option>`).join('')}
          </select>
          <div class="form-hint">0=mínimo, 5=máximo</div>
        </div>
        <div class="form-group">
          <label class="form-label">Children (workers)</label>
          <input type="number" id="cfg-children" value="${cfg.children || 4}" min="1" max="64">
          <div class="form-hint">Processos worker do Kamailio</div>
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">Log Facility</label>
          <select id="cfg-log_facility">
            ${['LOG_LOCAL0','LOG_LOCAL1','LOG_LOCAL2','LOG_LOCAL3','LOG_DAEMON','LOG_USER'].map(v =>
              `<option value="${v}" ${cfg.log_facility==v?'selected':''}>${v}</option>`
            ).join('')}
          </select>
        </div>
        <div class="form-group">
          <label class="form-label">Log StdError</label>
          <select id="cfg-log_stderror">
            <option value="no" ${cfg.log_stderror=='no'?'selected':''}>no</option>
            <option value="yes" ${cfg.log_stderror=='yes'?'selected':''}>yes</option>
          </select>
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">Porta SIP</label>
          <input type="number" id="cfg-port" value="${cfg.port || 5060}">
        </div>
        <div class="form-group">
          <label class="form-label">Auto Aliases</label>
          <select id="cfg-auto_aliases">
            <option value="no" ${cfg.auto_aliases=='no'?'selected':''}>no</option>
            <option value="yes" ${cfg.auto_aliases=='yes'?'selected':''}>yes</option>
          </select>
        </div>
      </div>
      <div class="form-group">
        <label class="form-label">Listen Addresses (uma por linha)</label>
        <textarea id="cfg-listen" rows="3" placeholder="udp:{{PROXY_IP}}:5060&#10;tcp:{{PROXY_IP}}:5060">${listens}</textarea>
        <div class="form-hint">Formato: protocolo:ip:porta</div>
      </div>
      <div class="btn-group">
        <button class="btn btn-primary" onclick="saveConfigGeral()">💾 Salvar</button>
        <button class="btn btn-success" onclick="reloadKamailio()">↺ Aplicar (Reload)</button>
      </div>
    </div>
  `;
}

async function saveConfigGeral() {
  const data = {
    debug:        document.getElementById('cfg-debug').value,
    children:     document.getElementById('cfg-children').value,
    log_facility: document.getElementById('cfg-log_facility').value,
    log_stderror: document.getElementById('cfg-log_stderror').value,
    port:         document.getElementById('cfg-port').value,
    auto_aliases: document.getElementById('cfg-auto_aliases').value,
    listen:       document.getElementById('cfg-listen').value,
  };
  try {
    await apiPost('/api/config/general', data);
    toast('Configurações salvas!', 'success');
  } catch(e) {
    toast('Erro: ' + e.message, 'error');
  }
}

// ── API BACKEND ──────────────────────────────────────────────────────
async function renderApiBackend(el) {
  let cfg = {};
  try {
    cfg = await apiFetch('/api/config/api-backend');
  } catch(e) {
    el.innerHTML = `<div class="alert alert-error">Erro: ${e.message}</div>`;
    return;
  }

  el.innerHTML = `
    <div class="card">
      <div class="card-title">⇄ Conexão com API de Roteamento</div>
      <div class="alert alert-info">
        ℹ O Kamailio consulta esta API para descobrir qual container Asterisk deve receber cada chamada ou registro.
      </div>
      <div class="form-group">
        <label class="form-label">URL da API</label>
        <input type="url" id="api-url" value="${cfg.api_url || ''}" placeholder="http://{{API_HOST}}:8886">
        <div class="form-hint">Endpoint base — o Kamailio chamará POST {url}/asterisk/proxy</div>
      </div>
      <div class="form-group">
        <label class="form-label">Timeout de Conexão (ms)</label>
        <input type="number" id="api-timeout" value="${cfg.connection_timeout || 2000}" min="500" max="30000" step="500">
        <div class="form-hint">Tempo máximo de espera por resposta da API</div>
      </div>
      <div class="btn-group">
        <button class="btn btn-primary" onclick="saveApiBackend()">💾 Salvar</button>
        <button class="btn btn-outline" onclick="testApiConnection()">⚡ Testar Conexão</button>
      </div>
      <div id="api-test-result" style="margin-top:12px"></div>
    </div>

    <div class="card">
      <div class="card-title">📋 Endpoint Esperado</div>
      <div class="alert alert-warning">
        ⚠ A API deve implementar: <strong>POST /asterisk/proxy</strong><br><br>
        <strong>Request body:</strong><br>
        <code style="font-family:monospace">{"username": "ramal_ou_numero"}</code><br><br>
        <strong>Response (200):</strong><br>
        <code style="font-family:monospace">{{CONTAINER_IP}}</code> <em>(IP do container Asterisk)</em>
      </div>
    </div>
  `;
}

async function saveApiBackend() {
  try {
    await apiPost('/api/config/api-backend', {
      api_url:            document.getElementById('api-url').value,
      connection_timeout: document.getElementById('api-timeout').value,
    });
    toast('API configurada!', 'success');
  } catch(e) {
    toast('Erro: ' + e.message, 'error');
  }
}

async function testApiConnection() {
  const url = document.getElementById('api-url').value;
  const el  = document.getElementById('api-test-result');
  el.innerHTML = '<div class="loader"></div> Testando...';
  try {
    const r = await apiPost('/api/config/api-backend/test', { url });
    if (r.reachable) {
      el.innerHTML = `<div class="alert alert-success">✓ API acessível! HTTP ${r.http_code} em ${r.url}</div>`;
    } else {
      el.innerHTML = `<div class="alert alert-error">✗ API inacessível (HTTP ${r.http_code || 'timeout'})</div>`;
    }
  } catch(e) {
    el.innerHTML = `<div class="alert alert-error">Erro: ${e.message}</div>`;
  }
}

// ── ROTAS ────────────────────────────────────────────────────────────
let routesList = [];

async function renderRotas(el) {
  let data = { routes: [] };
  try {
    data = await apiFetch('/api/routes');
    routesList = data.routes || [];
  } catch {}

  await loadRouteBlocks();

  el.innerHTML = `
    <div class="card">
      <div class="card-title">&#10148; Blocos de Roteamento (kamailio.cfg)</div>
      <div class="alert alert-info">
        Visualize e edite os blocos de roteamento do Kamailio diretamente.
        Cada bloco controla uma parte do fluxo SIP (REGISTER, INVITE, etc.).
        Um backup automático é criado antes de cada alteração.
      </div>
      <div id="route-blocks-container">
        <div class="loading-state"><div class="loader"></div></div>
      </div>
    </div>

    <div class="card" style="margin-top:24px">
      <div class="card-title">&#8644; Rotas Estáticas</div>
      <div class="alert alert-info">
        As rotas estáticas são injetadas diretamente no cache htable do Kamailio.
        Útil para ramais ou números que não precisam consultar a API a cada chamada.
      </div>
      <div id="routes-list"></div>
      <button class="btn btn-outline" onclick="addRouteRow()" style="margin-top:12px">+ Adicionar Rota</button>
      <div class="btn-group" style="margin-top:16px">
        <button class="btn btn-primary" onclick="saveRoutes()">Salvar e Injetar no Cache</button>
      </div>
    </div>
  `;

  renderRouteBlocks();
  renderRoutesList();
}

function renderRoutesList() {
  const el = document.getElementById('routes-list');
  if (routesList.length === 0) {
    el.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">↔</div>
        <div class="empty-state-text">Nenhuma rota estática configurada</div>
      </div>`;
    return;
  }

  el.innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr 100px auto;gap:8px;padding:8px 0;border-bottom:1px solid var(--border)">
      <div class="form-label" style="margin:0">Username / Ramal</div>
      <div class="form-label" style="margin:0">IP Destino</div>
      <div class="form-label" style="margin:0">TTL (s)</div>
      <div></div>
    </div>
    ${routesList.map((r, i) => `
      <div class="route-item">
        <input type="text" value="${r.username || ''}" onchange="routesList[${i}].username=this.value" placeholder="ex: 1001 ou 0048...">
        <input type="text" value="${r.destination || ''}" onchange="routesList[${i}].destination=this.value" placeholder="ex: {{CONTAINER_IP}}">
        <input type="number" value="${r.ttl || 300}" onchange="routesList[${i}].ttl=parseInt(this.value)" min="60">
        <button class="btn btn-sm btn-danger" onclick="removeRoute(${i})">✕</button>
      </div>
    `).join('')}
  `;
}

function addRouteRow() {
  routesList.push({ username: '', destination: '', ttl: 300 });
  renderRoutesList();
}

function removeRoute(i) {
  routesList.splice(i, 1);
  renderRoutesList();
}

async function saveRoutes() {
  const valid = routesList.filter(r => r.username && r.destination);
  try {
    const r = await apiPost('/api/routes', { routes: valid });
    const injected = r.injected || [];
    const ok = injected.filter(x => x.ok).length;
    toast(`${valid.length} rotas salvas, ${ok} injetadas no cache.`, 'success');
  } catch(e) {
    toast('Erro: ' + e.message, 'error');
  }
}

// ── CERTIFICADOS ─────────────────────────────────────────────────────
async function renderCertificados(el) {
  let cert = {};
  try {
    cert = await apiFetch('/api/cert');
  } catch {}

  el.innerHTML = `
    <div class="card">
      <div class="card-title">🔒 Status do Certificado TLS</div>
      ${cert.cert_exists ? `
        <div class="cert-status">
          <span class="cert-icon">🔒</span>
          <div>
            <div style="color:var(--green);font-weight:600">Certificado instalado</div>
            <div style="font-size:12px;color:var(--text2);margin-top:2px">
              ${cert.cert_path}<br>
              ${cert.cert_info ? cert.cert_info.replace(/\n/g,'<br>') : ''}
            </div>
          </div>
        </div>
      ` : `
        <div class="cert-status">
          <span class="cert-icon">🔓</span>
          <div>
            <div style="color:var(--yellow);font-weight:600">Nenhum certificado instalado</div>
            <div style="font-size:12px;color:var(--text2)">Adicione um certificado abaixo para ativar TLS/WSS</div>
          </div>
        </div>
      `}
    </div>

    <div class="card">
      <div class="card-title">⚡ Gerar Certificado Auto-assinado</div>
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">Domínio</label>
          <input type="text" id="cert-domain" value="{{DOMAIN}}" placeholder="seudominio.com.br">
        </div>
        <div class="form-group">
          <label class="form-label">Validade (dias)</label>
          <input type="number" id="cert-days" value="3650" min="30">
        </div>
      </div>
      <button class="btn btn-primary" onclick="generateCert()">⚡ Gerar Certificado</button>
      <div id="cert-gen-result" style="margin-top:12px"></div>
    </div>

    <div class="card">
      <div class="card-title">📤 Fazer Upload de Certificado</div>

      <div class="tabs">
        <div class="tab active" onclick="switchTab(this,'cert-tabs','tab-upload')">Upload de Arquivo</div>
        <div class="tab" onclick="switchTab(this,'cert-tabs','tab-paste')">Colar Conteúdo</div>
      </div>
      <div id="cert-tabs">
        <div class="tab-pane active" id="tab-upload">
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">Certificado (.crt / .pem)</label>
              <div class="upload-area" onclick="document.getElementById('cert-file').click()">
                <input type="file" id="cert-file" accept=".crt,.pem,.cer">
                <div style="font-size:24px;margin-bottom:8px">📄</div>
                <div>Clique para selecionar o certificado</div>
                <div style="font-size:11px;color:var(--text3);margin-top:4px">.crt, .pem, .cer</div>
              </div>
              <div id="cert-file-name" style="font-size:12px;color:var(--text2);margin-top:6px"></div>
            </div>
            <div class="form-group">
              <label class="form-label">Chave Privada (.key)</label>
              <div class="upload-area" onclick="document.getElementById('key-file').click()">
                <input type="file" id="key-file" accept=".key,.pem">
                <div style="font-size:24px;margin-bottom:8px">🔑</div>
                <div>Clique para selecionar a chave</div>
                <div style="font-size:11px;color:var(--text3);margin-top:4px">.key, .pem</div>
              </div>
              <div id="key-file-name" style="font-size:12px;color:var(--text2);margin-top:6px"></div>
            </div>
          </div>
          <button class="btn btn-primary" onclick="uploadCertFiles()">📤 Fazer Upload</button>
        </div>
        <div class="tab-pane" id="tab-paste">
          <div class="form-group">
            <label class="form-label">Conteúdo do Certificado (PEM)</label>
            <textarea id="cert-text" rows="6" placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"></textarea>
          </div>
          <div class="form-group">
            <label class="form-label">Conteúdo da Chave Privada (PEM)</label>
            <textarea id="key-text" rows="6" placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"></textarea>
          </div>
          <button class="btn btn-primary" onclick="pasteCert()">💾 Salvar</button>
        </div>
      </div>
      <div id="cert-upload-result" style="margin-top:12px"></div>
    </div>
  `;

  // File input labels
  document.getElementById('cert-file').addEventListener('change', function() {
    document.getElementById('cert-file-name').textContent = this.files[0]?.name || '';
  });
  document.getElementById('key-file').addEventListener('change', function() {
    document.getElementById('key-file-name').textContent = this.files[0]?.name || '';
  });
}

function switchTab(tabEl, containerId, paneId) {
  const container = document.getElementById(containerId);
  document.querySelectorAll(`[id="${containerId}"] ~ .tabs .tab`).forEach(t => t.classList.remove('active'));
  container.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  tabEl.classList.add('active');
  document.getElementById(paneId).classList.add('active');
  // Fix: tabs are siblings
  const tabsEl = tabEl.closest('.tabs');
  tabsEl.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  tabEl.classList.add('active');
}

async function generateCert() {
  const el = document.getElementById('cert-gen-result');
  el.innerHTML = '<div class="loader"></div> Gerando (pode demorar alguns segundos)...';
  try {
    const r = await apiPost('/api/cert/generate', {
      domain: document.getElementById('cert-domain').value,
      days:   parseInt(document.getElementById('cert-days').value),
    });
    el.innerHTML = `<div class="alert alert-success">✓ Certificado gerado!<br>Cert: ${r.cert}<br>Key: ${r.key}</div>`;
    toast('Certificado gerado com sucesso!', 'success');
  } catch(e) {
    el.innerHTML = `<div class="alert alert-error">✗ Erro: ${e.message}</div>`;
  }
}

async function uploadCertFiles() {
  const certFile = document.getElementById('cert-file').files[0];
  const keyFile  = document.getElementById('key-file').files[0];
  const el = document.getElementById('cert-upload-result');

  if (!certFile && !keyFile) {
    toast('Selecione ao menos um arquivo.', 'warning');
    return;
  }

  const form = new FormData();
  if (certFile) form.append('cert', certFile);
  if (keyFile)  form.append('key', keyFile);

  try {
    const r = await fetch(API + '/api/cert', { method: 'POST', body: form });
    const data = await r.json();
    if (data.ok) {
      el.innerHTML = `<div class="alert alert-success">✓ Salvo: ${data.saved.join(', ')}</div>`;
      toast('Certificado salvo!', 'success');
    } else {
      el.innerHTML = `<div class="alert alert-error">✗ ${data.error}</div>`;
    }
  } catch(e) {
    el.innerHTML = `<div class="alert alert-error">Erro: ${e.message}</div>`;
  }
}

async function pasteCert() {
  const certText = document.getElementById('cert-text').value;
  const keyText  = document.getElementById('key-text').value;
  const el = document.getElementById('cert-upload-result');

  const form = new FormData();
  if (certText) form.append('cert_text', certText);
  if (keyText)  form.append('key_text', keyText);

  try {
    const r = await fetch(API + '/api/cert', { method: 'POST', body: form });
    const data = await r.json();
    if (data.ok) {
      el.innerHTML = `<div class="alert alert-success">✓ Salvo: ${data.saved.join(', ')}</div>`;
      toast('Certificado salvo!', 'success');
    } else {
      el.innerHTML = `<div class="alert alert-error">✗ ${data.error}</div>`;
    }
  } catch(e) {
    el.innerHTML = `<div class="alert alert-error">Erro: ${e.message}</div>`;
  }
}

// ── CACHE ────────────────────────────────────────────────────────────
async function renderCache(el) {
  let data = { entries: [], raw: '' };
  try {
    data = await apiFetch('/api/cache');
  } catch {}

  el.innerHTML = `
    <div class="card">
      <div class="card-title">⚡ Cache de Roteamento (htable)</div>
      <div class="alert alert-info">
        ℹ O cache armazena mapeamentos username→IP por 5 minutos (300s TTL) para evitar consultas repetidas à API.
      </div>
      <div class="btn-group" style="margin-bottom:16px">
        <button class="btn btn-outline" onclick="navigateTo('cache')">↺ Recarregar</button>
        <button class="btn btn-danger" onclick="confirmFlushCache()">🗑 Limpar Cache</button>
      </div>
      ${data.entries.length > 0 ? `
        <div class="table-wrap">
          <table>
            <thead><tr><th>#</th><th>Entrada</th></tr></thead>
            <tbody>
              ${data.entries.map((e, i) => `<tr><td>${i+1}</td><td style="font-family:monospace">${escHtml(e)}</td></tr>`).join('')}
            </tbody>
          </table>
        </div>
        <div style="margin-top:8px;color:var(--text3);font-size:12px">${data.entries.length} entrada(s) em cache</div>
      ` : `
        <div class="empty-state">
          <div class="empty-state-icon">⚡</div>
          <div class="empty-state-text">Cache vazio</div>
        </div>
      `}
    </div>
  `;
}

function confirmFlushCache() {
  showModal('Limpar Cache', 'Isso removerá todas as entradas do htable. O Kamailio voltará a consultar a API para todas as chamadas.', async () => {
    try {
      await apiPost('/api/cache/flush', {});
      toast('Cache limpo!', 'success');
      navigateTo('cache');
    } catch(e) {
      toast('Erro: ' + e.message, 'error');
    }
  });
}

// ── LOGS ─────────────────────────────────────────────────────────────
async function renderLogs(el) {
  el.innerHTML = `
    <div class="card">
      <div class="card-title">≡ Logs do Kamailio</div>
      <div style="display:flex;gap:12px;align-items:center;margin-bottom:16px;flex-wrap:wrap">
        <div>
          <label class="form-label" style="display:inline">Linhas:</label>
          <select id="log-lines" style="width:auto;display:inline-block;margin-left:6px">
            <option value="50">50</option>
            <option value="100" selected>100</option>
            <option value="200">200</option>
            <option value="500">500</option>
          </select>
        </div>
        <button class="btn btn-sm btn-outline" onclick="reloadLogs()">↺ Atualizar</button>
        <button class="btn btn-sm btn-outline" onclick="toggleAutoRefresh()">⏱ Auto (10s)</button>
        <div id="log-status" style="font-size:12px;color:var(--text3)"></div>
      </div>
      <div class="log-box" id="log-content">Carregando...</div>
    </div>
  `;
  reloadLogs();
}

let logAutoRefresh = null;
async function reloadLogs() {
  const lines = document.getElementById('log-lines')?.value || 100;
  const el = document.getElementById('log-content');
  if (!el) return;
  try {
    const data = await apiFetch(`/api/logs?lines=${lines}`);
    const colored = data.lines.map(l => colorizeLog(escHtml(l))).join('\n');
    el.innerHTML = colored || '(sem logs)';
    el.scrollTop = el.scrollHeight;
    const st = document.getElementById('log-status');
    if (st) st.textContent = `Atualizado: ${new Date().toLocaleTimeString()}`;
  } catch(e) {
    if (el) el.textContent = 'Erro ao carregar logs: ' + e.message;
  }
}

function toggleAutoRefresh() {
  if (logAutoRefresh) {
    clearInterval(logAutoRefresh);
    logAutoRefresh = null;
    toast('Auto-refresh desativado', 'info');
  } else {
    logAutoRefresh = setInterval(reloadLogs, 10000);
    toast('Auto-refresh ativado (10s)', 'info');
  }
}

function colorizeLog(line) {
  if (/ERROR|CRITICAL/i.test(line)) return `<span class="log-err">${line}</span>`;
  if (/WARN/i.test(line))           return `<span class="log-warn">${line}</span>`;
  if (/INFO/i.test(line))           return `<span class="log-info">${line}</span>`;
  return line;
}

// ── EDITOR ───────────────────────────────────────────────────────────
async function renderEditor(el) {
  let cfg = '';
  try {
    const data = await apiFetch('/api/config/raw');
    cfg = data.content;
  } catch(e) {
    el.innerHTML = `<div class="alert alert-error">Erro: ${e.message}</div>`;
    return;
  }

  el.innerHTML = `
    <div class="card">
      <div class="card-title">✎ Editor kamailio.cfg</div>
      <div class="alert alert-warning">
        ⚠ Edição direta do arquivo de configuração. Um backup automático é criado antes de salvar.
      </div>
      <div class="btn-group" style="margin-bottom:12px">
        <button class="btn btn-outline btn-sm" onclick="checkSyntax()">✓ Verificar Sintaxe</button>
      </div>
      <div id="syntax-result" style="margin-bottom:12px"></div>
      <textarea id="raw-cfg" rows="30" style="font-family:monospace;font-size:12px">${escHtml(cfg)}</textarea>
      <div class="btn-group" style="margin-top:12px">
        <button class="btn btn-primary" onclick="saveRawConfig()">💾 Salvar</button>
        <button class="btn btn-success" onclick="reloadKamailio()">↺ Reload</button>
      </div>
    </div>
  `;
}

async function checkSyntax() {
  const content = document.getElementById('raw-cfg').value;
  const el = document.getElementById('syntax-result');
  el.innerHTML = '<div class="loader"></div> Verificando...';
  try {
    const r = await apiPost('/api/kamailio/syntax-check', { content });
    el.innerHTML = r.ok
      ? `<div class="alert alert-success">✓ Sintaxe OK</div>`
      : `<div class="alert alert-error">✗ Erros:<pre style="margin-top:6px;white-space:pre-wrap">${escHtml(r.output)}</pre></div>`;
  } catch(e) {
    el.innerHTML = `<div class="alert alert-error">Erro: ${e.message}</div>`;
  }
}

async function saveRawConfig() {
  const content = document.getElementById('raw-cfg').value;
  try {
    const r = await apiPost('/api/config/raw', { content });
    toast(`Config salva! Backup: ${r.backup}`, 'success');
  } catch(e) {
    toast('Erro: ' + e.message, 'error');
  }
}

// ── BACKUPS ──────────────────────────────────────────────────────────
async function renderBackups(el) {
  let data = { backups: [] };
  try {
    data = await apiFetch('/api/backups');
  } catch {}

  el.innerHTML = `
    <div class="card">
      <div class="card-title">⊡ Backups da Configuração</div>
      ${data.backups.length > 0 ? `
        <div class="table-wrap">
          <table>
            <thead><tr><th>Arquivo</th><th>Tamanho</th><th>Data</th><th>Ação</th></tr></thead>
            <tbody>
              ${data.backups.map(b => `
                <tr>
                  <td style="font-family:monospace;font-size:12px">${escHtml(b.file)}</td>
                  <td>${(b.size/1024).toFixed(1)} KB</td>
                  <td>${b.mtime}</td>
                  <td>
                    <button class="btn btn-sm btn-outline" onclick="restoreBackup('${escHtml(b.file)}')">↩ Restaurar</button>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      ` : `
        <div class="empty-state">
          <div class="empty-state-icon">⊡</div>
          <div class="empty-state-text">Nenhum backup encontrado</div>
        </div>
      `}
    </div>
  `;
}

function restoreBackup(filename) {
  showModal('Restaurar Backup', `Restaurar configuração de <strong>${filename}</strong>?<br>A configuração atual será sobrescrita (um novo backup será criado).`, async () => {
    try {
      await fetch(API + `/api/backups/${encodeURIComponent(filename)}/restore`, { method: 'POST' });
      toast('Backup restaurado!', 'success');
      navigateTo('backups');
    } catch(e) {
      toast('Erro: ' + e.message, 'error');
    }
  });
}

// ── Kamailio Actions ─────────────────────────────────────────────────
async function reloadKamailio() {
  try {
    const r = await apiPost('/api/kamailio/reload', {});
    toast(r.ok ? '✓ Kamailio recarregado!' : '✗ ' + r.output, r.ok ? 'success' : 'error');
  } catch(e) {
    toast('Erro: ' + e.message, 'error');
  }
}

function confirmRestart() {
  showModal('Restart Kamailio', '⚠ Esta ação irá reiniciar o Kamailio e todas as chamadas ativas serão interrompidas. Deseja continuar?', async () => {
    try {
      const r = await apiPost('/api/kamailio/restart', {});
      toast(r.ok ? '✓ Kamailio reiniciado!' : '✗ ' + r.output, r.ok ? 'success' : 'error');
    } catch(e) {
      toast('Erro: ' + e.message, 'error');
    }
  });
}

// ── Utilities ────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function toast(msg, type = 'info') {
  const icons = { success: '✓', error: '✗', warning: '⚠', info: 'ℹ' };
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `
    <span class="toast-icon">${icons[type] || 'ℹ'}</span>
    <span class="toast-msg">${escHtml(msg)}</span>
    <span class="toast-close" onclick="this.parentElement.remove()">×</span>
  `;
  document.getElementById('toast-container').appendChild(el);
  setTimeout(() => el.remove(), 5000);
}

let modalCallback = null;
function showModal(title, body, onConfirm) {
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-body').innerHTML = body;
  document.getElementById('modal-overlay').style.display = 'flex';
  document.getElementById('modal-confirm-btn').onclick = async () => {
    closeModal();
    if (onConfirm) await onConfirm();
  };
}
function closeModal() {
  document.getElementById('modal-overlay').style.display = 'none';
}


// =================================================================
// WEBPHONE — status persistente + indicador visual
// =================================================================
let wpUA       = null;
let wpSession  = null;
let wpState    = 'offline'; // 'offline' | 'connecting' | 'online'

// Atualiza indicador visual (persiste mesmo ao navegar)
function wpSyncUI() {
  const dot  = document.getElementById('wp-dot');
  const lbl  = document.getElementById('wp-lbl');
  const reg  = document.getElementById('wp-btn-reg');
  const unreg= document.getElementById('wp-btn-unreg');
  const call = document.getElementById('wp-btn-call');
  if (!dot) return;

  const map = {
    offline:    { color:'#ef4444', text:'● Offline',     reg:false, unreg:true,  call:true  },
    connecting: { color:'#f59e0b', text:'● Conectando…', reg:true,  unreg:false, call:true  },
    online:     { color:'#22c55e', text:'● Online',      reg:true,  unreg:false, call:false },
  };
  const s = map[wpState] || map.offline;
  dot.style.color   = s.color;
  if (lbl)   lbl.textContent   = s.text;
  if (reg)   reg.disabled      = s.reg;
  if (unreg) unreg.disabled    = s.unreg;
  if (call)  call.disabled     = s.call;
}

function wpLog(msg, type) {
  type = type || 'info';
  const el = document.getElementById('wp-log');
  if (!el) return;
  const colors = { ok:'#22c55e', err:'#ef4444', warn:'#f59e0b', info:'#4f8ef7' };
  const t = new Date().toLocaleTimeString();
  el.innerHTML += '<div style="color:' + (colors[type]||colors.info) + '">['+t+'] '+msg+'</div>';
  el.scrollTop = el.scrollHeight;
}

function renderWebPhone(el) {
  const digits = ['1','2','3','4','5','6','7','8','9','*','0','#'];
  const pad = digits.map(d =>
    '<button class="btn btn-outline" style="font-size:15px;padding:9px" onclick="wpDialpad(\''+d+'\')">'+d+'</button>'
  ).join('');

  el.innerHTML =
    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">' +

      // ── Card Config ──────────────────────────────────────────────
      '<div class="card">' +
        '<div class="card-title" style="display:flex;justify-content:space-between;align-items:center">' +
          '<span>&#9742; WebPhone</span>' +
          '<span id="wp-dot" style="font-size:13px;font-weight:600;color:#ef4444" title="Status do ramal">&#9679; Offline</span>' +
        '</div>' +

        // Status badge
        '<div id="wp-status-bar" style="background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);border-radius:6px;padding:8px 12px;font-size:12px;color:#fca5a5;margin-bottom:12px">' +
          '<span id="wp-lbl">● Offline — preencha os dados e clique em Registrar</span>' +
        '</div>' +

        '<div class="form-group">' +
          '<label class="form-label">WebSocket URL</label>' +
          '<input id="wp-ws" class="form-input" value="wss://{{DOMAIN}}:8089/asterisk/ws">' +
        '</div>' +
        '<div class="form-group">' +
          '<label class="form-label">SIP Domain</label>' +
          '<input id="wp-domain" class="form-input" value="{{DOMAIN}}">' +
        '</div>' +
        '<div class="form-group">' +
          '<label class="form-label">Ramal</label>' +
          '<input id="wp-user" class="form-input" placeholder="ex: 1001">' +
        '</div>' +
        '<div class="form-group">' +
          '<label class="form-label">Senha</label>' +
          '<input id="wp-pass" class="form-input" type="password" placeholder="••••••••">' +
        '</div>' +
        '<div class="btn-group" style="margin-top:4px">' +
          '<button class="btn btn-success" id="wp-btn-reg"   onclick="wpRegister()">&#9654; Registrar</button>' +
          '<button class="btn btn-danger"  id="wp-btn-unreg" onclick="wpUnregister()" disabled>&#9632; Desconectar</button>' +
        '</div>' +
      '</div>' +

      // ── Card Discador ────────────────────────────────────────────
      '<div class="card">' +
        '<div class="card-title">&#128222; Discador</div>' +
        '<div class="form-group">' +
          '<label class="form-label">Destino</label>' +
          '<div style="display:flex;gap:6px">' +
            '<input id="wp-dest" class="form-input" placeholder="ramal ou número" style="flex:1" onkeydown="if(event.key===\'Enter\') wpCall()">' +
            '<button class="btn btn-outline" onclick="document.getElementById(\'wp-dest\').value=\'\'" style="flex-shrink:0">&#10005;</button>' +
          '</div>' +
        '</div>' +

        // Dialpad
        '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:5px;margin:10px 0">' +
          pad +
        '</div>' +

        // Botões chamada
        '<div class="btn-group">' +
          '<button class="btn btn-success" id="wp-btn-call"   onclick="wpCall()"   disabled>&#128222; Ligar</button>' +
          '<button class="btn btn-danger"  id="wp-btn-hangup" onclick="wpHangup()" disabled>&#10005; Desligar</button>' +
          '<button class="btn btn-outline" id="wp-btn-answer" onclick="wpAnswer()" disabled style="color:#22c55e;border-color:#22c55e">&#10003; Atender</button>' +
        '</div>' +

        // Status chamada
        '<div id="wp-call-bar" style="display:none;margin-top:10px;padding:8px 12px;border-radius:6px;font-size:12px;font-weight:600"></div>' +
      '</div>' +

    '</div>' +

    // ── Log ─────────────────────────────────────────────────────────
    '<div class="card" style="margin-top:0">' +
      '<div class="card-title" style="display:flex;justify-content:space-between">' +
        '<span>&#8801; Log</span>' +
        '<button class="btn btn-sm btn-outline" onclick="document.getElementById(\'wp-log\').innerHTML=\'\'">Limpar</button>' +
      '</div>' +
      '<div id="wp-log" style="background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:10px;font-family:monospace;font-size:11px;max-height:180px;overflow-y:auto;color:var(--text3)"></div>' +
    '</div>' +

    '<audio id="wp-audio" autoplay style="display:none"></audio>';

  // Restaurar estado visual após rebuild do DOM
  wpSyncUI();
  wpSyncCallUI();
}

function wpSyncStatus(state, msg) {
  wpState = state;
  const bar = document.getElementById('wp-status-bar');
  const lbl = document.getElementById('wp-lbl');
  const dot = document.getElementById('wp-dot');

  const styles = {
    offline:    { bg:'rgba(239,68,68,.1)',  border:'rgba(239,68,68,.3)',  color:'#fca5a5', dot:'#ef4444' },
    connecting: { bg:'rgba(245,158,11,.1)', border:'rgba(245,158,11,.3)', color:'#fcd34d', dot:'#f59e0b' },
    online:     { bg:'rgba(34,197,94,.1)',  border:'rgba(34,197,94,.3)',  color:'#86efac', dot:'#22c55e' },
  };
  const s = styles[state] || styles.offline;

  if (bar) {
    bar.style.background   = s.bg;
    bar.style.borderColor  = s.border;
    bar.style.color        = s.color;
  }
  if (lbl) lbl.textContent = msg;
  if (dot) { dot.style.color = s.dot; dot.textContent = '● ' + (state === 'online' ? 'Online' : state === 'connecting' ? 'Conectando' : 'Offline'); }
  wpSyncUI();
}

function wpSyncCallUI() {
  const hangup = document.getElementById('wp-btn-hangup');
  const answer = document.getElementById('wp-btn-answer');
  const inCall = wpSession && (wpSession.isEstablished() || wpSession.isInProgress());
  if (hangup) hangup.disabled = !inCall;
  if (answer) { answer.disabled = !(wpSession && !wpSession.isEstablished() && wpSession.direction === 'incoming'); }
}

function wpSetCallBar(msg, type) {
  const bar = document.getElementById('wp-call-bar');
  if (!bar) return;
  if (!msg) { bar.style.display = 'none'; return; }
  const map = { ok:'#22c55e', err:'#ef4444', warn:'#f59e0b', info:'#4f8ef7' };
  bar.style.display     = 'block';
  bar.style.background  = (map[type]||map.info) + '22';
  bar.style.border      = '1px solid ' + (map[type]||map.info) + '55';
  bar.style.color       = map[type]||map.info;
  bar.textContent       = msg;
}

function wpRegister() {
  if (typeof JsSIP === 'undefined') {
    wpSyncStatus('offline', '● Erro: JsSIP não carregado. Aguarde e tente novamente.');
    return;
  }
  const ws     = document.getElementById('wp-ws').value.trim();
  const domain = document.getElementById('wp-domain').value.trim();
  const user   = document.getElementById('wp-user').value.trim();
  const pass   = document.getElementById('wp-pass').value.trim();
  if (!user || !pass) { wpSyncStatus('offline', '● Preencha o ramal e a senha'); return; }

  if (wpUA) { try { wpUA.stop(); } catch(e) {} wpUA = null; }

  wpSyncStatus('connecting', '● Conectando ao WebSocket...');
  wpLog('Iniciando: ' + user + '@' + domain);

  try {
    const socket = new JsSIP.WebSocketInterface(ws);
    wpUA = new JsSIP.UA({
      sockets:          [socket],
      uri:              'sip:' + user + '@' + domain,
      password:         pass,
      register:         true,
      register_expires: 300,
      contact_uri:      'sip:' + user + '@' + domain + ';transport=wss',
    });

    wpUA.on('connecting',   function() { wpSyncStatus('connecting', '● Conectando ao servidor SIP...'); });
    wpUA.on('connected',    function() { wpSyncStatus('connecting', '● Autenticando...'); wpLog('WS conectado', 'ok'); });
    wpUA.on('disconnected', function(e) {
      wpSyncStatus('offline', '● Desconectado' + (e.cause ? ': ' + e.cause : ''));
      wpLog('Desconectado: ' + (e.cause || ''), 'err');
    });
    wpUA.on('registered', function() {
      wpSyncStatus('online', '● Online — ' + user + '@' + domain);
      wpLog('Registrado com sucesso!', 'ok');
    });
    wpUA.on('unregistered', function() {
      wpSyncStatus('offline', '● Desregistrado');
      wpLog('Desregistrado');
    });
    wpUA.on('registrationFailed', function(e) {
      wpSyncStatus('offline', '● Falha no registro: ' + e.cause);
      wpLog('Falha: ' + e.cause, 'err');
    });
    wpUA.on('newRTCSession', function(e) {
      wpSession = e.session;
      if (e.originator === 'remote') {
        const caller = e.session.remote_identity.uri.toString();
        wpSetCallBar('&#128222; Chamada recebida de ' + caller, 'warn');
        wpLog('Chamada de ' + caller, 'warn');
        const answer = document.getElementById('wp-btn-answer');
        const hangup = document.getElementById('wp-btn-hangup');
        if (answer) answer.disabled = false;
        if (hangup) hangup.disabled = false;
      }
      wpSetupSession(e.session);
    });

    wpUA.start();
  } catch(err) {
    wpSyncStatus('offline', '● Erro: ' + err.message);
    wpLog('Erro: ' + err.message, 'err');
  }
}

function wpSetupSession(session) {
  session.on('confirmed',  function() { wpSetCallBar('Em chamada', 'ok'); wpLog('Chamada confirmada', 'ok'); });
  session.on('ended',      function() { wpSetCallBar('', ''); wpLog('Chamada encerrada'); wpResetCallButtons(); wpSession = null; });
  session.on('failed',     function(e) { wpSetCallBar('Falhou: ' + e.cause, 'err'); wpLog('Falhou: ' + e.cause, 'err'); wpResetCallButtons(); wpSession = null; });
  session.on('peerconnection', function(e) {
    e.peerconnection.ontrack = function(ev) {
      const audio = document.getElementById('wp-audio');
      if (audio && audio.srcObject !== ev.streams[0]) {
        audio.srcObject = ev.streams[0];
        wpLog('Audio conectado', 'ok');
      }
    };
  });
}

function wpCall() {
  if (!wpUA || wpState !== 'online') { wpLog('Registre o ramal antes de ligar', 'warn'); return; }
  const dest   = document.getElementById('wp-dest').value.trim();
  const domain = document.getElementById('wp-domain').value.trim();
  if (!dest) return;
  const target = dest.includes('@') ? dest : 'sip:' + dest + '@' + domain;
  try {
    wpSession = wpUA.call(target, {
      mediaConstraints: { audio: true, video: false },
      pcConfig: { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] },
    });
    wpSetupSession(wpSession);
    wpSetCallBar('Chamando ' + dest + '...', 'info');
    wpLog('Chamando: ' + target);
    const hangup = document.getElementById('wp-btn-hangup');
    const call   = document.getElementById('wp-btn-call');
    if (hangup) hangup.disabled = false;
    if (call)   call.disabled   = true;
  } catch(err) {
    wpLog('Erro ao ligar: ' + err.message, 'err');
  }
}

function wpAnswer() {
  if (!wpSession) return;
  try {
    wpSession.answer({
      mediaConstraints: { audio: true, video: false },
      pcConfig: { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] },
    });
    const answer = document.getElementById('wp-btn-answer');
    if (answer) answer.disabled = true;
    wpLog('Atendido', 'ok');
  } catch(err) { wpLog('Erro ao atender: ' + err.message, 'err'); }
}

function wpHangup() {
  if (wpSession) { try { wpSession.terminate(); } catch(e) {} wpSession = null; }
  wpResetCallButtons();
  wpSetCallBar('', '');
}

function wpResetCallButtons() {
  ['wp-btn-hangup','wp-btn-answer'].forEach(function(id) {
    const b = document.getElementById(id);
    if (b) b.disabled = true;
  });
  const call = document.getElementById('wp-btn-call');
  if (call) call.disabled = (wpState !== 'online');
}

function wpDialpad(digit) {
  const inp = document.getElementById('wp-dest');
  if (inp) inp.value += digit;
  if (wpSession && wpSession.isEstablished()) {
    try { wpSession.sendDTMF(digit); wpLog('DTMF: ' + digit); } catch(e) {}
  }
}

function wpUnregister() {
  if (wpUA) { try { wpUA.unregister(); wpUA.stop(); } catch(e) {} wpUA = null; }
  wpState = 'offline';
  wpSyncStatus('offline', '● Offline');
  wpSyncUI();
}


// ── MONITOR SIP (CLI em tempo real) ─────────────────────────────────
let monitorInterval = null;
let monitorPaused = false;
let monitorFilter = '';
let monitorLevelFilter = '';
let monitorAutoScroll = true;

async function renderMonitor(el) {
  // Limpa interval anterior
  if (monitorInterval) { clearInterval(monitorInterval); monitorInterval = null; }
  monitorPaused = false;

  el.innerHTML = `
    <div class="monitor-toolbar">
      <div class="monitor-toolbar-left">
        <button class="btn btn-sm btn-success" id="mon-toggle" onclick="toggleMonitor()">⏸ Pausar</button>
        <button class="btn btn-sm btn-outline" onclick="clearMonitor()">⌫ Limpar</button>
        <select id="mon-type-filter" onchange="monitorFilter=this.value" class="monitor-select">
          <option value="">Todos os tipos</option>
          <option value="REGISTER">REGISTER</option>
          <option value="INVITE">INVITE</option>
          <option value="AUTH">AUTH</option>
          <option value="API_LOOKUP">API Lookup</option>
          <option value="API_OK">API OK</option>
          <option value="API_ERROR">API Error</option>
          <option value="CACHE_HIT">Cache Hit</option>
          <option value="FORWARD">Forward</option>
          <option value="NO_ROUTE">No Route</option>
          <option value="DNS_ERROR">DNS Error</option>
          <option value="REG_REPLY">Reg Reply</option>
          <option value="REG_FAIL">Reg Fail</option>
          <option value="WEBSOCKET">WebSocket</option>
        </select>
        <select id="mon-level-filter" onchange="monitorLevelFilter=this.value" class="monitor-select">
          <option value="">Todos niveis</option>
          <option value="error">Erros</option>
          <option value="warn">Warnings</option>
          <option value="ok">Sucesso</option>
          <option value="info">Info</option>
        </select>
        <label class="monitor-check"><input type="checkbox" checked onchange="monitorAutoScroll=this.checked"> Auto-scroll</label>
      </div>
      <div class="monitor-toolbar-right">
        <div class="monitor-stats" id="mon-stats">-</div>
      </div>
    </div>
    <div class="monitor-counters" id="mon-counters"></div>
    <div class="monitor-terminal" id="mon-terminal">
      <div class="monitor-welcome">
        <span class="log-info">&#9654; SIP Monitor iniciado...</span>
        <span class="log-info">  Aguardando eventos do Kamailio...</span>
      </div>
    </div>
  `;

  // Start polling
  fetchMonitorData();
  monitorInterval = setInterval(() => {
    if (!monitorPaused) fetchMonitorData();
  }, 2000);
}

async function fetchMonitorData() {
  try {
    let url = '/api/sip-monitor?limit=200';
    if (monitorFilter) url += '&type=' + monitorFilter;
    if (monitorLevelFilter) url += '&level=' + monitorLevelFilter;
    const data = await apiFetch(url);
    renderMonitorEvents(data.events);
    renderMonitorStats(data.stats);
  } catch(e) {
    // silently fail
  }
}

function renderMonitorEvents(events) {
  const term = document.getElementById('mon-terminal');
  if (!term) return;

  if (events.length === 0) {
    term.innerHTML = '<div class="monitor-welcome"><span class="log-info">Aguardando eventos...</span></div>';
    return;
  }

  let html = '';
  for (const evt of events) {
    const time = evt.time || '';
    const type = evt.type || 'OTHER';
    const level = evt.level || 'info';
    const detail = evt.detail || '';

    const levelClass = {
      'error': 'log-err',
      'warn': 'log-warn',
      'ok': 'log-ok',
      'info': 'log-info',
    }[level] || 'log-info';

    const typeColors = {
      'REGISTER': '#4fc3f7',
      'INVITE': '#ba68c8',
      'AUTH': '#81c784',
      'API_LOOKUP': '#90a4ae',
      'API_OK': '#66bb6a',
      'API_ERROR': '#ef5350',
      'CACHE_HIT': '#ffb74d',
      'FORWARD': '#4dd0e1',
      'NO_ROUTE': '#e57373',
      'DNS_ERROR': '#ff7043',
      'REG_REPLY': '#aed581',
      'REG_FAIL': '#ef5350',
      'WEBSOCKET': '#ce93d8',
      'MALFORMED': '#ff8a65',
      'OTHER': '#78909c',
    };
    const typeColor = typeColors[type] || '#78909c';

    const typeBadge = `<span class="mon-type" style="color:${typeColor}">[${type.padEnd(11)}]</span>`;
    const timeStr = time ? `<span class="mon-time">${time}</span> ` : '';

    html += `<div class="mon-line ${levelClass}">${timeStr}${typeBadge} <span class="${levelClass}">${escHtml(detail)}</span></div>`;
  }

  term.innerHTML = html;

  if (monitorAutoScroll) {
    term.scrollTop = term.scrollHeight;
  }
}

function renderMonitorStats(stats) {
  const el = document.getElementById('mon-counters');
  if (!el || !stats) return;

  el.innerHTML = `
    <div class="mon-counter"><span class="mon-counter-val">${stats.total}</span><span class="mon-counter-label">Total</span></div>
    <div class="mon-counter"><span class="mon-counter-val" style="color:#4fc3f7">${stats.registers}</span><span class="mon-counter-label">REGISTER</span></div>
    <div class="mon-counter"><span class="mon-counter-val" style="color:#ba68c8">${stats.invites}</span><span class="mon-counter-label">INVITE</span></div>
    <div class="mon-counter"><span class="mon-counter-val" style="color:#66bb6a">${stats.api_ok}</span><span class="mon-counter-label">API OK</span></div>
    <div class="mon-counter"><span class="mon-counter-val" style="color:#ef5350">${stats.api_errors}</span><span class="mon-counter-label">API Err</span></div>
    <div class="mon-counter"><span class="mon-counter-val" style="color:#ffb74d">${stats.cache_hits}</span><span class="mon-counter-label">Cache</span></div>
    <div class="mon-counter"><span class="mon-counter-val" style="color:#ef5350">${stats.errors}</span><span class="mon-counter-label">Erros</span></div>
  `;

  const statsEl = document.getElementById('mon-stats');
  if (statsEl) {
    statsEl.innerHTML = monitorPaused
      ? '<span class="badge badge-yellow">PAUSADO</span>'
      : '<span class="badge badge-green">● AO VIVO</span>';
  }
}

function toggleMonitor() {
  monitorPaused = !monitorPaused;
  const btn = document.getElementById('mon-toggle');
  if (btn) {
    btn.textContent = monitorPaused ? '▶ Retomar' : '⏸ Pausar';
    btn.className = monitorPaused ? 'btn btn-sm btn-primary' : 'btn btn-sm btn-success';
  }
}

async function clearMonitor() {
  try {
    await apiPost('/api/sip-monitor/clear', {});
    const term = document.getElementById('mon-terminal');
    if (term) term.innerHTML = '<div class="monitor-welcome"><span class="log-info">Monitor limpo. Aguardando novos eventos...</span></div>';
    toast('Buffer limpo', 'success');
  } catch(e) {
    toast('Erro: ' + e.message, 'error');
  }
}

function escHtml(s) {
  if (!s) return '';
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}


// ── FIREWALL / FAIL2BAN ─────────────────────────────────────────────
let f2bInterval = null;

async function renderFirewall(el) {
  if (f2bInterval) { clearInterval(f2bInterval); f2bInterval = null; }
  if (captureInterval) { clearInterval(captureInterval); captureInterval = null; }

  el.innerHTML = '<div class="loading-state"><div class="loader"></div></div>';

  await loadFirewall(el);
}

async function loadFirewall(el) {
  try {
    const [status, wl] = await Promise.all([
      apiFetch('/api/fail2ban/status'),
      apiFetch('/api/fail2ban/whitelist')
    ]);

    const totalBanned = status.jails.reduce((s, j) => s + j.banned, 0);
    const totalFailed = status.jails.reduce((s, j) => s + (j.total_failed || 0), 0);

    // Collect all banned IPs across jails (dedup por IP - um IP em N jails = 1 linha)
    const bannedMap = new Map();
    for (const j of status.jails) {
      for (const ip of (j.banned_ips || [])) {
        if (!bannedMap.has(ip)) bannedMap.set(ip, []);
        bannedMap.get(ip).push(j.name);
      }
    }
    const allBanned = Array.from(bannedMap.entries()).map(([ip, jails]) => ({ ip, jails }));

    el.innerHTML = `
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-label">Status</div>
          <div class="stat-value ${status.running ? 'green' : 'red'}">${status.running ? 'ATIVO' : 'PARADO'}</div>
          <div class="stat-sub">${status.running ? '<span class="badge badge-green">Protegido</span>' : '<span class="badge badge-red">Desprotegido</span>'}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">IPs Bloqueados</div>
          <div class="stat-value red">${totalBanned}</div>
          <div class="stat-sub">ativos agora</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Tentativas</div>
          <div class="stat-value">${totalFailed}</div>
          <div class="stat-sub">total detectadas</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Jails</div>
          <div class="stat-value blue">${status.jails.length}</div>
          <div class="stat-sub">regras ativas</div>
        </div>
      </div>

      <!-- Jails (consolidado) -->
      <div class="card">
        <div class="card-title">Jails Ativos</div>
        <div class="table-wrap"><table>
          <thead><tr>
            <th>Jails</th><th>Banidos</th><th>Total Banidos</th><th>Falhas Atuais</th><th>Total Falhas</th>
          </tr></thead>
          <tbody>
            <tr>
              <td><strong>${status.jails.length}</strong></td>
              <td><span class="badge ${totalBanned > 0 ? 'badge-red' : 'badge-green'}">${totalBanned}</span></td>
              <td>${status.jails.reduce((s,j)=>s+(j.total_banned||0),0)}</td>
              <td>${status.jails.reduce((s,j)=>s+(j.failed||0),0)}</td>
              <td>${totalFailed}</td>
            </tr>
          </tbody>
        </table></div>
      </div>

      <!-- IPs Banidos -->
      <div class="card">
        <div class="card-title">IPs Bloqueados</div>
        ${allBanned.length === 0
          ? '<div class="empty-state"><div class="empty-state-icon">&#9888;</div><div class="empty-state-text">Nenhum IP bloqueado</div></div>'
          : `<div class="table-wrap"><table>
              <thead><tr><th>IP</th><th>Jails</th><th>Ação</th></tr></thead>
              <tbody>
                ${allBanned.map(b => `<tr>
                  <td><code>${b.ip}</code></td>
                  <td>${b.jails.map(jn => `<span class="badge badge-blue" style="margin-right:4px">${jn}</span>`).join('')}</td>
                  <td><button class="btn btn-sm btn-outline" onclick="f2bUnban('${b.ip}')">Desbloquear</button></td>
                </tr>`).join('')}
              </tbody>
            </table></div>
            <div class="btn-group" style="margin-top:12px">
              <button class="btn btn-sm btn-danger" onclick="f2bUnbanAll()">Desbloquear Todos</button>
            </div>`
        }
      </div>

      <!-- Bloquear Manual -->
      <div class="card">
        <div class="card-title">Bloquear IP Manualmente</div>
        <div style="display:flex;gap:8px;align-items:end">
          <div class="form-group" style="flex:1;margin:0">
            <label class="form-label">IP</label>
            <input type="text" id="f2b-ban-ip" placeholder="ex: 1.2.3.4">
          </div>
          <button class="btn btn-danger" onclick="f2bBan()" style="height:36px">Bloquear</button>
        </div>
        <div class="form-hint" style="margin-top:6px">Bloqueio aplicado em TODAS as jails ativas (incluindo permanente).</div>
      </div>

      <!-- Whitelist -->
      <div class="card">
        <div class="card-title">Whitelist (IPs que nunca são bloqueados)</div>

        <!-- Abas IP / DDNS -->
        <div class="wl-tabs" style="display:flex;gap:0;border-bottom:1px solid #2a2f3a;margin-bottom:14px">
          <button class="wl-tab-btn active" id="wl-tab-btn-ip" onclick="wlSwitchTab('ip')"
                  style="background:transparent;color:#cfd3dc;border:none;border-bottom:2px solid #3b82f6;padding:8px 18px;cursor:pointer;font-weight:600">
            IP / CIDR
          </button>
          <button class="wl-tab-btn" id="wl-tab-btn-ddns" onclick="wlSwitchTab('ddns')"
                  style="background:transparent;color:#9aa0a6;border:none;border-bottom:2px solid transparent;padding:8px 18px;cursor:pointer">
            DDNS / Hostname
          </button>
        </div>

        <!-- Aba IP -->
        <div id="wl-tab-ip" class="wl-tab-content">
          <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:end">
            <div class="form-group" style="flex:2;min-width:180px;margin:0">
              <label class="form-label">Endereço IP</label>
              <input type="text" id="wl-add-ip" placeholder="Ex.: 192.168.10.20" autocomplete="off">
            </div>
            <div class="form-group" style="width:140px;margin:0">
              <label class="form-label">Máscara</label>
              <select id="wl-add-mask">
                <option value="/32" selected>/32 (host)</option>
                <option value="/24">/24</option>
                <option value="/23">/23</option>
                <option value="/22">/22</option>
                <option value="/20">/20</option>
                <option value="/16">/16</option>
                <option value="/12">/12</option>
                <option value="/8">/8</option>
                <option value="">Sem máscara</option>
              </select>
            </div>
            <div class="form-group" style="flex:3;min-width:200px;margin:0">
              <label class="form-label">Nome do cliente <span style="color:#888;font-weight:400">(opcional)</span></label>
              <input type="text" id="wl-add-name" placeholder="Ex.: Cliente Acme - Matriz" autocomplete="off">
            </div>
            <button class="btn btn-primary" onclick="f2bAddToWhitelist()" style="height:36px">Adicionar à Whitelist</button>
          </div>
        </div>

        <!-- Aba DDNS -->
        <div id="wl-tab-ddns" class="wl-tab-content" style="display:none">
          <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:end">
            <div class="form-group" style="flex:3;min-width:240px;margin:0">
              <label class="form-label">Hostname DDNS</label>
              <input type="text" id="wl-add-ddns-host" placeholder="Ex.: cliente.duckdns.org" autocomplete="off">
            </div>
            <div class="form-group" style="flex:3;min-width:200px;margin:0">
              <label class="form-label">Nome do cliente <span style="color:#888;font-weight:400">(opcional)</span></label>
              <input type="text" id="wl-add-ddns-name" placeholder="Ex.: Cliente Acme - Sede" autocomplete="off">
            </div>
            <button class="btn btn-primary" onclick="f2bAddDdnsToWhitelist()" style="height:36px">Adicionar DDNS</button>
          </div>
          <div class="form-hint" style="margin-top:8px">
            O hostname é resolvido imediatamente e revalidado a cada 2 minutos pelo agendador.
            Caso o IP mude, a whitelist é atualizada e o novo IP é desbloqueado automaticamente.
          </div>
        </div>

        <div style="display:flex;gap:10px;margin-top:12px;align-items:center;flex-wrap:wrap">
          <button class="btn btn-outline" onclick="openWhitelistEditor()" style="height:34px">Editar Whitelist</button>
          <button class="btn btn-outline" onclick="f2bRefreshDdns()" style="height:34px" title="Forçar resolução imediata dos DDNS">Atualizar DDNS agora</button>
          <div class="form-hint" style="margin:0">
            Total: <strong>${(wl.entries || wl.ips || []).length}</strong> entrada(s) na whitelist.
            Inclua sempre o seu IP de acesso para evitar bloqueios acidentais.
          </div>
        </div>
      </div>
    `;
  } catch(e) {
    el.innerHTML = `<div class="alert alert-error">Erro ao carregar: ${e.message}</div>`;
  }
}

async function f2bUnban(ip, jail) {
  try {
    const payload = jail ? { ip, jail } : { ip };
    await apiPost('/api/fail2ban/unban', payload);
    toast(ip + ' desbloqueado com sucesso.', 'success');
    refreshPage();
  } catch(e) { toast('Erro: ' + e.message, 'error'); }
}

async function f2bUnbanAll() {
  if (!confirm('Tem certeza de que deseja desbloquear todos os IPs?')) return;
  try {
    await apiPost('/api/fail2ban/unban-all', {});
    toast('Todos os IPs foram desbloqueados.', 'success');
    refreshPage();
  } catch(e) { toast('Erro: ' + e.message, 'error'); }
}

async function f2bBan() {
  const ip = document.getElementById('f2b-ban-ip').value.trim();
  if (!ip) { toast('Informe um endereço IP.', 'warning'); return; }
  try {
    const r = await apiPost('/api/fail2ban/ban', { ip });
    const n = (r && r.banned_in) ? r.banned_in.length : 0;
    toast(`${ip} bloqueado em ${n} jail(s)`, 'success');
    document.getElementById('f2b-ban-ip').value = '';
    refreshPage();
  } catch(e) { toast('Erro: ' + e.message, 'error'); }
}

// ── Adicionar IP unico na Whitelist (form simples) ──────────────────
async function f2bAddToWhitelist() {
  const ipEl = document.getElementById('wl-add-ip');
  const maskEl = document.getElementById('wl-add-mask');
  const nameEl = document.getElementById('wl-add-name');
  const ip = (ipEl.value || '').trim();
  const mask = (maskEl.value || '').trim();
  const name = (nameEl.value || '').trim();

  if (!ip) { toast('Informe um endereço IP.', 'warning'); return; }

  try {
    const r = await apiPost('/api/fail2ban/whitelist/add', { ip, mask, name });
    if (!r.ok) {
      toast(r.error || 'Não foi possível adicionar o IP.', 'error');
      return;
    }
    // Limpa campos
    ipEl.value = '';
    nameEl.value = '';
    maskEl.value = '/32';
    // Modal de sucesso (centralizado)
    showSuccessModal('IP adicionado com sucesso na whitelist da Omnismart!');
    // Atualiza a tela em background
    refreshPage();
  } catch(e) {
    toast('Erro: ' + e.message, 'error');
  }
}

// ── Modal de Sucesso (centralizado, com botao OK) ───────────────────
function showSuccessModal(message) {
  // Remove instancia anterior, se existir
  const old = document.getElementById('omni-success-modal');
  if (old) old.remove();

  const overlay = document.createElement('div');
  overlay.id = 'omni-success-modal';
  overlay.className = 'modal-overlay';
  overlay.style.display = 'flex';
  overlay.innerHTML = `
    <div class="modal" style="max-width:420px;text-align:center">
      <div style="font-size:48px;line-height:1;color:#22c55e;margin-bottom:8px">✓</div>
      <div class="modal-title" style="text-align:center">Sucesso</div>
      <div class="modal-body" style="text-align:center;margin:12px 0 18px">${escHtml(message)}</div>
      <div class="modal-footer" style="justify-content:center">
        <button class="btn btn-primary" id="omni-success-ok" style="min-width:100px">OK</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  const close = () => overlay.remove();
  document.getElementById('omni-success-ok').onclick = close;
  overlay.addEventListener('click', (ev) => {
    if (ev.target === overlay) close();
  });
  // Foco automático no OK e Enter para fechar
  setTimeout(() => {
    const btn = document.getElementById('omni-success-ok');
    if (btn) btn.focus();
  }, 50);
  document.addEventListener('keydown', function onEsc(ev) {
    if (ev.key === 'Escape' || ev.key === 'Enter') {
      close();
      document.removeEventListener('keydown', onEsc);
    }
  });
}

// ── Troca de abas IP / DDNS no card Whitelist ────────────────────────
function wlSwitchTab(tab) {
  const ipTab    = document.getElementById('wl-tab-ip');
  const ddnsTab  = document.getElementById('wl-tab-ddns');
  const ipBtn    = document.getElementById('wl-tab-btn-ip');
  const ddnsBtn  = document.getElementById('wl-tab-btn-ddns');
  if (!ipTab || !ddnsTab) return;
  const isIp = (tab === 'ip');
  ipTab.style.display    = isIp ? '' : 'none';
  ddnsTab.style.display  = isIp ? 'none' : '';
  if (ipBtn)   { ipBtn.style.color   = isIp ? '#cfd3dc' : '#9aa0a6';
                 ipBtn.style.borderBottomColor   = isIp ? '#3b82f6' : 'transparent';
                 ipBtn.style.fontWeight          = isIp ? '600' : '400'; }
  if (ddnsBtn) { ddnsBtn.style.color = isIp ? '#9aa0a6' : '#cfd3dc';
                 ddnsBtn.style.borderBottomColor = isIp ? 'transparent' : '#3b82f6';
                 ddnsBtn.style.fontWeight        = isIp ? '400' : '600'; }
}

// ── Adicionar DDNS na Whitelist ──────────────────────────────────────
async function f2bAddDdnsToWhitelist() {
  const hostEl = document.getElementById('wl-add-ddns-host');
  const nameEl = document.getElementById('wl-add-ddns-name');
  const hostname = (hostEl.value || '').trim();
  const name = (nameEl.value || '').trim();

  if (!hostname) { toast('Informe um hostname DDNS.', 'warning'); return; }

  try {
    const r = await apiPost('/api/fail2ban/whitelist/add', { type: 'ddns', hostname, name });
    if (!r.ok) {
      toast(r.error || 'Não foi possível adicionar o DDNS.', 'error');
      return;
    }
    hostEl.value = '';
    nameEl.value = '';
    showSuccessModal(
      `DDNS adicionado com sucesso na whitelist da Omnismart!\nIP atual resolvido: ${r.ip}`
    );
    refreshPage();
  } catch(e) {
    toast('Erro: ' + e.message, 'error');
  }
}

// ── Forcar refresh dos DDNS (botao 'Atualizar DDNS agora') ───────────
async function f2bRefreshDdns() {
  try {
    const r = await apiPost('/api/fail2ban/whitelist/refresh-ddns', {});
    const ch = (r && r.changes) || [];
    const failed = (r && r.failed) || [];
    if (ch.length === 0 && failed.length === 0) {
      toast('Todos os DDNS já estão atualizados.', 'success');
    } else {
      const parts = [];
      if (ch.length) parts.push(`${ch.length} DDNS atualizado(s)`);
      if (failed.length) parts.push(`${failed.length} falha(s)`);
      toast(parts.join(' · '), ch.length ? 'success' : 'warning');
    }
    refreshPage();
  } catch(e) {
    toast('Erro: ' + e.message, 'error');
  }
}

// ── Editor avancado da Whitelist (tabela com IP/DDNS + Nome) ─────────
async function openWhitelistEditor() {
  let wl;
  try {
    wl = await apiFetch('/api/fail2ban/whitelist');
  } catch(e) {
    toast('Erro ao carregar whitelist: ' + e.message, 'error');
    return;
  }
  // Normaliza para incluir 'type'
  const entries = (wl.entries || (wl.ips || []).map(ip => ({ type: 'ip', ip, name: '' })))
    .map(e => Object.assign({ type: e.hostname ? 'ddns' : 'ip', name: '', ip: '', hostname: '' }, e));

  const old = document.getElementById('omni-wl-editor');
  if (old) old.remove();

  const overlay = document.createElement('div');
  overlay.id = 'omni-wl-editor';
  overlay.className = 'modal-overlay';
  overlay.style.display = 'flex';
  overlay.innerHTML = `
    <div class="modal" style="max-width:920px;width:95%">
      <div class="modal-title">Editar Whitelist</div>
      <div class="modal-body" style="max-height:65vh;overflow:auto">
        <p style="margin:0 0 10px;color:#9aa0a6">
          Edite manualmente as entradas da whitelist. Cada linha pode ser um IP/CIDR ou um DDNS (hostname dinâmico).
          Para entradas DDNS, o IP é atualizado automaticamente a cada 2 minutos.
        </p>
        <div class="table-wrap"><table id="wl-edit-table">
          <thead><tr>
            <th style="width:90px">Tipo</th>
            <th style="width:25%">IP / CIDR ou Hostname</th>
            <th style="width:130px">IP resolvido</th>
            <th>Nome do cliente</th>
            <th style="width:80px">Ações</th>
          </tr></thead>
          <tbody>
            ${entries.map((e, i) => wlEditorRowHtml(e, i)).join('')}
          </tbody>
        </table></div>
        <div style="margin-top:10px;display:flex;gap:8px">
          <button class="btn btn-sm btn-outline" onclick="wlEditorAddRow('ip')">+ Linha IP</button>
          <button class="btn btn-sm btn-outline" onclick="wlEditorAddRow('ddns')">+ Linha DDNS</button>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-outline" onclick="document.getElementById('omni-wl-editor').remove()">Cancelar</button>
        <button class="btn btn-primary" onclick="wlEditorSave()">Salvar Alterações</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', (ev) => {
    if (ev.target === overlay) overlay.remove();
  });
}

function wlEditorRowHtml(e, i) {
  const t = e.type === 'ddns' ? 'ddns' : 'ip';
  const main = t === 'ddns' ? (e.hostname || '') : (e.ip || '');
  const resolvedIp = t === 'ddns' ? (e.ip || '') : '';
  return `
    <tr data-wl-row="${i}">
      <td>
        <select data-wl-type onchange="wlEditorOnTypeChange(this)" style="width:100%">
          <option value="ip" ${t==='ip'?'selected':''}>IP/CIDR</option>
          <option value="ddns" ${t==='ddns'?'selected':''}>DDNS</option>
        </select>
      </td>
      <td><input type="text" data-wl-main value="${escHtml(main)}"
                 placeholder="${t==='ddns'?'Ex.: cliente.duckdns.org':'Ex.: 192.168.1.0/24'}"
                 style="width:100%"></td>
      <td><input type="text" data-wl-resolved value="${escHtml(resolvedIp)}"
                 placeholder="${t==='ddns'?'(auto)':'-'}"
                 ${t==='ddns'?'readonly':''} style="width:100%;background:${t==='ddns'?'#1a1d24':'#1a1d24'};color:#9aa0a6"></td>
      <td><input type="text" data-wl-name value="${escHtml(e.name || '')}" style="width:100%"></td>
      <td><button class="btn btn-sm btn-outline" onclick="this.closest('tr').remove()">Remover</button></td>
    </tr>`;
}

function wlEditorOnTypeChange(sel) {
  const tr = sel.closest('tr');
  const main = tr.querySelector('input[data-wl-main]');
  const resolved = tr.querySelector('input[data-wl-resolved]');
  if (sel.value === 'ddns') {
    main.placeholder = 'Ex.: cliente.duckdns.org';
    resolved.readOnly = true;
    resolved.placeholder = '(auto)';
    resolved.value = '';
  } else {
    main.placeholder = 'Ex.: 192.168.1.0/24';
    resolved.readOnly = false;
    resolved.placeholder = '-';
    resolved.value = '';
  }
}

function wlEditorAddRow(type) {
  const tbody = document.querySelector('#wl-edit-table tbody');
  if (!tbody) return;
  const i = tbody.querySelectorAll('tr').length;
  const tr = document.createElement('tr');
  const emptyEntry = type === 'ddns'
    ? { type: 'ddns', hostname: '', ip: '', name: '' }
    : { type: 'ip', ip: '', name: '' };
  tr.outerHTML = wlEditorRowHtml(emptyEntry, i);
  const wrap = document.createElement('tbody');
  wrap.innerHTML = wlEditorRowHtml(emptyEntry, i);
  tbody.appendChild(wrap.firstElementChild);
  const last = tbody.lastElementChild;
  const focus = last.querySelector('input[data-wl-main]');
  if (focus) focus.focus();
}

async function wlEditorSave() {
  const rows = document.querySelectorAll('#wl-edit-table tbody tr');
  const entries = [];
  rows.forEach(tr => {
    const type = tr.querySelector('select[data-wl-type]').value;
    const main = tr.querySelector('input[data-wl-main]').value.trim();
    const name = tr.querySelector('input[data-wl-name]').value.trim();
    if (!main) return;
    if (type === 'ddns') {
      entries.push({ type: 'ddns', hostname: main, name });
    } else {
      entries.push({ type: 'ip', ip: main, name });
    }
  });
  try {
    const r = await apiPost('/api/fail2ban/whitelist', { entries });
    if (r.invalid && r.invalid.length) {
      toast('Algumas entradas inválidas foram ignoradas: ' + r.invalid.join(', '), 'warning');
    }
    document.getElementById('omni-wl-editor').remove();
    showSuccessModal('Whitelist atualizada com sucesso na Omnismart!');
    refreshPage();
  } catch(e) {
    toast('Erro ao salvar: ' + e.message, 'error');
  }
}

// ── BLOCOS DE ROTEAMENTO (Kamailio route blocks) ─────────────────────
let routeBlocks = [];
let editingBlock = null;

async function loadRouteBlocks() {
  try {
    const data = await apiFetch('/api/config/route-blocks');
    routeBlocks = data.blocks || [];
  } catch(e) {
    routeBlocks = [];
    console.error('Erro ao carregar blocos:', e);
  }
}

function renderRouteBlocks() {
  const el = document.getElementById('route-blocks-container');
  if (!el) return;

  if (routeBlocks.length === 0) {
    el.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">{}</div>
        <div class="empty-state-text">Nenhum bloco de roteamento encontrado</div>
      </div>`;
    return;
  }

  const descriptions = {
    'request_route':            'Rota principal — ponto de entrada de todos os requests SIP',
    'route[REGISTRAR]':         'Processa REGISTER — consulta a API ou o cache e encaminha ao Asterisk.',
    'route[FORWARD_REGISTER]':  'Encaminha REGISTER para o backend Asterisk',
    'route[ROUTE_TO_BACKEND]':  'Roteamento de INVITE/mensagens — resolve destino via cache/API',
    'route[RELAY]':             'Relay genérico — encaminha a transação SIP ao destino.',
    'onreply_route[REPLY_REGISTER]': 'Processa respostas de REGISTER do backend',
    'failure_route[FAIL_REGISTER]':  'Trata falhas no REGISTER',
    'event_route[xhttp:request]':    'Handshake WebSocket para WebRTC',
  };

  const icons = {
    'request_route':            '&#9654;',
    'route[REGISTRAR]':         '&#9998;',
    'route[FORWARD_REGISTER]':  '&#10132;',
    'route[ROUTE_TO_BACKEND]':  '&#8644;',
    'route[RELAY]':             '&#8674;',
    'onreply_route[REPLY_REGISTER]': '&#8617;',
    'failure_route[FAIL_REGISTER]':  '&#10008;',
    'event_route[xhttp:request]':    '&#9881;',
  };

  el.innerHTML = routeBlocks.map((b, i) => {
    const desc = descriptions[b.name] || 'Bloco de roteamento Kamailio';
    const icon = icons[b.name] || '&#10148;';
    const lines = b.body.split('\n').length;
    return `
      <div class="route-block-card" id="block-card-${i}">
        <div class="route-block-header" onclick="toggleBlockView(${i})">
          <div class="route-block-info">
            <span class="route-block-icon">${icon}</span>
            <div>
              <div class="route-block-name">${escHtml(b.name)}</div>
              <div class="route-block-desc">${escHtml(desc)}</div>
            </div>
          </div>
          <div class="route-block-meta">
            <span class="badge badge-blue">${lines} linhas</span>
            <span class="route-block-chevron" id="chevron-${i}">&#9660;</span>
          </div>
        </div>
        <div class="route-block-body" id="block-body-${i}" style="display:none">
          <div class="route-block-actions">
            <button class="btn btn-sm btn-outline" onclick="editRouteBlock(${i})">&#9998; Editar</button>
            <button class="btn btn-sm btn-outline" onclick="copyBlockCode(${i})">&#9112; Copiar</button>
          </div>
          <pre class="route-block-code"><code>${escHtml(b.body)}</code></pre>
        </div>
      </div>
    `;
  }).join('');
}

function toggleBlockView(idx) {
  const body = document.getElementById('block-body-' + idx);
  const chevron = document.getElementById('chevron-' + idx);
  if (!body) return;
  const visible = body.style.display !== 'none';
  body.style.display = visible ? 'none' : 'block';
  chevron.innerHTML = visible ? '&#9660;' : '&#9650;';
}

function copyBlockCode(idx) {
  const block = routeBlocks[idx];
  if (!block) return;
  const text = block.name + ' ' + block.body;
  navigator.clipboard.writeText(text).then(() => {
    toast('Codigo copiado!', 'success');
  }).catch(() => {
    toast('Não foi possível copiar.', 'error');
  });
}

function editRouteBlock(idx) {
  editingBlock = idx;
  const block = routeBlocks[idx];
  if (!block) return;

  showModal('Editar ' + block.name, `
    <div style="margin-bottom:12px">
      <div class="form-label">Bloco: <strong>${escHtml(block.name)}</strong></div>
      <div style="font-size:12px;color:var(--text3);margin-bottom:8px">
        O nome do bloco não pode ser alterado. Edite apenas o corpo (incluindo as chaves).
      </div>
    </div>
    <textarea id="block-edit-textarea" rows="20"
      style="font-family:monospace;font-size:12px;width:100%;background:var(--bg1);color:var(--text1);border:1px solid var(--border);border-radius:6px;padding:12px;tab-size:4"
    >${escHtml(block.body)}</textarea>
    <div id="block-edit-status" style="margin-top:8px"></div>
  `, null);

  // Replace modal confirm button behavior
  const confirmBtn = document.getElementById('modal-confirm-btn');
  confirmBtn.textContent = 'Salvar';
  confirmBtn.onclick = async () => {
    await saveRouteBlock(idx);
  };

  // Enable tab in textarea
  setTimeout(() => {
    const ta = document.getElementById('block-edit-textarea');
    if (ta) {
      ta.addEventListener('keydown', function(e) {
        if (e.key === 'Tab') {
          e.preventDefault();
          const start = this.selectionStart;
          const end = this.selectionEnd;
          this.value = this.value.substring(0, start) + '    ' + this.value.substring(end);
          this.selectionStart = this.selectionEnd = start + 4;
        }
      });
    }
  }, 100);
}

async function saveRouteBlock(idx) {
  const block = routeBlocks[idx];
  const textarea = document.getElementById('block-edit-textarea');
  const statusEl = document.getElementById('block-edit-status');
  if (!block || !textarea) return;

  const newBody = textarea.value;
  statusEl.innerHTML = '<div class="loader" style="display:inline-block;width:16px;height:16px"></div> Validando e salvando...';

  try {
    const r = await apiFetch('/api/config/route-blocks/' + encodeURIComponent(block.name), {
      method: 'PUT',
      body: JSON.stringify({ body: newBody }),
    });
    toast('Bloco ' + block.name + ' salvo! Backup: ' + (r.backup || ''), 'success');
    closeModal();
    // Reload blocks
    await loadRouteBlocks();
    renderRouteBlocks();
  } catch(e) {
    const msg = e.message || 'Erro desconhecido';
    statusEl.innerHTML = '<div class="alert alert-error" style="margin:0">' + escHtml(msg) + '</div>';
    toast('Erro ao salvar: ' + msg, 'error');
  }
}


// ── SIP CAPTURE ──────────────────────────────────────────────────────
async function renderSipCapture(el) {
  captureLastIndex = 0;

  el.innerHTML = `
    <div class="card">
      <div class="card-title">🖥 Configuração LXD</div>
      <div id="lxd-config-form">
        <div class="form-row">
          <div class="form-group">
            <label>Host</label>
            <input type="text" id="lxd-host" placeholder="IP do servidor LXD" />
          </div>
          <div class="form-group">
            <label>Porta SSH</label>
            <input type="number" id="lxd-port" value="22" />
          </div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>Usuário</label>
            <input type="text" id="lxd-user" value="root" />
          </div>
          <div class="form-group">
            <label>Senha</label>
            <input type="password" id="lxd-pass" placeholder="Senha SSH" />
          </div>
        </div>
        <div class="btn-group" style="margin-top:8px">
          <button class="btn btn-outline" onclick="saveLxdConfig()">💾 Salvar</button>
          <button class="btn btn-outline" onclick="testLxdConnection()">🔌 Testar Conexão</button>
          <button class="btn btn-success" onclick="loadContainers()">↺ Carregar Containers</button>
        </div>
        <div id="lxd-status" style="margin-top:8px"></div>
      </div>
    </div>

    <div class="card">
      <div class="card-title">📦 Containers</div>
      <div id="containers-list">
        <div class="loading-state">Clique em "Carregar Containers" acima</div>
      </div>
    </div>

    <div class="card">
      <div class="card-title">
        📡 Captura SIP
        <span id="capture-badge" style="display:none;margin-left:8px;padding:2px 10px;border-radius:12px;background:#e74c3c;color:#fff;font-size:12px;animation:pulse 1s infinite">● CAPTURANDO</span>
      </div>
      <div class="btn-group" style="margin-bottom:10px">
        <button class="btn btn-danger" id="btn-stop-capture" onclick="stopCapture()" style="display:none">⏹ Parar Captura</button>
        <button class="btn btn-outline" onclick="clearCapture()">🗑 Limpar</button>
        <span style="margin-left:16px;color:#888" id="capture-count">0 pacotes</span>
      </div>
      <div style="margin-bottom:10px">
        <input type="text" id="capture-filter" placeholder="Filtrar: método, IP, Call-ID..." style="width:100%;max-width:400px" oninput="filterCaptureTable()" />
      </div>
      <div style="overflow-x:auto;">
        <table class="data-table" id="capture-table">
          <thead>
            <tr>
              <th style="width:90px">Hora</th>
              <th style="width:160px">Origem</th>
              <th style="width:30px">→</th>
              <th style="width:160px">Destino</th>
              <th style="width:120px">Método</th>
              <th>From</th>
              <th>To</th>
              <th style="width:200px">Call-ID</th>
            </tr>
          </thead>
          <tbody id="capture-tbody">
            <tr><td colspan="8" style="text-align:center;color:#888;padding:20px">Selecione um container e inicie a captura</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <style>
      @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.5} }
      .data-table { width:100%; border-collapse:collapse; font-size:13px; font-family:monospace; }
      .data-table th { background:#1a1a2e; color:#aaa; padding:6px 8px; text-align:left; font-weight:500; border-bottom:1px solid #2a2a3e; }
      .data-table td { padding:5px 8px; border-bottom:1px solid #1a1a2e; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:200px; }
      .data-table tr:hover { background:rgba(255,255,255,0.03); }
      .data-table tr.sip-invite td { color:#4fc3f7; }
      .data-table tr.sip-register td { color:#81c784; }
      .data-table tr.sip-bye td { color:#ffb74d; }
      .data-table tr.sip-error td { color:#e57373; }
      .data-table tr.sip-options td { color:#666; }
      .container-card { display:flex; align-items:center; justify-content:space-between; padding:10px 14px; background:#1a1a2e; border-radius:8px; margin-bottom:6px; }
      .container-card .c-name { font-weight:600; font-family:monospace; }
      .container-card .c-status { font-size:12px; padding:2px 8px; border-radius:10px; }
      .container-card .c-status.running { background:#27ae6022; color:#2ecc71; }
      .container-card .c-status.stopped { background:#e74c3c22; color:#e74c3c; }
      .container-card .c-ips { color:#888; font-size:12px; margin-left:12px; }
    </style>
  `;

  // Load LXD config
  try {
    const cfg = await apiFetch('/api/lxd/config');
    if (cfg.host) document.getElementById('lxd-host').value = cfg.host;
    if (cfg.port) document.getElementById('lxd-port').value = cfg.port;
    if (cfg.user) document.getElementById('lxd-user').value = cfg.user;
    if (cfg.password) document.getElementById('lxd-pass').value = cfg.password;
  } catch(e) {}

  // Check if capture is active
  try {
    const st = await apiFetch('/api/sip-capture/status');
    if (st.active) {
      document.getElementById('capture-badge').style.display = 'inline';
      document.getElementById('btn-stop-capture').style.display = '';
      startCapturePolling();
    }
  } catch(e) {}
}

async function saveLxdConfig() {
  try {
    await apiPost('/api/lxd/config', {
      host: document.getElementById('lxd-host').value,
      port: parseInt(document.getElementById('lxd-port').value),
      user: document.getElementById('lxd-user').value,
      password: document.getElementById('lxd-pass').value
    });
    toast('Configuração LXD salva!', 'success');
  } catch(e) {
    toast('Erro: ' + e.message, 'error');
  }
}

async function testLxdConnection() {
  const el = document.getElementById('lxd-status');
  el.innerHTML = '<span style="color:#aaa">Testando conexão...</span>';
  try {
    // Save first
    await saveLxdConfig();
    const r = await apiPost('/api/lxd/test', {});
    if (r.ok) {
      el.innerHTML = `<span style="color:#2ecc71">✓ Conectado! ${r.containers} containers encontrados</span>`;
    } else {
      el.innerHTML = `<span style="color:#e74c3c">✗ Falha: ${r.error}</span>`;
    }
  } catch(e) {
    el.innerHTML = `<span style="color:#e74c3c">✗ Erro: ${e.message}</span>`;
  }
}

async function loadContainers() {
  const el = document.getElementById('containers-list');
  el.innerHTML = '<div class="loading-state"><div class="loader"></div></div>';
  try {
    const r = await apiFetch('/api/lxd/containers');
    if (!r.containers || r.containers.length === 0) {
      el.innerHTML = '<div style="color:#888;padding:10px">Nenhum container encontrado</div>';
      return;
    }
    let html = '';
    for (const c of r.containers) {
      const statusClass = c.status === 'RUNNING' ? 'running' : 'stopped';
      const canCapture = c.status === 'RUNNING';
      html += `
        <div class="container-card">
          <div style="display:flex;align-items:center;gap:12px">
            <span class="c-name">${c.name}</span>
            <span class="c-status ${statusClass}">${c.status}</span>
            <span class="c-ips">${c.ip_display}</span>
          </div>
          ${canCapture ? `<button class="btn btn-sm btn-outline" onclick="startCapture('${c.name}')">📡 Capturar</button>` : '<span style="color:#666;font-size:12px">Offline</span>'}
        </div>`;
    }
    el.innerHTML = html;
  } catch(e) {
    el.innerHTML = `<div class="alert alert-error">Erro: ${e.message}</div>`;
  }
}

async function startCapture(container) {
  try {
    await apiPost('/api/sip-capture/start', { container });
    toast(`Captura iniciada em ${container}`, 'success');
    document.getElementById('capture-badge').style.display = 'inline';
    document.getElementById('btn-stop-capture').style.display = '';
    document.getElementById('capture-tbody').innerHTML = '';
    captureLastIndex = 0;
    startCapturePolling();
  } catch(e) {
    toast('Erro: ' + e.message, 'error');
  }
}

async function stopCapture() {
  try {
    await apiPost('/api/sip-capture/stop', {});
    toast('Captura parada', 'success');
  } catch(e) {}
  document.getElementById('capture-badge').style.display = 'none';
  document.getElementById('btn-stop-capture').style.display = 'none';
  if (captureInterval) { clearInterval(captureInterval); captureInterval = null; }
}

async function clearCapture() {
  try { await apiPost('/api/sip-capture/clear', {}); } catch(e) {}
  document.getElementById('capture-tbody').innerHTML = '<tr><td colspan="8" style="text-align:center;color:#888;padding:20px">Sem pacotes</td></tr>';
  document.getElementById('capture-count').textContent = '0 pacotes';
  captureLastIndex = 0;
}

function startCapturePolling() {
  if (captureInterval) clearInterval(captureInterval);
  captureInterval = setInterval(pollCaptureData, 1000);
  pollCaptureData();
}

async function pollCaptureData() {
  try {
    const r = await apiFetch(`/api/sip-capture/data?since=${captureLastIndex}`);
    document.getElementById('capture-count').textContent = `${r.total} pacotes`;

    if (!r.active) {
      document.getElementById('capture-badge').style.display = 'none';
      document.getElementById('btn-stop-capture').style.display = 'none';
      if (captureInterval && !r.active) { clearInterval(captureInterval); captureInterval = null; }
    }

    if (r.packets && r.packets.length > 0) {
      const tbody = document.getElementById('capture-tbody');
      // Remove placeholder
      if (tbody.querySelector('td[colspan]')) tbody.innerHTML = '';

      for (const p of r.packets) {
        const tr = document.createElement('tr');
        // Color code by method
        const method = (p.method || '').toUpperCase();
        if (method.includes('INVITE')) tr.className = 'sip-invite';
        else if (method.includes('REGISTER')) tr.className = 'sip-register';
        else if (method.includes('BYE') || method.includes('CANCEL')) tr.className = 'sip-bye';
        else if (method.startsWith('4') || method.startsWith('5')) tr.className = 'sip-error';
        else if (method.includes('OPTIONS')) tr.className = 'sip-options';

        tr.innerHTML = `
          <td>${p.time || ''}</td>
          <td title="${p.src}">${p.src || ''}</td>
          <td style="color:#555">→</td>
          <td title="${p.dst}">${p.dst || ''}</td>
          <td><strong>${p.method || ''}</strong></td>
          <td>${p.from_user || ''}</td>
          <td>${p.to_user || ''}</td>
          <td title="${p.call_id}" style="font-size:11px">${p.call_id || ''}</td>
        `;
        tbody.appendChild(tr);
      }

      // Auto scroll
      const table = document.getElementById('capture-table');
      table.parentElement.scrollTop = table.parentElement.scrollHeight;

      captureLastIndex = r.total;
    }
  } catch(e) {}
}

function filterCaptureTable() {
  const filter = document.getElementById('capture-filter').value.toLowerCase();
  const rows = document.querySelectorAll('#capture-tbody tr');
  rows.forEach(row => {
    if (!filter) { row.style.display = ''; return; }
    const text = row.textContent.toLowerCase();
    row.style.display = text.includes(filter) ? '' : 'none';
  });
}


// ── DOCUMENTACAO ─────────────────────────────────────────────────────
async function renderDocs(el) {
  el.innerHTML = '<div class="loading-state"><div class="loader"></div></div>';
  try {
    const r = await apiFetch('/api/docs');
    const md = r.content || '';
    let html = '';
    if (typeof marked !== 'undefined' && marked.parse) {
      marked.setOptions({ gfm: true, breaks: true });
      html = marked.parse(md);
    } else {
      // Fallback simples sem marked.js
      html = md
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/```([\s\S]*?)```/g, '<pre style="background:#0d1117;padding:12px;border-radius:6px;overflow-x:auto;font-size:12px;color:#c9d1d9;border:1px solid #21262d">$1</pre>')
        .replace(/`([^`]+)`/g, '<code style="background:rgba(110,118,129,0.2);padding:2px 6px;border-radius:3px;font-size:12px;color:#f0883e">$1</code>')
        .replace(/^#### (.+)$/gm, '<h4 style="color:#ffb74d;margin:15px 0 8px">$1</h4>')
        .replace(/^### (.+)$/gm, '<h3 style="color:#81c784;margin:20px 0 10px">$1</h3>')
        .replace(/^## (.+)$/gm, '<h2 style="color:#4fc3f7;font-size:20px;margin:25px 0 12px;border-bottom:1px solid rgba(255,255,255,0.1);padding-bottom:8px">$1</h2>')
        .replace(/^# (.+)$/gm, '<h1 style="color:#fff;font-size:24px;margin:30px 0 15px;border-bottom:1px solid rgba(255,255,255,0.1);padding-bottom:8px">$1</h1>')
        .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
        .replace(/^---$/gm, '<hr style="border:none;border-top:1px solid rgba(255,255,255,0.1);margin:20px 0">')
        .replace(/\n/g, '<br>');
    }
    el.innerHTML = `
      <div class="card" style="max-height:calc(100vh - 120px);overflow-y:auto">
        <div style="font-size:14px;line-height:1.7;color:#ccc">${html}</div>
      </div>`;
  } catch(e) {
    el.innerHTML = '<div class="alert alert-error">Erro: ' + e.message + '</div>';
  }
}


// ── SERVIDORES LXD ───────────────────────────────────────────────────
async function renderLxdServers(el) {
  el.innerHTML = '<div class="card">'
    + '<div class="card-title" style="display:flex;justify-content:space-between;align-items:center">'
    + '<span>&#9741; Servidores LXD</span>'
    + '<button class="btn btn-success btn-sm" onclick="showAddLxdServer()">+ Adicionar</button>'
    + '</div>'
    + '<div id="lxd-servers-list"><div class="loading-state"><div class="loader"></div></div></div>'
    + '</div>'
    + '<div class="card">'
    + '<div class="card-title" style="display:flex;justify-content:space-between;align-items:center">'
    + '<span>&#127760; Mapeamento IP (Privado &rarr; P&uacute;blico)</span>'
    + '<button class="btn btn-outline btn-sm" onclick="refreshIpMapping()">&#8634; Sincronizar</button>'
    + '</div>'
    + '<div id="ip-mapping-info" style="margin-bottom:10px;color:#888;font-size:12px"></div>'
    + '<div id="ip-mapping-table"></div>'
    + '</div>'
    + '<div id="lxd-modal" style="display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.6);z-index:1000;align-items:center;justify-content:center">'
    + '<div style="background:#1a1a2e;border-radius:12px;padding:24px;width:450px;max-width:90vw">'
    + '<h3 id="lxd-modal-title" style="margin:0 0 16px;color:#fff">Adicionar Servidor LXD</h3>'
    + '<div class="form-group"><label>Nome</label><input type="text" id="lxd-srv-name" placeholder="Ex: LXD-03"></div>'
    + '<div class="form-group"><label>Host (IP)</label><input type="text" id="lxd-srv-host" placeholder="{{PROXY_IP}}"></div>'
    + '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">'
    + '<div class="form-group"><label>Porta SSH</label><input type="number" id="lxd-srv-port" value="22"></div>'
    + '<div class="form-group"><label>Usu\u00e1rio</label><input type="text" id="lxd-srv-user" value="root"></div>'
    + '</div>'
    + '<div class="form-group"><label>Senha</label><input type="password" id="lxd-srv-pass" placeholder="Senha SSH"></div>'
    + '<div class="btn-group" style="margin-top:12px">'
    + '<button class="btn btn-success" onclick="saveLxdServer()">Salvar</button>'
    + '<button class="btn btn-outline" onclick="closeLxdModal()">Cancelar</button>'
    + '</div></div></div>';
  loadLxdServers();
  loadIpMapping();
}

var _lxdEditIdx = -1;

function showAddLxdServer() {
  _lxdEditIdx = -1;
  document.getElementById('lxd-modal-title').textContent = 'Adicionar Servidor LXD';
  document.getElementById('lxd-srv-name').value = '';
  document.getElementById('lxd-srv-host').value = '';
  document.getElementById('lxd-srv-port').value = '22';
  document.getElementById('lxd-srv-user').value = 'root';
  document.getElementById('lxd-srv-pass').value = '';
  document.getElementById('lxd-modal').style.display = 'flex';
}

function showEditLxdServer(idx, name, host, port, user) {
  _lxdEditIdx = idx;
  document.getElementById('lxd-modal-title').textContent = 'Editar ' + name;
  document.getElementById('lxd-srv-name').value = name;
  document.getElementById('lxd-srv-host').value = host;
  document.getElementById('lxd-srv-port').value = port;
  document.getElementById('lxd-srv-user').value = user;
  document.getElementById('lxd-srv-pass').value = '';
  document.getElementById('lxd-modal').style.display = 'flex';
}

function closeLxdModal() { document.getElementById('lxd-modal').style.display = 'none'; }

async function saveLxdServer() {
  var data = {
    name: document.getElementById('lxd-srv-name').value,
    host: document.getElementById('lxd-srv-host').value,
    port: parseInt(document.getElementById('lxd-srv-port').value),
    user: document.getElementById('lxd-srv-user').value,
    password: document.getElementById('lxd-srv-pass').value,
    enabled: true
  };
  try {
    if (_lxdEditIdx >= 0) {
      await apiFetch('/api/lxd-servers/' + _lxdEditIdx, {method:'PUT', body:JSON.stringify(data)});
    } else {
      await apiPost('/api/lxd-servers', data);
    }
    closeLxdModal();
    loadLxdServers();
    toast('Servidor salvo!', 'success');
  } catch(e) { toast('Erro: ' + e.message, 'error'); }
}

async function deleteLxdServer(idx) {
  if (!confirm('Remover este servidor?')) return;
  try {
    await apiFetch('/api/lxd-servers/' + idx, {method:'DELETE'});
    loadLxdServers();
    toast('Removido com sucesso.', 'success');
  } catch(e) { toast('Erro: ' + e.message, 'error'); }
}

async function testLxdServer(idx) {
  try {
    var r = await apiPost('/api/lxd-servers/' + idx + '/test', {});
    if (r.ok) toast('Conectado! ' + r.containers + ' containers', 'success');
    else toast('Falha: ' + r.error, 'error');
  } catch(e) { toast('Erro: ' + e.message, 'error'); }
}

async function loadLxdServers() {
  var el = document.getElementById('lxd-servers-list');
  try {
    var r = await apiFetch('/api/lxd-servers');
    if (!r.servers || r.servers.length === 0) {
      el.innerHTML = '<div style="color:#888;padding:10px">Nenhum servidor LXD configurado</div>';
      return;
    }
    var html = '<table class="data-table"><thead><tr><th>Nome</th><th>Host</th><th>Porta</th><th>Status</th><th>Ações</th></tr></thead><tbody>';
    r.servers.forEach(function(s, i) {
      var safeName = (s.name || s.host).replace(/'/g, '');
      html += '<tr><td><strong>' + safeName + '</strong></td>'
        + '<td style="font-family:monospace">' + s.host + '</td>'
        + '<td>' + s.port + '</td>'
        + '<td>' + (s.enabled ? '<span style="color:#2ecc71">Ativo</span>' : '<span style="color:#888">Inativo</span>') + '</td>'
        + '<td><div class="btn-group">'
        + '<button class="btn btn-sm btn-outline" onclick="testLxdServer(' + i + ')">Testar</button>'
        + '<button class="btn btn-sm btn-outline" onclick="showEditLxdServer(' + i + ',\'' + safeName + '\',\'' + s.host + '\',' + s.port + ',\'' + s.user + '\')">Editar</button>'
        + '<button class="btn btn-sm btn-danger" onclick="deleteLxdServer(' + i + ')">x</button>'
        + '</div></td></tr>';
    });
    html += '</tbody></table>';
    el.innerHTML = html;
  } catch(e) { el.innerHTML = '<div class="alert alert-error">' + e.message + '</div>'; }
}

async function loadIpMapping() {
  var el = document.getElementById('ip-mapping-table');
  var info = document.getElementById('ip-mapping-info');
  try {
    var r = await apiFetch('/api/lxd/ip-mapping');
    var age = r.age < 60 ? r.age + 's' : Math.round(r.age/60) + 'min';
    info.textContent = r.count + ' mapeamentos | Cache: ' + age;
    if (!r.mapping || Object.keys(r.mapping).length === 0) {
      el.innerHTML = '<div style="color:#888">Nenhum mapeamento. Clique "Sincronizar" para buscar dos LXDs.</div>';
      return;
    }
    var html = '<table class="data-table"><thead><tr><th>IP Privado</th><th></th><th>IP Publico</th></tr></thead><tbody>';
    for (var priv in r.mapping) {
      html += '<tr><td style="font-family:monospace">' + priv + '</td><td style="color:#555">&rarr;</td><td style="font-family:monospace;color:#2ecc71">' + r.mapping[priv] + '</td></tr>';
    }
    html += '</tbody></table>';
    el.innerHTML = html;
  } catch(e) { el.innerHTML = ''; }
}

async function refreshIpMapping() {
  document.getElementById('ip-mapping-table').innerHTML = '<div class="loading-state"><div class="loader"></div></div>';
  try {
    await apiPost('/api/lxd/ip-mapping/refresh', {});
    loadIpMapping();
    toast('Mapeamento atualizado!', 'success');
  } catch(e) { toast('Erro: ' + e.message, 'error'); }
}


// ── CACHE DE RAMAIS ──────────────────────────────────────────────────
async function renderRoutingCache(el) {
  el.innerHTML = '<div class="card">'
    + '<div class="card-title" style="display:flex;justify-content:space-between;align-items:center">'
    + '<span>&#128269; Registro de Ramais</span>'
    + '<div class="btn-group">'
    + '<button class="btn btn-outline btn-sm" onclick="loadRoutingCache()">&#8634; Atualizar</button>'
    + '<button class="btn btn-danger btn-sm" onclick="flushRoutingCache()">&#128465; Limpar Tudo</button>'
    + '</div></div>'
    + '<div style="margin-bottom:10px;color:#888;font-size:12px" id="cache-info"></div>'
    + '<div style="margin-bottom:10px"><input type="text" id="cache-filter" placeholder="Filtrar ramal..." style="width:100%;max-width:300px;padding:8px 12px;background:#0f1419;border:1px solid #2d3748;border-radius:6px;color:#e2e8f0" oninput="filterCacheTable()"></div>'
    + '<div id="cache-table-wrapper" style="overflow-x:auto"></div>'
    + '</div>';
  loadRoutingCache();
}

async function loadRoutingCache() {
  var wrap = document.getElementById('cache-table-wrapper');
  var info = document.getElementById('cache-info');
  if (!wrap) return;
  wrap.innerHTML = '<div class="loading-state"><div class="loader"></div></div>';
  try {
    var r = await apiFetch('/api/routing-cache');
    info.textContent = r.count + ' ramais registrados';
    if (!r.entries || r.entries.length === 0) {
      wrap.innerHTML = '<div style="color:#888;padding:20px;text-align:center">Nenhum registro</div>';
      return;
    }
    var html = '<table class="data-table" id="cache-data-table"><thead><tr>'
      + '<th>Ramal</th>'
      + '<th>IP Container (Privado)</th>'
      + '<th>IP Publico</th>'
      + '<th>Registrado em</th>'
      + '<th>Ha quanto tempo</th>'
      + '<th style="width:100px">Ações</th>'
      + '</tr></thead><tbody>';
    var nowTs = Math.floor(Date.now() / 1000);
    r.entries.forEach(function(e) {
      var pubIp = e.public_ip ? e.public_ip : '<span style="color:#888">-</span>';
      var safeName = (e.name || '').replace(/'/g, '');
      var regAt = e.registered_at ? e.registered_at : '<span style="color:#888">-</span>';
      var ago = '<span style="color:#888">-</span>';
      if (e.registered_at_ts) {
        var diff = nowTs - e.registered_at_ts;
        var ageColor = '#48bb78';
        if (diff > 600) ageColor = '#ecc94b';
        if (diff > 1800) ageColor = '#f56565';
        if (diff < 60) ago = diff + 's';
        else if (diff < 3600) ago = Math.floor(diff / 60) + ' min';
        else ago = Math.floor(diff / 3600) + 'h ' + Math.floor((diff % 3600) / 60) + 'min';
        ago = '<span style="color:' + ageColor + ';font-weight:600">' + ago + '</span>';
      }
      html += '<tr>'
        + '<td><strong>' + safeName + '</strong></td>'
        + '<td style="font-family:monospace">' + (e.value || '') + '</td>'
        + '<td style="font-family:monospace;color:#48bb78">' + pubIp + '</td>'
        + '<td style="font-family:monospace;font-size:12px">' + regAt + '</td>'
        + '<td style="font-family:monospace;font-size:12px">' + ago + '</td>'
        + '<td><button class="btn btn-sm btn-danger" onclick="deleteCacheEntry(\'' + safeName + '\')">x Limpar</button></td>'
        + '</tr>';
    });
    html += '</tbody></table>';
    wrap.innerHTML = html;
  } catch(e) {
    wrap.innerHTML = '<div class="alert alert-error">Erro: ' + e.message + '</div>';
  }
}

function filterCacheTable() {
  var filter = document.getElementById('cache-filter').value.toLowerCase();
  var rows = document.querySelectorAll('#cache-data-table tbody tr');
  rows.forEach(function(row) {
    var text = row.textContent.toLowerCase();
    row.style.display = (!filter || text.indexOf(filter) !== -1) ? '' : 'none';
  });
}

async function deleteCacheEntry(name) {
  if (!confirm('Remover registro de "' + name + '"?')) return;
  try {
    var r = await apiFetch('/api/routing-cache/' + encodeURIComponent(name), {method:'DELETE'});
    if (r.ok) {
      toast('Cache de ' + name + ' removido!', 'success');
      loadRoutingCache();
    } else {
      toast('Erro: ' + (r.output || 'falha'), 'error');
    }
  } catch(e) { toast('Erro: ' + e.message, 'error'); }
}

async function flushRoutingCache() {
  if (!confirm('Limpar TODOS os registros de ramais?')) return;
  try {
    var r = await apiPost('/api/routing-cache/flush', {});
    if (r.ok) {
      toast('Cache limpo!', 'success');
      loadRoutingCache();
    } else {
      toast('Erro: ' + (r.output || 'falha'), 'error');
    }
  } catch(e) { toast('Erro: ' + e.message, 'error'); }
}
