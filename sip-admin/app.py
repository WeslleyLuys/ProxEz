#!/usr/bin/env python3
"""
SIP Proxy Admin Panel - Backend Flask
Painel de administracao para Kamailio SIP Proxy
"""

import os
import time
import re
import json
import hashlib
import subprocess
import tempfile
from datetime import datetime
import threading
from functools import wraps
from flask import (Flask, request, jsonify, render_template,
                   send_from_directory, session, redirect, url_for)
from werkzeug.utils import secure_filename

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.secret_key = os.environ.get('SECRET_KEY', 'CHANGE-ME')

KAMAILIO_CFG = '/etc/kamailio/kamailio.cfg'
CERT_DIR = '/etc/kamailio/certs'
LOG_FILE = '/var/log/syslog'
AUTH_FILE = '/etc/kamailio/admin-auth.json'
LXD_CONFIG_FILE = '/etc/kamailio/lxd-config.json'
LXD_SERVERS_FILE = '/etc/kamailio/lxd-servers.json'
WHITELIST_FILE = '/etc/kamailio/whitelist.json'
F2B_DEFAULTS_FILE = '/etc/fail2ban/jail.d/00-defaults.conf'

# Entradas fixas que sempre fazem parte da whitelist (loopback)
WHITELIST_FIXED = ['127.0.0.1/8', '::1']

# ─── Whitelist Storage (JSON com comentarios) ────────────────────────────────

def _parse_legacy_ignoreip():
    """Le a whitelist atual de /etc/fail2ban/jail.d/00-defaults.conf
    e retorna lista de entries [{'ip': str, 'name': ''}]."""
    entries = []
    try:
        with open(F2B_DEFAULTS_FILE) as f:
            content = f.read()
        m = re.search(r'^ignoreip\s*=\s*(.+)$', content, re.MULTILINE)
        if m:
            for ip in m.group(1).split():
                ip = ip.strip()
                if ip and ip not in WHITELIST_FIXED:
                    entries.append({'ip': ip, 'name': ''})
    except Exception:
        pass
    return entries

def _normalize_entry(e):
    """Normaliza uma entry para o schema atual {type, ip, name, hostname, resolved_at}.
    Backward-compat: entradas antigas sem 'type' viram type='ip'."""
    if not isinstance(e, dict):
        return None
    etype = str(e.get('type', '')).strip().lower()
    ip = str(e.get('ip', '')).strip()
    name = str(e.get('name', '')).strip()
    hostname = str(e.get('hostname', '')).strip()
    resolved_at = str(e.get('resolved_at', '')).strip()
    if etype not in ('ip', 'ddns'):
        # Sem type: infere pelo conteudo
        etype = 'ddns' if hostname else 'ip'
    if etype == 'ddns':
        if not hostname:
            return None
        return {'type': 'ddns', 'hostname': hostname, 'name': name,
                'ip': ip, 'resolved_at': resolved_at}
    # type=ip
    if not ip:
        return None
    return {'type': 'ip', 'ip': ip, 'name': name}

def load_whitelist_entries():
    """Carrega whitelist do arquivo JSON. Se nao existir, migra do
    arquivo legado (00-defaults.conf) e cria o JSON inicial."""
    if not os.path.exists(WHITELIST_FILE):
        entries = _parse_legacy_ignoreip()
        save_whitelist_entries(entries)
        return entries
    try:
        with open(WHITELIST_FILE) as f:
            data = json.load(f)
        if isinstance(data, list):
            out = []
            for e in data:
                ne = _normalize_entry(e)
                if ne:
                    out.append(ne)
            return out
        return []
    except Exception:
        return []

def save_whitelist_entries(entries):
    """Salva entries na whitelist JSON e regenera 00-defaults.conf.
    Remove duplicatas (por IP para type=ip, por hostname para type=ddns)."""
    seen_ips = set()
    seen_hosts = set()
    clean = []
    for e in entries:
        ne = _normalize_entry(e)
        if not ne:
            continue
        if ne['type'] == 'ddns':
            key = ne['hostname'].lower()
            if key in seen_hosts:
                continue
            seen_hosts.add(key)
        else:
            key = ne['ip']
            if key in seen_ips:
                continue
            seen_ips.add(key)
        clean.append(ne)
    with open(WHITELIST_FILE, 'w') as f:
        json.dump(clean, f, indent=2, ensure_ascii=False)
    os.chmod(WHITELIST_FILE, 0o644)
    _regenerate_f2b_defaults(clean)
    return clean

def _regenerate_f2b_defaults(entries):
    """Reescreve /etc/fail2ban/jail.d/00-defaults.conf a partir das entries.
    Inclui IPs de type=ip e IPs ja resolvidos de type=ddns."""
    ips = list(WHITELIST_FIXED)
    for e in entries:
        if e.get('type') == 'ddns':
            ip = e.get('ip', '').strip()
            if ip:
                ips.append(ip)
        else:
            ip = e.get('ip', '').strip()
            if ip:
                ips.append(ip)
    ip_str = ' '.join(ips)
    conf = f"""[DEFAULT]
ignoreip = {ip_str}

[sshd]
enabled = false
"""
    with open(F2B_DEFAULTS_FILE, 'w') as f:
        f.write(conf)

def _validate_ip_or_cidr(value):
    """Valida formato IPv4/IPv6 com mascara opcional."""
    if not value:
        return False
    return bool(re.match(r'^[\d\.\:a-fA-F]+(/\d{1,3})?$', value))

def _validate_hostname(value):
    """Valida formato de hostname FQDN."""
    if not value or len(value) > 253:
        return False
    return bool(re.match(r'^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$', value))

def _resolve_hostname(hostname):
    """Resolve um hostname para IPv4. Retorna o IP ou None em caso de falha."""
    import socket
    try:
        # getaddrinfo respeita /etc/hosts e DNS, IPv4 only por enquanto
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
        if infos:
            return infos[0][4][0]
    except Exception:
        return None
    return None

def refresh_ddns_entries(entries=None):
    """Resolve todos os hostnames das entries DDNS e atualiza os IPs.
    Retorna {'changes': [...], 'unchanged': N, 'failed': [...]}."""
    from datetime import datetime
    if entries is None:
        entries = load_whitelist_entries()
    changes = []
    failed = []
    unchanged = 0
    for e in entries:
        if e.get('type') != 'ddns':
            continue
        host = e.get('hostname', '').strip()
        if not host:
            continue
        new_ip = _resolve_hostname(host)
        if not new_ip:
            failed.append(host)
            continue
        old_ip = e.get('ip', '').strip()
        if new_ip != old_ip:
            changes.append({'hostname': host, 'old_ip': old_ip, 'new_ip': new_ip})
            e['ip'] = new_ip
            e['resolved_at'] = datetime.now().isoformat(timespec='seconds')
        else:
            unchanged += 1
    if changes:
        save_whitelist_entries(entries)
        run_cmd('fail2ban-client reload 2>&1')
        for ch in changes:
            _unban_ip_all_jails(ch['new_ip'])
    return {'changes': changes, 'unchanged': unchanged, 'failed': failed}

def _unban_ip_all_jails(ip):
    """Desbane um IP de todas as jails (so funciona para IP unico, sem CIDR)."""
    if '/' in ip or not re.match(r'^[\d\.\:a-fA-F]+$', ip):
        return False
    _, _, rc = run_cmd(f'fail2ban-client unban {ip} 2>/dev/null')
    return rc == 0

# ─── Auth ────────────────────────────────────────────────────────────────────

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Mapa de permissoes por pagina -> rotas da API
PAGE_PERMISSIONS = {
    'dashboard': ['/api/status'],
    'config-geral': ['/api/config/general'],
    'api-backend': ['/api/config/api-backend'],
    'rotas': ['/api/routes'],
    'certificados': ['/api/cert'],
    'cache': ['/api/cache'],
    'webphone': [],
    'firewall': ['/api/fail2ban'],
    'monitor': ['/api/sip-monitor'],
    'logs': ['/api/logs'],
    'editor': ['/api/config/raw', '/api/config/route-blocks'],
    'backups': ['/api/backups'],
    'kamailio': ['/api/kamailio'],
    'routing-cache': ['/api/routing-cache'],
    'lxd-servers': ['/api/lxd-servers', '/api/lxd/ip-mapping'],
    'docs': ['/api/docs'],
    'sip-capture': ['/api/lxd', '/api/sip-capture'],
}

def load_users():
    if os.path.exists(AUTH_FILE):
        try:
            with open(AUTH_FILE) as f:
                data = json.load(f)
            if 'users' in data:
                return data['users']
            # Migrar formato antigo (usuario unico) para multi-usuario
            old_user = data.get('username', 'admin')
            return {old_user: {'password': data['password'], 'name': data.get('name', 'Administrador'), 'permissions': ['*']}}
        except Exception:
            pass
    return {'admin': {'password': hash_password('changeme'), 'name': 'Administrador', 'permissions': ['*']}}

def save_users(users):
    with open(AUTH_FILE, 'w') as f:
        json.dump({'users': users}, f, indent=2)
    os.chmod(AUTH_FILE, 0o600)

def load_auth():
    users = load_users()
    first = list(users.keys())[0]
    return {'username': first, 'password': users[first]['password'], 'name': users[first].get('name', first)}

def save_auth(username, password, name='Administrador'):
    users = load_users()
    if username in users:
        users[username]['password'] = hash_password(password)
        users[username]['name'] = name
    else:
        users[username] = {'password': hash_password(password), 'name': name, 'permissions': ['*']}
    save_users(users)

def check_permission(username, api_path):
    users = load_users()
    user = users.get(username, {})
    perms = user.get('permissions', [])
    if '*' in perms:
        return True
    for page, routes in PAGE_PERMISSIONS.items():
        if page in perms:
            for route in routes:
                if api_path.startswith(route):
                    return True
    return False

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Nao autenticado', 'redirect': '/login'}), 401
            return redirect('/login')
        # Verificar permissao por rota
        if request.path.startswith('/api/') and request.path not in ('/api/auth/me', '/api/auth/change-password', '/api/status'):
            if not check_permission(session.get('username', ''), request.path):
                return jsonify({'error': 'Sem permissao'}), 403
        return f(*args, **kwargs)
    return decorated

# ─── Helpers ─────────────────────────────────────────────────────────────────

def run_cmd(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return '', 'Timeout', 1
    except Exception as e:
        return '', str(e), 1

def read_cfg():
    try:
        with open(KAMAILIO_CFG, 'r') as f:
            return f.read()
    except Exception:
        return None

def write_cfg(content):
    try:
        backup = KAMAILIO_CFG + '.bak.' + datetime.now().strftime('%Y%m%d%H%M%S')
        with open(KAMAILIO_CFG, 'r') as f:
            orig = f.read()
        with open(backup, 'w') as f:
            f.write(orig)
        with open(KAMAILIO_CFG, 'w') as f:
            f.write(content)
        return True, backup
    except Exception as e:
        return False, str(e)

def parse_general_config(cfg):
    params = {}
    patterns = {
        'debug': r'^debug\s*=\s*(\d+)',
        'children': r'^children\s*=\s*(\d+)',
        'log_facility': r'^log_facility\s*=\s*(\S+)',
        'log_stderror': r'^log_stderror\s*=\s*(\S+)',
        'auto_aliases': r'^auto_aliases\s*=\s*(\S+)',
        'port': r'^port\s*=\s*(\d+)',
    }
    for key, pat in patterns.items():
        m = re.search(pat, cfg, re.MULTILINE)
        params[key] = m.group(1) if m else ''
    listens = re.findall(r'^listen\s*=\s*(\S+)', cfg, re.MULTILINE)
    params['listen'] = listens
    return params

def parse_api_config(cfg):
    params = {}
    m = re.search(r'modparam\("http_client",\s*"connection_timeout",\s*(\d+)\)', cfg)
    params['connection_timeout'] = m.group(1) if m else '2000'
    m = re.search(r'modparam\("http_client",\s*"httpcon",\s*"apiserver=>([^"]+)"\)', cfg)
    params['api_url'] = m.group(1) if m else ''
    return params

# ─── Auth Routes ─────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET'])
def login_page():
    if session.get('logged_in'):
        return redirect('/')
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    users = load_users()
    user = users.get(username)
    if user and hash_password(password) == user['password']:
        session['logged_in'] = True
        session['username'] = username
        session['name'] = user.get('name', username)
        session['permissions'] = user.get('permissions', [])
        session.permanent = True
        return jsonify({'ok': True})
    return jsonify({'ok': False, 'error': 'Usuario ou senha incorretos'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'ok': True})

@app.route('/api/auth/me')
@login_required
def auth_me():
    return jsonify({'username': session.get('username'), 'name': session.get('name'), 'permissions': session.get('permissions', ['*'])})

@app.route('/api/auth/change-password', methods=['POST'])
@login_required
def change_password():
    data = request.json or {}
    current = data.get('current', '')
    new_pass = data.get('new', '')
    confirm = data.get('confirm', '')
    users = load_users()
    username = session.get('username')
    user = users.get(username, {})
    if hash_password(current) != user.get('password', ''):
        return jsonify({'error': 'Senha atual incorreta'}), 400
    if len(new_pass) < 6:
        return jsonify({'error': 'Nova senha precisa ter ao menos 6 caracteres'}), 400
    if new_pass != confirm:
        return jsonify({'error': 'Confirmacao nao confere'}), 400
    save_auth(username, new_pass, user.get('name', 'Administrador'))
    return jsonify({'ok': True})

# ─── Main Routes ─────────────────────────────────────────────────────────────

@app.route('/')
@login_required
def index():
    return render_template('index.html')

# --- STATUS ---

@app.route('/api/status')
@login_required
def status():
    out, err, rc = run_cmd('systemctl is-active kamailio')
    running = (out == 'active')
    out2, _, _ = run_cmd('pgrep -c kamailio')
    pids = int(out2) if out2.isdigit() else 0
    out3, _, _ = run_cmd('systemctl show kamailio --property=ActiveEnterTimestamp --value')
    uptime_str = out3.strip() if out3 else 'N/A'
    out4, _, _ = run_cmd('kamailio -V 2>/dev/null | head -1')
    version = out4.strip() if out4 else 'N/A'
    out5, _, _ = run_cmd("ps aux | grep kamailio | grep -v grep | awk '{sum+=$6} END {print sum}'")
    mem_kb = int(out5) if out5 and out5.isdigit() else 0
    out6, _, _ = run_cmd('kamcmd htable.stats routing 2>/dev/null')
    cache_entries = 0
    m = re.search(r'size:\s*(\d+)', out6)
    if m:
        cache_entries = int(m.group(1))
    out7, _, _ = run_cmd('kamcmd tm.stats 2>/dev/null')
    current_tx = 0
    m = re.search(r'current:\s*(\d+)', out7)
    if m:
        current_tx = int(m.group(1))
    return jsonify({
        'running': running, 'pids': pids, 'uptime': uptime_str,
        'version': version, 'memory_mb': round(mem_kb / 1024, 1),
        'cache_entries': cache_entries, 'current_transactions': current_tx,
    })

# --- CONFIG GERAL ---

@app.route('/api/config/general', methods=['GET'])
@login_required
def get_general():
    cfg = read_cfg()
    if cfg is None:
        return jsonify({'error': 'Nao foi possivel ler kamailio.cfg'}), 500
    return jsonify(parse_general_config(cfg))

@app.route('/api/config/general', methods=['POST'])
@login_required
def save_general():
    data = request.json
    cfg = read_cfg()
    if cfg is None:
        return jsonify({'error': 'Nao foi possivel ler kamailio.cfg'}), 500
    simple_params = {
        'debug': r'(^debug\s*=\s*)\d+',
        'children': r'(^children\s*=\s*)\d+',
        'log_facility': r'(^log_facility\s*=\s*)\S+',
        'log_stderror': r'(^log_stderror\s*=\s*)\S+',
        'auto_aliases': r'(^auto_aliases\s*=\s*)\S+',
        'port': r'(^port\s*=\s*)\d+',
    }
    for key, pat in simple_params.items():
        if key in data and data[key] != '':
            cfg = re.sub(pat, r'\g<1>' + str(data[key]), cfg, flags=re.MULTILINE)
    if 'listen' in data and data['listen']:
        listens = data['listen']
        if isinstance(listens, str):
            listens = [l.strip() for l in listens.split('\n') if l.strip()]
        cfg = re.sub(r'^listen\s*=\s*\S+\n', '', cfg, flags=re.MULTILINE)
        new_listens = '\n'.join(f'listen={l}' for l in listens)
        cfg = re.sub(r'(port\s*=\s*\d+)', new_listens + '\n\n' + r'\1', cfg, count=1)
    ok, info = write_cfg(cfg)
    if not ok:
        return jsonify({'error': info}), 500
    return jsonify({'ok': True, 'backup': info})

# --- CONFIG API ---

@app.route('/api/config/api-backend', methods=['GET'])
@login_required
def get_api_backend():
    cfg = read_cfg()
    if cfg is None:
        return jsonify({'error': 'Nao foi possivel ler kamailio.cfg'}), 500
    return jsonify(parse_api_config(cfg))

@app.route('/api/config/api-backend', methods=['POST'])
@login_required
def save_api_backend():
    data = request.json
    cfg = read_cfg()
    if cfg is None:
        return jsonify({'error': 'Nao foi possivel ler kamailio.cfg'}), 500
    if 'api_url' in data and data['api_url']:
        cfg = re.sub(
            r'(modparam\("http_client",\s*"httpcon",\s*"apiserver=>)[^"]+(")',
            r'\g<1>' + data['api_url'] + r'\2', cfg
        )
    if 'connection_timeout' in data and data['connection_timeout']:
        cfg = re.sub(
            r'(modparam\("http_client",\s*"connection_timeout",\s*)\d+(\))',
            r'\g<1>' + str(data['connection_timeout']) + r'\2', cfg
        )
    ok, info = write_cfg(cfg)
    if not ok:
        return jsonify({'error': info}), 500
    return jsonify({'ok': True, 'backup': info})

@app.route('/api/config/api-backend/test', methods=['POST'])
@login_required
def test_api():
    data = request.json
    url = data.get('url', '')
    if not url:
        cfg = read_cfg() or ''
        m = re.search(r'httpcon",\s*"apiserver=>([^"]+)"', cfg)
        url = m.group(1) if m else ''
    if not url:
        return jsonify({'ok': False, 'error': 'URL nao configurada'})
    out, err, rc = run_cmd(f'curl -s --max-time 3 -o /dev/null -w "%{{http_code}}" {url}/', timeout=5)
    return jsonify({'ok': rc == 0, 'http_code': out, 'url': url, 'reachable': rc == 0})

# --- CONFIG RAW ---

@app.route('/api/config/raw', methods=['GET'])
@login_required
def get_raw():
    cfg = read_cfg()
    if cfg is None:
        return jsonify({'error': 'Nao foi possivel ler kamailio.cfg'}), 500
    return jsonify({'content': cfg})

@app.route('/api/config/raw', methods=['POST'])
@login_required
def save_raw():
    data = request.json
    content = data.get('content', '')
    if not content:
        return jsonify({'error': 'Conteudo vazio'}), 400
    with tempfile.NamedTemporaryFile(mode='w', suffix='.cfg', delete=False) as tf:
        tf.write(content)
        tmp_path = tf.name
    out, err, rc = run_cmd(f'kamailio -c -f {tmp_path} 2>&1')
    os.unlink(tmp_path)
    if rc != 0 and 'error' in (out + err).lower():
        return jsonify({'error': 'Erro de sintaxe: ' + (out or err)}), 400
    ok, info = write_cfg(content)
    if not ok:
        return jsonify({'error': info}), 500
    return jsonify({'ok': True, 'backup': info})

# --- CERTIFICADOS ---

@app.route('/api/cert', methods=['GET'])
@login_required
def get_cert():
    os.makedirs(CERT_DIR, exist_ok=True)
    cert_file = os.path.join(CERT_DIR, 'server.crt')
    key_file = os.path.join(CERT_DIR, 'server.key')
    result = {
        'cert_exists': os.path.exists(cert_file),
        'key_exists': os.path.exists(key_file),
        'cert_path': cert_file, 'key_path': key_file, 'cert_info': None
    }
    if result['cert_exists']:
        out, _, _ = run_cmd(f'openssl x509 -in {cert_file} -noout -subject -issuer -dates 2>/dev/null')
        result['cert_info'] = out
    return jsonify(result)

@app.route('/api/cert', methods=['POST'])
@login_required
def upload_cert():
    os.makedirs(CERT_DIR, exist_ok=True)
    saved = []
    if 'cert' in request.files:
        f = request.files['cert']
        if f.filename:
            f.save(os.path.join(CERT_DIR, 'server.crt'))
            saved.append('certificado')
    if 'key' in request.files:
        f = request.files['key']
        if f.filename:
            path = os.path.join(CERT_DIR, 'server.key')
            f.save(path); os.chmod(path, 0o600)
            saved.append('chave privada')
    if 'cert_text' in request.form and request.form['cert_text']:
        with open(os.path.join(CERT_DIR, 'server.crt'), 'w') as f:
            f.write(request.form['cert_text'])
        if 'certificado' not in saved: saved.append('certificado')
    if 'key_text' in request.form and request.form['key_text']:
        path = os.path.join(CERT_DIR, 'server.key')
        with open(path, 'w') as f: f.write(request.form['key_text'])
        os.chmod(path, 0o600)
        if 'chave privada' not in saved: saved.append('chave privada')
    if not saved:
        return jsonify({'error': 'Nenhum arquivo enviado'}), 400
    return jsonify({'ok': True, 'saved': saved})

@app.route('/api/cert/generate', methods=['POST'])
@login_required
def generate_cert():
    data = request.json or {}
    domain = data.get('domain', '{{DOMAIN}}')
    days = data.get('days', 3650)
    os.makedirs(CERT_DIR, exist_ok=True)
    cert_file = os.path.join(CERT_DIR, 'server.crt')
    key_file = os.path.join(CERT_DIR, 'server.key')
    cmd = (f'openssl req -x509 -newkey rsa:4096 -keyout {key_file} -out {cert_file} '
           f'-days {days} -nodes -subj "/CN={domain}/O=OmniSmart/C=BR" 2>&1')
    out, err, rc = run_cmd(cmd, timeout=30)
    if rc != 0:
        return jsonify({'error': err or out}), 500
    os.chmod(key_file, 0o600)
    return jsonify({'ok': True, 'cert': cert_file, 'key': key_file})

# --- KAMAILIO CONTROLE ---

@app.route('/api/kamailio/reload', methods=['POST'])
@login_required
def kamailio_reload():
    out, err, rc = run_cmd('kamcmd core.reload 2>&1 || kamailio -c -f /etc/kamailio/kamailio.cfg 2>&1 | head -5')
    if rc == 0:
        return jsonify({'ok': True, 'output': out})
    out2, err2, rc2 = run_cmd('systemctl reload kamailio 2>&1')
    return jsonify({'ok': rc2 == 0, 'output': out2 or err2})

@app.route('/api/kamailio/restart', methods=['POST'])
@login_required
def kamailio_restart():
    out, err, rc = run_cmd('systemctl restart kamailio 2>&1')
    return jsonify({'ok': rc == 0, 'output': out or err})

@app.route('/api/kamailio/syntax-check', methods=['POST'])
@login_required
def syntax_check():
    data = request.json or {}
    content = data.get('content', '')
    if content:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.cfg', delete=False) as tf:
            tf.write(content)
            tmp_path = tf.name
        out, err, rc = run_cmd(f'kamailio -c -f {tmp_path} 2>&1')
        os.unlink(tmp_path)
    else:
        out, err, rc = run_cmd('kamailio -c -f /etc/kamailio/kamailio.cfg 2>&1')
    combined = (out + '\n' + err).strip()
    ok = rc == 0 or 'error' not in combined.lower()
    return jsonify({'ok': ok, 'output': combined})

# --- CACHE htable ---

@app.route('/api/cache')
@login_required
def get_cache():
    out, _, _ = run_cmd('kamcmd htable.dump routing 2>/dev/null')
    entries = []
    if out:
        for line in out.split('\n'):
            line = line.strip()
            if line and not line.startswith('==='):
                entries.append(line)
    return jsonify({'entries': entries, 'raw': out})

@app.route('/api/cache/flush', methods=['POST'])
@login_required
def flush_cache():
    out, err, rc = run_cmd('kamcmd htable.flush routing 2>/dev/null')
    return jsonify({'ok': rc == 0, 'output': out or err})

# --- LOGS ---

@app.route('/api/logs')
@login_required
def get_logs():
    lines = int(request.args.get('lines', 100))
    filter_str = request.args.get('filter', 'kamailio')
    cmd = f'journalctl -u kamailio --no-pager -n {lines} 2>/dev/null || grep "{filter_str}" /var/log/syslog 2>/dev/null | tail -{lines}'
    out, _, _ = run_cmd(cmd, timeout=5)
    log_lines = out.split('\n') if out else []
    return jsonify({'lines': log_lines})

# --- ROTAS ---

@app.route('/api/routes')
@login_required
def get_routes():
    routes_file = '/etc/kamailio/routes.json'
    try:
        with open(routes_file) as f:
            routes = json.load(f)
    except Exception:
        routes = []
    return jsonify({'routes': routes})

@app.route('/api/routes', methods=['POST'])
@login_required
def save_routes():
    routes = request.json.get('routes', [])
    routes_file = '/etc/kamailio/routes.json'
    with open(routes_file, 'w') as f:
        json.dump(routes, f, indent=2)
    results = []
    for r in routes:
        user = r.get('username', '')
        dest = r.get('destination', '')
        if user and dest:
            out, err, rc = run_cmd(f'kamcmd htable.seti routing {user} {dest} 2>/dev/null')
            results.append({'user': user, 'dest': dest, 'ok': rc == 0})
    return jsonify({'ok': True, 'injected': results})

@app.route('/api/routes/<username>', methods=['DELETE'])
@login_required
def delete_route(username):
    routes_file = '/etc/kamailio/routes.json'
    try:
        with open(routes_file) as f:
            routes = json.load(f)
        routes = [r for r in routes if r.get('username') != username]
        with open(routes_file, 'w') as f:
            json.dump(routes, f, indent=2)
        run_cmd(f'kamcmd htable.delete routing {username} 2>/dev/null')
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- BACKUPS ---

@app.route('/api/backups')
@login_required
def list_backups():
    import glob
    backups = sorted(glob.glob(KAMAILIO_CFG + '.bak.*'), reverse=True)
    result = []
    for b in backups[:10]:
        stat = os.stat(b)
        result.append({
            'file': os.path.basename(b),
            'size': stat.st_size,
            'mtime': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        })
    return jsonify({'backups': result})

@app.route('/api/backups/<filename>/restore', methods=['POST'])
@login_required
def restore_backup(filename):
    if not filename.startswith('kamailio.cfg.bak.') or '/' in filename:
        return jsonify({'error': 'Arquivo invalido'}), 400
    src = os.path.join('/etc/kamailio', filename)
    if not os.path.exists(src):
        return jsonify({'error': 'Arquivo nao encontrado'}), 404
    with open(src) as f:
        content = f.read()
    ok, info = write_cfg(content)
    return jsonify({'ok': ok, 'info': info})



# --- SIP MONITOR (CLI em tempo real) ---

_monitor_last_lines = []

def parse_sip_log_line(line):
    """Extrai info SIP estruturada de uma linha de log do Kamailio."""
    event = {}
    m = re.match(r'^(\w+\s+\d+\s+[\d:]+)', line)
    event['time'] = m.group(1) if m else ''

    if 'ERROR:' in line:
        event['level'] = 'error'
    elif 'WARNING:' in line or 'WARN:' in line:
        event['level'] = 'warn'
    else:
        event['level'] = 'info'

    # REGISTER
    rm = re.search(r'REGISTER from (sip:\S+)\s*\(IP:\s*([\d.]+):(\d+)\)', line)
    if rm:
        event['type'] = 'REGISTER'
        event['from'] = rm.group(1)
        event['ip'] = rm.group(2)
        event['port'] = rm.group(3)
        event['detail'] = f'{rm.group(1)} from {rm.group(2)}:{rm.group(3)}'
        return event

    rm = re.search(r'REGISTER with Auth - user:\s*(\S+)', line)
    if rm:
        event['type'] = 'AUTH'
        event['detail'] = f'Auth user: {rm.group(1)}'
        return event

    rm = re.search(r'API lookup:\s*(\S+)', line)
    if rm:
        event['type'] = 'API_LOOKUP'
        event['detail'] = f'Consulta API: {rm.group(1)}'
        return event

    rm = re.search(r'API OK:\s*(\S+)\s*->\s*(\S+)', line)
    if rm:
        event['type'] = 'API_OK'
        event['level'] = 'ok'
        event['detail'] = f'{rm.group(1)} -> {rm.group(2)}'
        return event

    rm = re.search(r'API erro para\s*(\S+):\s*HTTP\s*(\d+)', line)
    if rm:
        event['type'] = 'API_ERROR'
        event['level'] = 'error'
        event['detail'] = f'{rm.group(1)} HTTP {rm.group(2)}'
        return event

    rm = re.search(r'Cache HIT.*?(\S+)\s*->\s*(\S+)', line)
    if rm:
        event['type'] = 'CACHE_HIT'
        event['level'] = 'ok'
        event['detail'] = f'{rm.group(1)} -> {rm.group(2)}'
        return event

    rm = re.search(r'Forwarding REGISTER to\s*(\S+)', line)
    if rm:
        event['type'] = 'FORWARD'
        event['detail'] = f'Forward to {rm.group(1)}'
        return event

    rm = re.search(r'Routing\s+(\w+):\s*(\S+)\s*->\s*(\S+)', line)
    if rm:
        event['type'] = rm.group(1).upper()
        event['detail'] = f'{rm.group(2)} -> {rm.group(3)}'
        return event

    rm = re.search(r'Sem rota para\s*(\S+)', line)
    if rm:
        event['type'] = 'NO_ROUTE'
        event['level'] = 'error'
        event['detail'] = f'Sem rota: {rm.group(1)}'
        return event

    rm = re.search(r'could not resolve hostname:\s*"([^"]+)"', line)
    if rm:
        event['type'] = 'DNS_ERROR'
        event['level'] = 'error'
        event['detail'] = f'DNS falhou: {rm.group(1)}'
        return event

    rm = re.search(r'REGISTER reply:\s*(\d+)\s*(\S*)\s*from\s*([\d.]+)', line)
    if rm:
        code = rm.group(1)
        event['type'] = 'REG_REPLY'
        event['level'] = 'ok' if code.startswith('2') else ('warn' if code.startswith('4') else 'error')
        event['detail'] = f'{code} {rm.group(2)} from {rm.group(3)}'
        return event

    rm = re.search(r'REGISTER failure\s*(\d+)\s*for\s*(\S+)', line)
    if rm:
        event['type'] = 'REG_FAIL'
        event['level'] = 'error'
        event['detail'] = f'Falha {rm.group(1)} para {rm.group(2)}'
        return event

    if 'ws_handle_handshake' in line or 'websocket' in line.lower():
        event['type'] = 'WEBSOCKET'
        event['detail'] = re.sub(r'^.*?kamailio\[\d+\]:\s*', '', line).strip()[:120]
        if 'WARNING' in line:
            event['level'] = 'warn'
        return event

    rm = re.search(r'Malformed SIP from\s*([\d.]+):(\d+)', line)
    if rm:
        event['type'] = 'MALFORMED'
        event['level'] = 'warn'
        event['detail'] = f'Malformed from {rm.group(1)}:{rm.group(2)}'
        return event

    if 'kamailio' in line:
        event['type'] = 'OTHER'
        event['detail'] = re.sub(r'^.*?kamailio\[\d+\]:\s*', '', line).strip()[:120]
        return event

    return None


def fetch_sip_events(num_lines=200):
    """Le os logs do journalctl e parseia em eventos."""
    out, _, rc = run_cmd(f'journalctl -u kamailio --no-pager -n {num_lines} --output=short 2>/dev/null', timeout=5)
    events = []
    if out:
        for line in out.strip().split('\n'):
            evt = parse_sip_log_line(line)
            if evt:
                events.append(evt)
    return events


@app.route('/api/sip-monitor')
@login_required
def sip_monitor():
    limit = int(request.args.get('limit', 200))
    type_filter = request.args.get('type', '')
    level_filter = request.args.get('level', '')

    events = fetch_sip_events(limit * 2)

    if type_filter:
        types = set(type_filter.upper().split(','))
        events = [e for e in events if e.get('type') in types]
    if level_filter:
        levels = set(level_filter.lower().split(','))
        events = [e for e in events if e.get('level') in levels]

    events = events[-limit:]

    stats = {
        'total': len(events),
        'registers': sum(1 for e in events if e.get('type') == 'REGISTER'),
        'invites': sum(1 for e in events if e.get('type') == 'INVITE'),
        'errors': sum(1 for e in events if e.get('level') == 'error'),
        'api_ok': sum(1 for e in events if e.get('type') == 'API_OK'),
        'api_errors': sum(1 for e in events if e.get('type') == 'API_ERROR'),
        'cache_hits': sum(1 for e in events if e.get('type') == 'CACHE_HIT'),
    }

    return jsonify({'events': events, 'stats': stats, 'monitor_active': True})


@app.route('/api/sip-monitor/clear', methods=['POST'])
@login_required
def sip_monitor_clear():
    # Rotate journal for kamailio
    run_cmd('journalctl --vacuum-time=1s -u kamailio 2>/dev/null', timeout=5)
    return jsonify({'ok': True})


@app.route('/api/sip-monitor/stats')
@login_required
def sip_monitor_stats():
    events = fetch_sip_events(300)
    ips = set()
    users = set()
    for e in events:
        if e.get('ip'):
            ips.add(e['ip'])
        fr = e.get('from', '')
        if fr:
            users.add(fr.replace('sip:', '').split('@')[0])
    return jsonify({
        'total_events': len(events),
        'unique_ips': len(ips),
        'unique_users': len(users),
    })


# --- FAIL2BAN MANAGEMENT ---

@app.route('/api/fail2ban/status')
@login_required
def fail2ban_status():
    out, _, rc = run_cmd('fail2ban-client status 2>/dev/null')
    jails = []
    if rc == 0:
        m = re.search(r'Jail list:\s*(.+)', out)
        if m:
            jail_names = [j.strip() for j in m.group(1).split(',')]
            for name in jail_names:
                jout, _, _ = run_cmd(f'fail2ban-client status {name} 2>/dev/null')
                jail = {'name': name, 'banned': 0, 'banned_ips': [], 'failed': 0, 'total_failed': 0}
                m2 = re.search(r'Currently banned:\s*(\d+)', jout)
                if m2: jail['banned'] = int(m2.group(1))
                m2 = re.search(r'Total banned:\s*(\d+)', jout)
                if m2: jail['total_banned'] = int(m2.group(1))
                m2 = re.search(r'Currently failed:\s*(\d+)', jout)
                if m2: jail['failed'] = int(m2.group(1))
                m2 = re.search(r'Total failed:\s*(\d+)', jout)
                if m2: jail['total_failed'] = int(m2.group(1))
                m2 = re.search(r'Banned IP list:\s*(.*)', jout)
                if m2 and m2.group(1).strip():
                    jail['banned_ips'] = m2.group(1).strip().split()
                jails.append(jail)

    out2, _, _ = run_cmd('systemctl is-active fail2ban')
    running = out2.strip() == 'active'

    return jsonify({'running': running, 'jails': jails})


@app.route('/api/fail2ban/ban', methods=['POST'])
@login_required
def fail2ban_ban():
    # Banimento manual via painel: aplica em TODAS as jails ativas
    # (descobertas dinamicamente). Inclui jail 'kamailio-manual' (permanente),
    # 'kamailio' (24h), 'sip-admin-web' e quaisquer outras que existam.
    # Como kamailio-manual tem bantime=-1, o IP fica permanentemente bloqueado
    # mesmo apos as outras jails expirarem.
    data = request.json or {}
    ip = data.get('ip', '').strip()
    if not ip or not re.match(r'^[\d.:/]+$', ip):
        return jsonify({'error': 'IP invalido'}), 400

    # Permite override (compat) - se vier 'jail' especifico, bana so nele
    specific_jail = data.get('jail', '').strip()
    if specific_jail:
        out, err, rc = run_cmd(f'fail2ban-client set {specific_jail} banip {ip} 2>&1')
        return jsonify({'ok': rc == 0, 'output': out or err, 'jails': [specific_jail]})

    # Descobre todas as jails ativas dinamicamente
    out, _, _ = run_cmd('fail2ban-client status 2>/dev/null')
    m = re.search(r'Jail list:\s*(.+)', out)
    if not m:
        return jsonify({'error': 'Nenhuma jail ativa'}), 500
    jails = [j.strip() for j in m.group(1).split(',') if j.strip()]

    results = []
    for jail in jails:
        out, err, rc = run_cmd(f'fail2ban-client set {jail} banip {ip} 2>&1')
        results.append({'jail': jail, 'ok': rc == 0, 'output': (out or err).strip()})

    success = [r['jail'] for r in results if r['ok']]
    return jsonify({
        'ok': len(success) > 0,
        'banned_in': success,
        'total_jails': len(jails),
        'jails': [r['jail'] for r in results],
        'results': results
    })


@app.route('/api/fail2ban/unban', methods=['POST'])
@login_required
def fail2ban_unban():
    data = request.json or {}
    ip = data.get('ip', '').strip()
    jail = data.get('jail', '')
    if not ip or not re.match(r'^[\d.:/]+$', ip):
        return jsonify({'error': 'IP invalido'}), 400
    if jail:
        out, err, rc = run_cmd(f'fail2ban-client set {jail} unbanip {ip} 2>&1')
    else:
        out, err, rc = run_cmd(f'fail2ban-client unban {ip} 2>&1')
    return jsonify({'ok': rc == 0, 'output': out or err})


@app.route('/api/fail2ban/unban-all', methods=['POST'])
@login_required
def fail2ban_unban_all():
    out, err, rc = run_cmd('fail2ban-client unban --all 2>&1')
    return jsonify({'ok': rc == 0, 'output': out or err})


@app.route('/api/fail2ban/whitelist', methods=['GET'])
@login_required
def fail2ban_whitelist_get():
    """Retorna a whitelist atual com nomes (entries) e tambem como lista
    simples de IPs (ips) para compatibilidade com clientes antigos."""
    entries = load_whitelist_entries()
    return jsonify({
        'entries': entries,
        'ips': [e['ip'] for e in entries],
    })


@app.route('/api/fail2ban/whitelist', methods=['POST'])
@login_required
def fail2ban_whitelist_set():
    """Substitui a whitelist completa.

    Aceita formatos:
      - {'entries': [{type:'ip'|'ddns', ip|hostname, name}, ...]}  (preferido)
      - {'ips': ['1.2.3.4', ...]}                                  (compatibilidade)

    Para entradas DDNS, resolve o hostname automaticamente ao salvar.
    """
    from datetime import datetime
    data = request.json or {}
    entries_raw = data.get('entries')

    if entries_raw is None:
        ips = data.get('ips', [])
        if isinstance(ips, str):
            ips = ips.split()
        entries_raw = [{'type': 'ip', 'ip': ip, 'name': ''} for ip in ips]

    valid = []
    invalid = []
    for e in entries_raw:
        if not isinstance(e, dict):
            e = {'type': 'ip', 'ip': str(e).strip(), 'name': ''}
        etype = str(e.get('type', '')).strip().lower() or ('ddns' if e.get('hostname') else 'ip')
        name = str(e.get('name', '')).strip()
        if etype == 'ddns':
            host = str(e.get('hostname', '')).strip()
            if not host or not _validate_hostname(host):
                invalid.append(host or '(hostname vazio)')
                continue
            # Resolve no momento do salvamento
            resolved_ip = _resolve_hostname(host) or str(e.get('ip', '')).strip()
            valid.append({
                'type': 'ddns', 'hostname': host, 'name': name,
                'ip': resolved_ip,
                'resolved_at': datetime.now().isoformat(timespec='seconds') if resolved_ip else ''
            })
        else:
            ip = str(e.get('ip', '')).strip()
            if not ip:
                continue
            if not _validate_ip_or_cidr(ip):
                invalid.append(ip)
                continue
            valid.append({'type': 'ip', 'ip': ip, 'name': name})

    saved = save_whitelist_entries(valid)
    run_cmd('fail2ban-client reload 2>&1')

    # Desbane os IPs (de type=ip e os ja resolvidos de type=ddns)
    unbanned = []
    for e in saved:
        ip = e.get('ip', '').strip()
        if ip and _unban_ip_all_jails(ip):
            unbanned.append(ip)

    return jsonify({
        'ok': True,
        'whitelisted': len(saved),
        'unbanned': unbanned,
        'invalid': invalid,
    })


@app.route('/api/fail2ban/whitelist/add', methods=['POST'])
@login_required
def fail2ban_whitelist_add():
    """Adiciona um IP/CIDR ou DDNS a whitelist.

    Body para IP:    {type:'ip',   ip, mask?, name?}    (type pode ser omitido)
    Body para DDNS:  {type:'ddns', hostname, name?}

    Para DDNS: resolve o hostname imediatamente e armazena o IP atual.
    O cron job '/etc/cron.d/sip-admin-ddns-refresh' atualiza periodicamente.
    """
    from datetime import datetime
    data = request.json or {}
    etype = str(data.get('type', '')).strip().lower()
    name = str(data.get('name', '')).strip()

    # Sem type: infere
    if not etype:
        etype = 'ddns' if data.get('hostname') else 'ip'

    entries = load_whitelist_entries()

    if etype == 'ddns':
        host = str(data.get('hostname', '')).strip()
        if not host:
            return jsonify({'ok': False, 'error': 'Informe um hostname DDNS válido.'}), 400
        if not _validate_hostname(host):
            return jsonify({'ok': False, 'error': f'Formato de hostname inválido: {host}'}), 400
        # Resolve agora
        resolved_ip = _resolve_hostname(host)
        if not resolved_ip:
            return jsonify({'ok': False, 'error': f'Não foi possível resolver o hostname: {host}'}), 400

        # Substitui se ja existir (mesmo hostname), senao acrescenta
        found = False
        for e in entries:
            if e.get('type') == 'ddns' and e.get('hostname', '').lower() == host.lower():
                e['name'] = name
                e['ip'] = resolved_ip
                e['resolved_at'] = datetime.now().isoformat(timespec='seconds')
                found = True
                break
        if not found:
            entries.append({
                'type': 'ddns', 'hostname': host, 'name': name,
                'ip': resolved_ip,
                'resolved_at': datetime.now().isoformat(timespec='seconds'),
            })

        save_whitelist_entries(entries)
        run_cmd('fail2ban-client reload 2>&1')
        _unban_ip_all_jails(resolved_ip)

        return jsonify({
            'ok': True,
            'type': 'ddns',
            'hostname': host,
            'ip': resolved_ip,
            'name': name,
            'total': len(entries),
        })

    # type=ip
    ip = str(data.get('ip', '')).strip()
    mask = str(data.get('mask', '')).strip()
    if not ip:
        return jsonify({'ok': False, 'error': 'Informe um IP válido.'}), 400
    if mask and '/' not in ip:
        if not mask.startswith('/'):
            mask = '/' + mask
        ip = ip + mask
    if not _validate_ip_or_cidr(ip):
        return jsonify({'ok': False, 'error': f'Formato inválido: {ip}'}), 400

    found = False
    for e in entries:
        if e.get('type', 'ip') == 'ip' and e.get('ip') == ip:
            e['name'] = name
            found = True
            break
    if not found:
        entries.append({'type': 'ip', 'ip': ip, 'name': name})

    save_whitelist_entries(entries)
    run_cmd('fail2ban-client reload 2>&1')
    unbanned = _unban_ip_all_jails(ip)

    return jsonify({
        'ok': True,
        'type': 'ip',
        'ip': ip,
        'name': name,
        'unbanned': bool(unbanned),
        'total': len(entries),
    })


@app.route('/api/fail2ban/whitelist/delete', methods=['POST'])
@login_required
def fail2ban_whitelist_delete():
    """Remove uma entrada da whitelist.

    Body: {ip: str}  ou  {hostname: str}
    """
    data = request.json or {}
    ip = str(data.get('ip', '')).strip()
    host = str(data.get('hostname', '')).strip()
    if not ip and not host:
        return jsonify({'ok': False, 'error': 'Informe um IP ou hostname.'}), 400

    entries = load_whitelist_entries()
    if host:
        new_entries = [e for e in entries
                       if not (e.get('type') == 'ddns'
                               and e.get('hostname', '').lower() == host.lower())]
    else:
        new_entries = [e for e in entries
                       if not (e.get('type', 'ip') == 'ip' and e.get('ip') == ip)]

    if len(new_entries) == len(entries):
        return jsonify({'ok': False, 'error': 'Entrada não encontrada na whitelist.'}), 404

    save_whitelist_entries(new_entries)
    run_cmd('fail2ban-client reload 2>&1')
    return jsonify({'ok': True, 'remaining': len(new_entries)})


@app.route('/api/fail2ban/whitelist/refresh-ddns', methods=['POST'])
@login_required
def fail2ban_whitelist_refresh_ddns():
    """Forca a resolucao imediata de todos os hostnames DDNS da whitelist.
    Util para o botao 'Atualizar agora' do painel."""
    result = refresh_ddns_entries()
    return jsonify({'ok': True, **result})


@app.route('/api/fail2ban/restart', methods=['POST'])
@login_required
def fail2ban_restart():
    out, err, rc = run_cmd('systemctl restart fail2ban 2>&1')
    return jsonify({'ok': rc == 0, 'output': out or err})

# --- ROUTE BLOCKS (Blocos de Roteamento do kamailio.cfg) ---

def parse_route_blocks(cfg):
    """Extrai blocos route[NAME] { ... } e request_route { ... } do kamailio.cfg."""
    blocks = []
    # Match: route[NAME] { ... }, request_route { ... }, onreply_route[NAME] { ... },
    # failure_route[NAME] { ... }, event_route[NAME] { ... }
    pattern = re.compile(
        r'^((?:request_route|route\[\w+\]|onreply_route\[\w+\]|failure_route\[\w+\]|event_route\[[^\]]+\]))\s*\{',
        re.MULTILINE
    )
    for m in pattern.finditer(cfg):
        name = m.group(1)
        start = m.start()
        # Find matching closing brace
        brace_count = 0
        body_start = m.end() - 1  # position of opening {
        pos = body_start
        while pos < len(cfg):
            if cfg[pos] == '{':
                brace_count += 1
            elif cfg[pos] == '}':
                brace_count -= 1
                if brace_count == 0:
                    body = cfg[body_start:pos+1]
                    blocks.append({
                        'name': name,
                        'body': body,
                        'start': start,
                        'end': pos + 1,
                    })
                    break
            pos += 1
    return blocks


@app.route('/api/config/route-blocks', methods=['GET'])
@login_required
def get_route_blocks():
    cfg = read_cfg()
    if cfg is None:
        return jsonify({'error': 'Nao foi possivel ler kamailio.cfg'}), 500
    blocks = parse_route_blocks(cfg)
    # Return without start/end positions (internal use only)
    result = [{'name': b['name'], 'body': b['body']} for b in blocks]
    return jsonify({'blocks': result})


@app.route('/api/config/route-blocks/<path:block_name>', methods=['GET'])
@login_required
def get_route_block(block_name):
    cfg = read_cfg()
    if cfg is None:
        return jsonify({'error': 'Nao foi possivel ler kamailio.cfg'}), 500
    blocks = parse_route_blocks(cfg)
    for b in blocks:
        if b['name'] == block_name:
            return jsonify({'name': b['name'], 'body': b['body']})
    return jsonify({'error': f'Bloco {block_name} nao encontrado'}), 404


@app.route('/api/config/route-blocks/<path:block_name>', methods=['PUT'])
@login_required
def update_route_block(block_name):
    data = request.json or {}
    new_body = data.get('body', '')
    if not new_body:
        return jsonify({'error': 'Body vazio'}), 400

    cfg = read_cfg()
    if cfg is None:
        return jsonify({'error': 'Nao foi possivel ler kamailio.cfg'}), 500

    blocks = parse_route_blocks(cfg)
    target = None
    for b in blocks:
        if b['name'] == block_name:
            target = b
            break

    if not target:
        return jsonify({'error': f'Bloco {block_name} nao encontrado'}), 404

    # Rebuild the full block: name + body
    old_full = cfg[target['start']:target['end']]
    new_full = block_name + ' ' + new_body

    new_cfg = cfg[:target['start']] + new_full + cfg[target['end']:]

    # Validate syntax
    with tempfile.NamedTemporaryFile(mode='w', suffix='.cfg', delete=False) as tf:
        tf.write(new_cfg)
        tmp_path = tf.name
    out, err, rc = run_cmd(f'kamailio -c -f {tmp_path} 2>&1')
    os.unlink(tmp_path)
    if rc != 0 and 'error' in (out + err).lower():
        return jsonify({'error': 'Erro de sintaxe: ' + (out or err), 'syntax_error': True}), 400

    ok, info = write_cfg(new_cfg)
    if not ok:
        return jsonify({'error': info}), 500
    return jsonify({'ok': True, 'backup': info})




# ─── LXD CONFIG ──────────────────────────────────────────────────────────────

def load_lxd_config():
    if os.path.exists(LXD_CONFIG_FILE):
        try:
            with open(LXD_CONFIG_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {'host': '', 'port': 22, 'user': 'root', 'password': ''}

def save_lxd_config(cfg):
    with open(LXD_CONFIG_FILE, 'w') as f:
        json.dump(cfg, f, indent=2)
    os.chmod(LXD_CONFIG_FILE, 0o600)

def lxd_ssh_cmd(cmd, timeout=10):
    cfg = load_lxd_config()
    if not cfg.get('host'):
        return '', 'LXD nao configurado', 1
    ssh_cmd = f"sshpass -p '{cfg['password']}' ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no {cfg['user']}@{cfg['host']} -p {cfg['port']} '{cmd}'"
    return run_cmd(ssh_cmd, timeout=timeout)

@app.route('/api/lxd/config', methods=['GET'])
@login_required
def get_lxd_config():
    cfg = load_lxd_config()
    # Nao retornar senha completa
    safe = {**cfg, 'password': '••••••••' if cfg.get('password') else ''}
    return jsonify(safe)

@app.route('/api/lxd/config', methods=['POST'])
@login_required
def save_lxd_config_route():
    data = request.json or {}
    cfg = load_lxd_config()
    if data.get('host'): cfg['host'] = data['host']
    if data.get('port'): cfg['port'] = int(data['port'])
    if data.get('user'): cfg['user'] = data['user']
    if data.get('password') and data['password'] != '••••••••':
        cfg['password'] = data['password']
    save_lxd_config(cfg)
    return jsonify({'ok': True})

@app.route('/api/lxd/test', methods=['POST'])
@login_required
def test_lxd():
    out, err, rc = lxd_ssh_cmd('echo OK && lxc list --format csv -c n 2>/dev/null | wc -l')
    if rc == 0 and 'OK' in out:
        lines = out.strip().split('\n')
        count = lines[-1].strip() if len(lines) > 1 else '0'
        return jsonify({'ok': True, 'containers': int(count)})
    return jsonify({'ok': False, 'error': err or out or 'Falha na conexao'})

@app.route('/api/lxd/containers', methods=['GET'])
@login_required
def list_containers():
    out, err, rc = lxd_ssh_cmd('lxc list --format csv -c ns4', timeout=15)
    if rc != 0:
        return jsonify({'error': err or 'Falha ao listar containers'}), 500
    containers = []
    for line in out.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.split(',')
        if len(parts) >= 2:
            name = parts[0].strip()
            status = parts[1].strip()
            ips = parts[2].strip() if len(parts) > 2 else ''
            # Parse IPs
            ip_list = []
            for ip_part in ips.split('\n'):
                ip_part = ip_part.strip()
                if ip_part:
                    ip_list.append(ip_part)
            containers.append({
                'name': name,
                'status': status,
                'ips': ip_list,
                'ip_display': ' / '.join(ip_list) if ip_list else 'N/A'
            })
    return jsonify({'containers': containers})


# ─── SIP CAPTURE ─────────────────────────────────────────────────────────────

_capture_process = None
_capture_packets = []
_capture_lock = threading.Lock()
_capture_container = None
_capture_active = False

def parse_sip_packet(raw_text):
    """Parse raw tcpdump SIP output into structured data."""
    packets = []
    current_pkt = None
    sip_lines = []

    for line in raw_text.split('\n'):
        # New packet header from tcpdump
        if re.match(r'^\d{2}:\d{2}:\d{2}\.\d+', line):
            # Save previous packet
            if current_pkt and sip_lines:
                sip_text = '\n'.join(sip_lines)
                enrich_sip(current_pkt, sip_text)
                packets.append(current_pkt)

            # Parse tcpdump header: timestamp IP src > dst: SIP: ...
            current_pkt = {'raw_header': line, 'time': '', 'src': '', 'dst': '', 'method': '', 'status': '', 'call_id': '', 'from_user': '', 'to_user': ''}
            sip_lines = []

            # Extract timestamp
            tm = re.match(r'^(\d{2}:\d{2}:\d{2}\.\d+)', line)
            if tm:
                current_pkt['time'] = tm.group(1)[:12]

            # Extract src > dst
            ipm = re.search(r'IP\s+([\d.]+)\.?(\d+)?\s+>\s+([\d.]+)\.?(\d+)?', line)
            if ipm:
                src_ip = ipm.group(1)
                src_port = ipm.group(2) or ''
                dst_ip = ipm.group(3)
                dst_port = ipm.group(4) or ''
                current_pkt['src'] = f"{src_ip}:{src_port}" if src_port else src_ip
                current_pkt['dst'] = f"{dst_ip}:{dst_port}" if dst_port else dst_ip

            # Quick method from header line
            sm = re.search(r'SIP:\s+(\w+)\s+sip:', line)
            if sm:
                current_pkt['method'] = sm.group(1)
            sm2 = re.search(r'SIP:\s+SIP/2\.0\s+(\d{3})\s+(.+)', line)
            if sm2:
                current_pkt['status'] = sm2.group(1)
                current_pkt['method'] = f"{sm2.group(1)} {sm2.group(2).strip()}"

        elif current_pkt:
            sip_lines.append(line)

    # Last packet
    if current_pkt and sip_lines:
        sip_text = '\n'.join(sip_lines)
        enrich_sip(current_pkt, sip_text)
        packets.append(current_pkt)

    return packets


def enrich_sip(pkt, sip_text):
    """Extract SIP headers from raw text."""
    # Method from first SIP line
    m = re.search(r'^(INVITE|REGISTER|BYE|ACK|CANCEL|OPTIONS|NOTIFY|SUBSCRIBE|REFER|INFO|UPDATE|PRACK|MESSAGE)\s+sip:', sip_text, re.MULTILINE)
    if m and not pkt['method']:
        pkt['method'] = m.group(1)

    # Status
    m = re.search(r'^SIP/2\.0\s+(\d{3})\s+(.+)', sip_text, re.MULTILINE)
    if m and not pkt['status']:
        pkt['status'] = m.group(1)
        if not pkt['method']:
            pkt['method'] = f"{m.group(1)} {m.group(2).strip()}"

    # Call-ID
    m = re.search(r'^Call-ID:\s*(.+)', sip_text, re.MULTILINE | re.IGNORECASE)
    if m:
        pkt['call_id'] = m.group(1).strip()[:40]

    # From
    m = re.search(r'^From:.*?<sip:([^@>]+)', sip_text, re.MULTILINE | re.IGNORECASE)
    if m:
        pkt['from_user'] = m.group(1)

    # To
    m = re.search(r'^To:.*?<sip:([^@>]+)', sip_text, re.MULTILINE | re.IGNORECASE)
    if m:
        pkt['to_user'] = m.group(1)

    # CSeq method
    m = re.search(r'^CSeq:\s*\d+\s+(\w+)', sip_text, re.MULTILINE | re.IGNORECASE)
    if m and not pkt.get('cseq_method'):
        pkt['cseq_method'] = m.group(1)
        if pkt['status'] and not pkt.get('method_clean'):
            pkt['method'] = f"{pkt['status']} {m.group(1)}"


def _capture_thread(container):
    global _capture_process, _capture_active, _capture_packets
    cfg = load_lxd_config()
    if not cfg.get('host'):
        return

    ssh_cmd = (
        f"sshpass -p '{cfg['password']}' ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "
        f"{cfg['user']}@{cfg['host']} -p {cfg['port']} "
        f"'timeout 300 lxc exec {container} -- tcpdump -i any -n -l port 5060 -A -s 0 2>/dev/null'"
    )

    try:
        _capture_process = subprocess.Popen(
            ssh_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        buffer = []
        for line in iter(_capture_process.stdout.readline, ''):
            if not _capture_active:
                break
            buffer.append(line.rstrip())
            # Process buffer when we hit a new packet header or buffer gets large
            if len(buffer) > 5 and re.match(r'^\d{2}:\d{2}:\d{2}\.\d+', line):
                raw = '\n'.join(buffer[:-1])
                pkts = parse_sip_packet(raw)
                if pkts:
                    with _capture_lock:
                        _capture_packets.extend(pkts)
                        # Keep max 500 packets
                        if len(_capture_packets) > 500:
                            _capture_packets = _capture_packets[-500:]
                buffer = [line.rstrip()]

        # Final flush
        if buffer:
            raw = '\n'.join(buffer)
            pkts = parse_sip_packet(raw)
            if pkts:
                with _capture_lock:
                    _capture_packets.extend(pkts)

    except Exception as e:
        pass
    finally:
        _capture_active = False
        if _capture_process:
            try:
                _capture_process.kill()
            except:
                pass
            _capture_process = None


@app.route('/api/sip-capture/start', methods=['POST'])
@login_required
def start_capture():
    global _capture_active, _capture_packets, _capture_container
    if _capture_active:
        return jsonify({'error': f'Captura ja ativa em {_capture_container}'}), 400

    data = request.json or {}
    container = data.get('container', '')
    if not container or not re.match(r'^[a-zA-Z0-9_-]+$', container):
        return jsonify({'error': 'Container invalido'}), 400

    with _capture_lock:
        _capture_packets = []
    _capture_active = True
    _capture_container = container

    t = threading.Thread(target=_capture_thread, args=(container,), daemon=True)
    t.start()

    return jsonify({'ok': True, 'container': container})


@app.route('/api/sip-capture/stop', methods=['POST'])
@login_required
def stop_capture():
    global _capture_active, _capture_process, _capture_container
    _capture_active = False
    if _capture_process:
        try:
            _capture_process.kill()
        except:
            pass
        _capture_process = None
    container = _capture_container
    _capture_container = None
    return jsonify({'ok': True, 'stopped': container})


@app.route('/api/sip-capture/status', methods=['GET'])
@login_required
def capture_status():
    with _capture_lock:
        count = len(_capture_packets)
    return jsonify({
        'active': _capture_active,
        'container': _capture_container,
        'packet_count': count
    })


@app.route('/api/sip-capture/data', methods=['GET'])
@login_required
def capture_data():
    since = int(request.args.get('since', 0))
    with _capture_lock:
        if since > 0 and since < len(_capture_packets):
            pkts = _capture_packets[since:]
        else:
            pkts = list(_capture_packets)
        total = len(_capture_packets)
    return jsonify({
        'packets': pkts,
        'total': total,
        'active': _capture_active,
        'container': _capture_container
    })


@app.route('/api/sip-capture/clear', methods=['POST'])
@login_required
def clear_capture():
    global _capture_packets
    with _capture_lock:
        _capture_packets = []
    return jsonify({'ok': True})



# --- DOCUMENTACAO ---

@app.route('/api/docs')
@login_required
def get_docs():
    docs_file = '/etc/kamailio/BASE_CONHECIMENTO_PROXY.md'
    try:
        with open(docs_file, 'r') as f:
            content = f.read()
        return jsonify({'content': content})
    except Exception as e:
        return jsonify({'error': str(e)}), 500



# ─── LXD SERVERS + IP MAPPING ────────────────────────────────────────────────

_ip_mapping_cache = {}
_ip_mapping_time = 0
_IP_MAPPING_TTL = 300  # 5 minutes

def load_lxd_servers():
    if os.path.exists(LXD_SERVERS_FILE):
        try:
            with open(LXD_SERVERS_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return []

def save_lxd_servers(servers):
    with open(LXD_SERVERS_FILE, 'w') as f:
        json.dump(servers, f, indent=2)
    os.chmod(LXD_SERVERS_FILE, 0o600)

def fetch_ip_mapping_from_lxd():
    """SSH to all LXD servers and build private->public IP mapping."""
    global _ip_mapping_cache, _ip_mapping_time
    servers = load_lxd_servers()
    mapping = {}
    for srv in servers:
        if not srv.get('host') or not srv.get('enabled', True):
            continue
        ssh_cmd = (
            f"sshpass -p '{srv['password']}' ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "
            f"{srv['user']}@{srv['host']} -p {srv.get('port', 22)} "
            f"'lxc list --format csv -c n,4,s 2>/dev/null'"
        )
        out, err, rc = run_cmd(ssh_cmd, timeout=15)
        if rc != 0 or not out:
            continue
        # Join multiline entries (CSV with quoted newlines)
        raw = out.strip()
        # Rebuild lines: if a line doesn't end with RUNNING/STOPPED, append to previous
        lines = []
        for piece in raw.split('\n'):
            piece = piece.strip()
            if not piece:
                continue
            if lines and not lines[-1].endswith('RUNNING') and not lines[-1].endswith('STOPPED'):
                lines[-1] += ' ' + piece
            else:
                lines.append(piece)
        for line in lines:
            line = line.replace('"', '')
            # Find status
            if 'RUNNING' not in line:
                continue
            # Extract name (first field)
            parts = line.split(',')
            name = parts[0].strip()
            # Extract all IPs from the line
            all_ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)', line)
            private_ip = None
            public_ip = None
            for ip in all_ips:
                if ip.startswith('11.') or ip.startswith('10.') or ip.startswith('192.168.'):
                    private_ip = ip
                elif not ip.startswith('127.'):
                    public_ip = ip
            if private_ip and public_ip:
                mapping[private_ip] = public_ip
    _ip_mapping_cache = mapping
    _ip_mapping_time = time.time()
    return mapping

def get_ip_mapping():
    """Get cached IP mapping, refresh if expired."""
    global _ip_mapping_cache, _ip_mapping_time
    if time.time() - _ip_mapping_time > _IP_MAPPING_TTL:
        fetch_ip_mapping_from_lxd()
    return _ip_mapping_cache

def translate_ip(private_ip):
    """Translate private IP to public IP."""
    mapping = get_ip_mapping()
    return mapping.get(private_ip, private_ip)


# --- LXD Servers CRUD ---

@app.route('/api/lxd-servers', methods=['GET'])
@login_required
def get_lxd_servers():
    servers = load_lxd_servers()
    # Hide passwords
    safe = []
    for s in servers:
        sc = dict(s)
        sc['password'] = '••••••••' if s.get('password') else ''
        safe.append(sc)
    return jsonify({'servers': safe})

@app.route('/api/lxd-servers', methods=['POST'])
@login_required
def add_lxd_server():
    data = request.json or {}
    servers = load_lxd_servers()
    srv = {
        'name': data.get('name', ''),
        'host': data.get('host', ''),
        'port': int(data.get('port', 22)),
        'user': data.get('user', 'root'),
        'password': data.get('password', ''),
        'enabled': data.get('enabled', True)
    }
    if not srv['host']:
        return jsonify({'error': 'Host obrigatorio'}), 400
    servers.append(srv)
    save_lxd_servers(servers)
    return jsonify({'ok': True})

@app.route('/api/lxd-servers/<int:idx>', methods=['PUT'])
@login_required
def update_lxd_server(idx):
    data = request.json or {}
    servers = load_lxd_servers()
    if idx < 0 or idx >= len(servers):
        return jsonify({'error': 'Servidor nao encontrado'}), 404
    srv = servers[idx]
    if data.get('name'): srv['name'] = data['name']
    if data.get('host'): srv['host'] = data['host']
    if data.get('port'): srv['port'] = int(data['port'])
    if data.get('user'): srv['user'] = data['user']
    if data.get('password') and data['password'] != '••••••••':
        srv['password'] = data['password']
    if 'enabled' in data: srv['enabled'] = data['enabled']
    save_lxd_servers(servers)
    return jsonify({'ok': True})

@app.route('/api/lxd-servers/<int:idx>', methods=['DELETE'])
@login_required
def delete_lxd_server(idx):
    servers = load_lxd_servers()
    if idx < 0 or idx >= len(servers):
        return jsonify({'error': 'Servidor nao encontrado'}), 404
    servers.pop(idx)
    save_lxd_servers(servers)
    return jsonify({'ok': True})

@app.route('/api/lxd-servers/<int:idx>/test', methods=['POST'])
@login_required
def test_lxd_server(idx):
    servers = load_lxd_servers()
    if idx < 0 or idx >= len(servers):
        return jsonify({'error': 'Servidor nao encontrado'}), 404
    srv = servers[idx]
    ssh_cmd = (
        f"sshpass -p '{srv['password']}' ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "
        f"{srv['user']}@{srv['host']} -p {srv.get('port', 22)} "
        f"'echo OK && lxc list --format csv -c n 2>/dev/null | wc -l'"
    )
    out, err, rc = run_cmd(ssh_cmd, timeout=10)
    if rc == 0 and 'OK' in out:
        lines = out.strip().split('\n')
        count = lines[-1].strip() if len(lines) > 1 else '0'
        return jsonify({'ok': True, 'containers': int(count)})
    return jsonify({'ok': False, 'error': err or out or 'Falha na conexao'})


# --- IP Mapping ---

@app.route('/api/lxd/ip-mapping', methods=['GET'])
@login_required
def get_ip_mapping_route():
    mapping = get_ip_mapping()
    return jsonify({'mapping': mapping, 'count': len(mapping), 'age': int(time.time() - _ip_mapping_time)})

@app.route('/api/lxd/ip-mapping/refresh', methods=['POST'])
@login_required
def refresh_ip_mapping():
    mapping = fetch_ip_mapping_from_lxd()
    return jsonify({'ok': True, 'mapping': mapping, 'count': len(mapping)})

@app.route('/api/lxd/translate/<ip>')
def translate_ip_route(ip):
    """Translate private IP to public. No auth required (Kamailio calls this)."""
    public_ip = translate_ip(ip)
    return public_ip



# ─── ROUTING CACHE MANAGEMENT ────────────────────────────────────────────────

@app.route('/api/routing-cache')
@login_required
def get_routing_cache():
    """List all entries in htable 'routing' with timestamps from routing_time."""
    # Get timestamps
    out_t, _, _ = run_cmd('kamcmd htable.dump routing_time 2>/dev/null', timeout=5)
    timestamps = {}
    if out_t:
        current_t = {}
        for line in out_t.split('\n'):
            line = line.strip()
            if line == '}' and current_t.get('name'):
                if current_t.get('value'):
                    try:
                        timestamps[current_t['name']] = int(current_t['value'])
                    except (ValueError, TypeError):
                        pass
                current_t = {}
            for sep in [': ', '=']:
                if sep in line:
                    parts = line.split(sep, 1)
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = parts[1].strip().rstrip(',').strip()
                        if key == 'name' and val and val != 'routing_time':
                            current_t['name'] = val
                        elif key == 'value' and val:
                            current_t['value'] = val
                    break
        if current_t.get('name') and current_t.get('value'):
            try:
                timestamps[current_t['name']] = int(current_t['value'])
            except (ValueError, TypeError):
                pass

    out, err, rc = run_cmd('kamcmd htable.dump routing 2>/dev/null', timeout=5)
    entries = []
    if out:
        # Parse kamcmd output format:
        # {
        # 	entry: 47
        # 	slot: {
        # 		{
        # 			name: ramalaktz3a
        # 			value: {{CONTAINER_IP}}
        # 			type: str
        # 		}
        # 	}
        # }
        current = {}
        for line in out.split('\n'):
            line = line.strip()
            # Detect new entry block
            if line == '}' and current.get('name'):
                entries.append(current)
                current = {}
            # Parse "name: value" or "name = value"
            for sep in [': ', '=']:
                if sep in line:
                    parts = line.split(sep, 1)
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = parts[1].strip().rstrip(',').strip()
                        if key == 'name' and val and val != 'routing':
                            current['name'] = val
                        elif key == 'value' and val:
                            current['value'] = val
                        elif key == 'expires':
                            current['expires'] = val
                    break
        if current.get('name'):
            entries.append(current)

    # Add public IP translation and timestamp
    from datetime import datetime as dt
    mapping = get_ip_mapping() if 'get_ip_mapping' in globals() else {}
    for e in entries:
        priv = e.get('value', '')
        e['public_ip'] = mapping.get(priv, '')
        ts = timestamps.get(e.get('name', ''))
        if ts:
            e['registered_at'] = dt.fromtimestamp(ts).strftime('%d/%m/%Y %H:%M:%S')
            e['registered_at_ts'] = ts
        else:
            e['registered_at'] = ''
            e['registered_at_ts'] = 0

    return jsonify({'entries': entries, 'count': len(entries)})


@app.route('/api/routing-cache/<key>', methods=['DELETE'])
@login_required
def delete_routing_cache(key):
    """Delete a specific cache entry."""
    if not re.match(r'^[a-zA-Z0-9_-]+$', key):
        return jsonify({'error': 'Chave invalida'}), 400
    out, err, rc = run_cmd(f'kamcmd htable.delete routing {key} 2>/dev/null', timeout=5)
    return jsonify({'ok': rc == 0, 'output': out or err})


@app.route('/api/routing-cache/flush', methods=['POST'])
@login_required
def flush_routing_cache():
    """Flush entire routing cache."""
    out, err, rc = run_cmd('kamcmd htable.flush routing 2>/dev/null', timeout=5)
    return jsonify({'ok': rc == 0, 'output': out or err})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888, debug=False)
