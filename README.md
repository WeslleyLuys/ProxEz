# Omni SIP Proxy

Gateway **WebRTC ↔ SIP** baseado em **Kamailio 5.8** com um **painel administrativo web** (Flask). Termina conexões WebRTC (WSS) de softphones no navegador, roteia dinamicamente para containers Asterisk e oferece um painel para gerenciar registros, firewall, certificados, captura SIP e um WebPhone embutido.

> ⚠️ Todos os valores sensíveis (IPs, domínios, senhas, chaves) foram substituídos por placeholders `{{...}}`. Configure via `.env` antes do deploy. **Nunca** faça commit de segredos reais.

---

## Arquitetura

```
  Navegador (JsSIP/WebRTC)                Kamailio (proxy)              Containers Asterisk
  ┌────────────────────┐   WSS/TLS   ┌──────────────────────┐  SIP/UDP  ┌──────────────────┐
  │  softphone web      │───:8089────▶│  termina WSS          │──:5060──▶│  ramalXXXXX      │
  │  ramalXXXXX         │◀───────────│  roteia por USER      │◀─────────│  (PJSIP realtime)│
  └────────────────────┘             │  Path/NAT traversal   │           └──────────────────┘
                                     │  cache (htables)      │
                                     └──────────┬───────────┘
                                                │ HTTP
                                                ▼
                                     ┌──────────────────────┐
                                     │  API de provisionamento│
                                     │  (decide o container   │
                                     │   + balanceamento)     │
                                     └──────────────────────┘
```

- **O cliente WebRTC nunca fala direto com o Asterisk.** Toda a sinalização passa pelo Kamailio, que termina o WebSocket seguro (WSS) e converte para SIP/UDP internamente.
- **O roteamento é por usuário do ramal**, não por domínio. Para cada REGISTER/INVITE, o proxy consulta a API (`/pabx/ramals/proxy/<user>`) que retorna qual container Asterisk atende aquele ramal, com balanceamento de carga.
- **Cache local (htables)** evita consultar a API a cada pacote.

## Componentes

| Caminho | Função |
|---|---|
| `kamailio/kamailio.cfg.template` | Configuração do Kamailio com placeholders `{{VAR}}` |
| `sip-admin/app.py` | Backend Flask do painel (auth multiusuário, permissões, APIs) |
| `sip-admin/static/` | Frontend: `app.js`, `style.css`, `webrtc-test.html`, JsSIP (WebPhone) |
| `sip-admin/templates/` | Páginas Jinja: `index.html`, `login.html` |
| `scripts/deploy.sh` | Renderiza o template com o `.env` e instala o `kamailio.cfg` |

## Como o Kamailio funciona (resumo do `request_route`)

1. **REGISTER** — cliente registra via WSS. O proxy consulta a API para descobrir o container, adiciona o header **Path** (RFC 3327) com o IP:porta real do cliente (`received=`), encaminha ao Asterisk e salva a conexão em htables.
2. **Autenticação** — feita pelo **Asterisk** (challenge 401 digest). O proxy só roteia.
3. **Qualify (OPTIONS)** — o proxy responde `200 OK` localmente em nome do cliente WebRTC (que não responde OPTIONS unsolicited de forma confiável), mantendo o ramal `Avail` no Asterisk.
4. **INVITE** — roteado ao container pelo user (cache → API → fallback pelo chamador). Entrega a clientes WebRTC pela conexão WSS existente (`transport=ws`).
5. **In-dialog (ACK/BYE/INFO)** — o proxy reescreve o destino (`$du`) usando o `received=` do Path para atravessar o NAT, preservando `transport=ws` para destinos WebRTC.
6. **WebSocket fechado** — um `event_route[websocket:closed]` limpa o registro do cache quando a conexão cai (navegador fechado).

### htables (cache em memória)

| htable | Mapeia | TTL |
|---|---|---|
| `routing` | `ramal → container Asterisk` | curto (auto-expira) |
| `wscontacts` | `ramal → IP:porta da conexão WSS` | — |
| `sipcontacts` | `ramal → IP:porta` (clientes SIP UDP/TCP) | — |
| `wsconn` | `IP:porta → ramal` (reverso, p/ limpar no close) | — |

## Painel administrativo (`sip-admin`)

Flask servido atrás de um nginx (TLS). Recursos:

- **Auth multiusuário** com permissões por página (default de bootstrap: `admin` / `changeme` — **troque na primeira execução**).
- **Registro de Ramais** — lista os ramais registrados (cache `routing`/`wscontacts`).
- **Cache de Roteamento** — inspeciona/limpa o htable de rotas.
- **Firewall** — gerencia regras via SSH nos hosts.
- **WebPhone** — softphone WebRTC embutido (JsSIP servido localmente).
- **Captura SIP** — captura ao vivo por container (via `tcpdump`/`sngrep`).
- **Servidores LXD** — inventário de containers e mapeamento IP privado→público.
- **Certificados** — geração/gestão de certificados TLS.

## Deploy

Requisitos no host: Debian/Ubuntu, `kamailio` 5.8+ (módulos `tm`, `sl`, `rr`, `path`, `htable`, `http_client`, `websocket`, `tls`, `ctl`), `python3` + `flask`, TLS válido para o domínio, e uma API de provisionamento que resolva `ramal → container`.

```bash
git clone <seu-repo> omni-sip-proxy
cd omni-sip-proxy

cp .env.example .env
vi .env                 # preencha PROXY_IP, DOMAIN, API_HOST, TLS_*, etc.

# Kamailio
sudo ./scripts/deploy.sh

# Painel
sudo mkdir -p /opt/sip-admin
sudo cp -r sip-admin/* /opt/sip-admin/
# execute app.py via systemd/gunicorn (fora do escopo deste repo)
```

### Placeholders usados

| Placeholder | Significado |
|---|---|
| `{{PROXY_IP}}` / `{{PROXY_NET}}` | IP público do proxy / prefixo de rede |
| `{{PUBLIC_IP}}` / `{{PUBLIC_NET}}` | Faixa pública dos clientes |
| `{{CONTAINER_IP}}` / `{{INTERNAL_IP}}` / `{{INTERNAL_NET}}` | IPs internos dos containers Asterisk |
| `{{API_HOST}}` | Host da API de provisionamento |
| `{{DOMAIN}}` | FQDN do PABX |
| `{{TLS_PRIVATE_KEY}}` / `{{TLS_CERT}}` | Caminhos dos arquivos TLS |
| `{{SIP_REALM}}` | Realm de autenticação SIP |
| `{{SSH_PASSWORD}}` | Senha SSH (nunca commitar a real — use `.env`/secret manager) |

## Notas sobre DTMF (WebRTC)

Configure os softphones WebRTC para enviar DTMF via **RFC 2833** (`telephone-event` no RTP), alinhado ao `dtmf_mode=rfc4733` dos endpoints Asterisk. Enviar DTMF via **SIP INFO** (sinalização) é frágil em WebRTC e causa falhas em feature codes (ex.: transferência) sob redes com NAT agressivo.

## Segurança

- `.env`, `users.json`, `*.json` de configuração, chaves e certificados estão no `.gitignore` — **nunca** commite.
- `SECRET_KEY` do Flask deve vir do ambiente.
- Troque a senha `admin/changeme` imediatamente.
- Restrinja o painel a VPN ou allow-list de IPs.
- Este repositório contém apenas **código e templates** — nenhum dado de ambiente real.

## Licença

Defina a licença conforme sua necessidade (ex.: MIT) antes de publicar.
