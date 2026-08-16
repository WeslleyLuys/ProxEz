#!/bin/bash
# Renderiza kamailio.cfg.template com as variáveis do .env e instala em
# /etc/kamailio/kamailio.cfg. Valida a sintaxe antes de reiniciar.
#
#   cp .env.example .env && vi .env
#   sudo ./scripts/deploy.sh
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || { echo "ERRO: .env não encontrado (copie de .env.example)"; exit 1; }
set -a; . ./.env; set +a

REQ=(PROXY_IP PROXY_NET DOMAIN API_HOST API_PORT TLS_PRIVATE_KEY TLS_CERT SIP_REALM
     CONTAINER_IP INTERNAL_NET PUBLIC_IP PUBLIC_NET)
for v in "${REQ[@]}"; do
  [ -n "${!v:-}" ] || { echo "ERRO: variável $v não definida no .env"; exit 1; }
done

BACKUP="/etc/kamailio/kamailio.cfg.bak.deploy_$(date +%Y%m%d%H%M%S)"
[ -f /etc/kamailio/kamailio.cfg ] && sudo cp /etc/kamailio/kamailio.cfg "$BACKUP" && echo "Backup: $BACKUP"

sed \
  -e "s#{{PROXY_IP}}#${PROXY_IP}#g" \
  -e "s#{{PROXY_NET}}#${PROXY_NET}#g" \
  -e "s#{{PUBLIC_IP}}#${PUBLIC_IP}#g" \
  -e "s#{{PUBLIC_NET}}#${PUBLIC_NET}#g" \
  -e "s#{{CONTAINER_IP}}#${CONTAINER_IP}#g" \
  -e "s#{{INTERNAL_IP}}#${CONTAINER_IP}#g" \
  -e "s#{{INTERNAL_NET}}#${INTERNAL_NET}#g" \
  -e "s#{{API_HOST}}#${API_HOST}#g" \
  -e "s#{{DOMAIN}}#${DOMAIN}#g" \
  -e "s#{{TLS_PRIVATE_KEY}}#${TLS_PRIVATE_KEY}#g" \
  -e "s#{{TLS_CERT}}#${TLS_CERT}#g" \
  -e "s#{{SIP_REALM}}#${SIP_REALM}#g" \
  kamailio/kamailio.cfg.template | sudo tee /etc/kamailio/kamailio.cfg > /dev/null

if ! sudo kamailio -c -f /etc/kamailio/kamailio.cfg; then
  echo "ERRO: sintaxe inválida — restaurando backup"
  [ -f "$BACKUP" ] && sudo cp "$BACKUP" /etc/kamailio/kamailio.cfg
  exit 1
fi

sudo systemctl restart kamailio
sleep 2
sudo systemctl is-active kamailio && echo "Deploy OK"
