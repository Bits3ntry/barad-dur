#!/usr/bin/env bash
# Put the lab target behind a name and a TLS port, the way a real host looks.
#
#   bash scripts/poc_demo/tls_front.sh
#
# juice-shop (already running on 127.0.0.1:3111) is behind nginx on :80 and :443
# with a self-signed certificate for `juice-shop.demo`. The worker resolves that
# name to the host gateway, so |
#   the recon worker → juice-shop.demo:443 → nginx → juice-shop:3111
# is a real TCP path with a real certificate — nothing is faked in the observations.
#
# The certificate is self-signed on purpose: "certificate not trusted" is a
# finding the demo can show, and it is true.
set -Eeuo pipefail

cd "$(dirname "$0")/../.."
readonly DEST="${POC_DIR:-${HOME}/HUB/Workspace/Councilbox/CYB/poc-juice-shop}"
readonly TLS="${DEST}/tls"
readonly HOST="juice-shop.demo"
readonly BACKEND="host.docker.internal:3111"

mkdir -p "$TLS"

if [[ ! -s "$TLS/${HOST}.crt" ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 90 \
    -keyout "$TLS/${HOST}.key" -out "$TLS/${HOST}.crt" \
    -subj "/CN=${HOST}/O=Juice Shop Lab" \
    -addext "subjectAltName=DNS:${HOST}" 2>/dev/null
  echo "cert: $TLS/${HOST}.crt"
fi

cat > "$TLS/nginx.conf" <<CONF
server {
    listen 80;
    server_name ${HOST};
    location / {
        proxy_pass http://${BACKEND};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
server {
    listen 443 ssl;
    server_name ${HOST};
    ssl_certificate     /etc/nginx/certs/${HOST}.crt;
    ssl_certificate_key /etc/nginx/certs/${HOST}.key;
    location / {
        proxy_pass http://${BACKEND};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
CONF

docker rm -f juice-shop-front >/dev/null 2>&1 || true
docker run -d --name juice-shop-front --restart unless-stopped \
  -p 80:80 -p 443:443 \
  -v "$TLS/nginx.conf:/etc/nginx/conf.d/default.conf:ro" \
  -v "$TLS:/etc/nginx/certs:ro" \
  --add-host "${BACKEND%%:*}":host-gateway \
  nginx:1.27-alpine >/dev/null

for _ in $(seq 1 20); do
  code=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: ${HOST}" "https://127.0.0.1/" || true)
  [[ "$code" == "200" ]] && break
  sleep 1
done
echo "https  -> $code"
curl -s -o /dev/null -w 'http   -> %{http_code}\n' -H "Host: ${HOST}" "http://127.0.0.1/"
curl -sk -H "Host: ${HOST}" "https://127.0.0.1/" | grep -o '<title>[^<]*</title>' | head -1

# The worker is the only component that must resolve the name: it runs the
# probes. `host-gateway` also works, but it is an alias (0.250.250.254) and the
# asset screen would show that instead of an address; the host's LAN IP is what
# the packets actually use, so that is what the inventory records.
TARGET_IP="${POC_TARGET_IP:-$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo 127.0.0.1)}"
cat > compose.demo.yaml <<YAML
# POC demo override: the lab target's name, resolvable from the workers.
#   docker compose -f compose.yaml -f compose.local.yaml -f compose.demo.yaml up -d --no-deps shauron-worker agent-worker
# POC_TARGET_IP is the host address the published 443 is reachable on.
services:
  shauron-worker:
    extra_hosts:
      - "juice-shop.demo:\${POC_TARGET_IP:-${TARGET_IP}}"
  agent-worker:
    extra_hosts:
      - "juice-shop.demo:\${POC_TARGET_IP:-${TARGET_IP}}"
YAML
printf 'target ip: %s\n' "$TARGET_IP"

docker compose -f compose.yaml -f compose.local.yaml -f compose.demo.yaml \
  up -d --no-deps --no-build shauron-worker agent-worker 2>&1 | tail -3

sleep 2
docker exec barad-dur-shauron-worker-1 getent hosts "${HOST}" || \
  docker exec barad-dur-shauron-worker-1 sh -c "getent hosts ${HOST} || ping -c1 ${HOST} | head -2"
