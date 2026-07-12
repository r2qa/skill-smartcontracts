#!/usr/bin/env bash
# Start a LOCAL java-tron (tron-quickstart) — a private-net TVM sandbox ("anvil for TVM").
# Prints a pre-funded account. Ports: 9090 (HTTP). Safe: local private net only.
set -u
NAME="${TVM_CONTAINER:-tvm-quickstart}"
PORT="${TVM_PORT:-9090}"
PLAT=""; [ "$(uname -m)" = arm64 ] && PLAT="--platform linux/amd64"   # image is x86_64
docker rm -f "$NAME" >/dev/null 2>&1 || true
echo "starting tron-quickstart ($NAME) on :$PORT ${PLAT:+(amd64 emulation — slower)}…"
docker run -d $PLAT -p "$PORT:9090" -e "defaultBalance=100000000" -e "formatJson=true" \
  --name "$NAME" trontools/quickstart >/dev/null || { echo "docker run failed"; exit 1; }
echo -n "waiting for the node"; ok=0
for i in $(seq 1 90); do
  if curl -fsS "http://127.0.0.1:$PORT/wallet/getnowblock" >/dev/null 2>&1; then ok=1; break; fi
  echo -n "."; sleep 3
done
echo
[ "$ok" = 1 ] || { echo "node did not become ready in ~4.5m — check: docker logs $NAME"; exit 1; }
echo "TVM up at http://127.0.0.1:$PORT"
curl -fsS "http://127.0.0.1:$PORT/admin/accounts?format=all" 2>/dev/null | head -c 400; echo
