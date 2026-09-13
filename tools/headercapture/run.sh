#!/bin/sh
# Loads one page that makes every kind of request in headless Chrome, over HTTP/2 and
# HTTP/1.1, and records each request's headers in arrival order.
#   ./run.sh <chrome binary> <label>    writes cap-<label>-h2.json and cap-<label>-h1.json
set -e
CHROME="$1"; LABEL="$2"
[ -n "$CHROME" ] && [ -n "$LABEL" ] || { echo "usage: $0 <chrome binary> <label>" >&2; exit 2; }
cd "$(dirname "$0")"
if [ ! -f cert.pem ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout key.pem -out cert.pem \
    -days 30 -subj /CN=localhost -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
fi
for PROTO in h2 h1; do
  H2PORT=$((20000 + $(od -An -N2 -tu2 /dev/urandom | tr -d ' ') % 20000)); H1PORT=$((H2PORT + 1))
  H2PORT=$H2PORT H1PORT=$H1PORT WAIT=16000 node capture.mjs "cap-$LABEL-$PROTO.json" &
  NODEPID=$!
  sleep 1
  PROFILE=$(mktemp -d)
  if [ "$PROTO" = h2 ]; then URL="https://localhost:$H2PORT/"; else URL="http://localhost:$H1PORT/"; fi
  # a fresh profile each time, so no cache or cookie from an earlier run changes what is sent
  perl -e 'alarm 25; exec @ARGV' "$CHROME" --headless=new --user-data-dir="$PROFILE" --no-first-run --disable-gpu \
    --ignore-certificate-errors --timeout=6000 --virtual-time-budget=6000 --dump-dom "$URL" >/dev/null 2>&1 || true
  rm -rf "$PROFILE"
  wait $NODEPID
done
echo "wrote cap-$LABEL-h2.json and cap-$LABEL-h1.json"
