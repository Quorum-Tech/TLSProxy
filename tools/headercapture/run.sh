#!/bin/sh
# Loads, in headless Chrome over HTTP/2 and HTTP/1.1, an address that redirects to another site
# and then one page that makes every kind of request, recording each request's headers in
# arrival order.
#   ./run.sh <chrome binary> <label>    writes cap-<label>-h2.json and cap-<label>-h1.json
set -e
CHROME="$1"; LABEL="$2"
[ -n "$CHROME" ] && [ -n "$LABEL" ] || { echo "usage: $0 <chrome binary> <label>" >&2; exit 2; }
cd "$(dirname "$0")"
if [ ! -f cert.pem ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout key.pem -out cert.pem \
    -days 30 -subj /CN=localhost -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
fi
# headless Chrome with --dump-dom can outlive its --timeout: each load gets a hard stop
load() {
  PROFILE=$(mktemp -d)   # a fresh profile each time: no cache or cookie from an earlier load
  perl -e "alarm $1; exec @ARGV" "$CHROME" --headless=new --user-data-dir="$PROFILE" --no-first-run --disable-gpu \
    --ignore-certificate-errors --timeout=5000 --virtual-time-budget=5000 --dump-dom "$2" >/dev/null 2>&1 || true
  rm -rf "$PROFILE"
}
for PROTO in h2 h1; do
  H2PORT=$((20000 + $(od -An -N2 -tu2 /dev/urandom | tr -d ' ') % 20000)); H1PORT=$((H2PORT + 1))
  H2PORT=$H2PORT H1PORT=$H1PORT WAIT=30000 node capture.mjs "cap-$LABEL-$PROTO.json" &
  NODEPID=$!
  sleep 1
  if [ "$PROTO" = h2 ]; then URL="https://localhost:$H2PORT/"; else URL="http://localhost:$H1PORT/"; fi
  load 8 "${URL}r/nav"    # an address typed into a fresh browser that redirects to another site
  load 14 "$URL"          # the page that makes every other kind of request
  wait $NODEPID
done
echo "wrote cap-$LABEL-h2.json and cap-$LABEL-h1.json"
