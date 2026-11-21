#!/usr/bin/env bash
# Rebuild the avatar, social preview and README banner from assets/brand/mascot/redfilade-mascot.png.
# The mascot artwork is used as-is: only cropped and framed. The wordmark is drawn over it.
# Needs: Python 3 with numpy + Pillow, Node + npm, Google Chrome. Fonts (SIL OFL) are installed
# at pinned versions into a temp folder with install scripts disabled, never into the repo.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; OUT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; trap 'kill "${SRV:-0}" 2>/dev/null || true; rm -rf "$WORK"' EXIT
python3 "$HERE/compose.py" "$WORK"
cp "$HERE/word.html" "$WORK/"
(cd "$WORK" && npm init -y >/dev/null && npm install --ignore-scripts --silent @fontsource/fredoka@5.3.0 @fontsource/nunito@5.3.0)
cp "$WORK/node_modules/@fontsource/fredoka/files/fredoka-latin-700-normal.woff2" \
   "$WORK/node_modules/@fontsource/nunito/files/nunito-latin-800-normal.woff2" \
   "$WORK/node_modules/@fontsource/nunito/files/nunito-latin-600-normal.woff2" "$WORK/"
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$WORK" >/dev/null 2>&1 & SRV=$!
for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:$PORT/word.html" >/dev/null && break; sleep 0.1; done
shot() { google-chrome --headless=new --no-sandbox --hide-scrollbars --virtual-time-budget=5000 \
  --window-size="$2,$3" --screenshot="$OUT/$4" "http://127.0.0.1:$PORT/word.html?mode=$1" 2>/dev/null
  [ "$(wc -c < "$OUT/$4")" -gt 150000 ] || { echo "render of $4 looks wrong (too small)" >&2; exit 1; }; }
shot social 1280 640 redfilade-social-1280x640.png
shot banner 1600 520 redfilade-banner.png
echo "Built into $OUT"
