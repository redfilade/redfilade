#!/usr/bin/env bash
# Re-render the 3D brand images (banner, social preview, avatar) into assets/brand/.
# Needs: Node + npm, Python 3 and Google Chrome.
# three.js and the two SIL OFL fonts (Fredoka, Nunito) are installed at pinned versions into a
# throwaway folder with install scripts disabled, never into the repo.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; OUT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; trap 'kill "${SRV:-0}" 2>/dev/null || true; rm -rf "$WORK"' EXIT
cp "$HERE/scene.html" "$WORK/"
(cd "$WORK" && npm init -y >/dev/null && npm install --ignore-scripts --silent \
  three@0.187.0 @fontsource/fredoka@5.3.0 @fontsource/nunito@5.3.0)
mkdir -p "$WORK/fonts"
cp "$WORK/node_modules/@fontsource/fredoka/files/fredoka-latin-700-normal.woff2" \
   "$WORK/node_modules/@fontsource/nunito/files/nunito-latin-800-normal.woff2" "$WORK/fonts/"
# Serve on a free port with no subshell, so the server is always stopped on exit.
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$WORK" >/dev/null 2>&1 & SRV=$!
for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:$PORT/scene.html" >/dev/null && break; sleep 0.1; done
curl -sf "http://127.0.0.1:$PORT/scene.html" | grep -q 'id="stage"' || { echo "scene server not serving scene.html" >&2; exit 1; }
shot() { google-chrome --headless=new --no-sandbox --hide-scrollbars --use-angle=swiftshader \
  --enable-unsafe-swiftshader --virtual-time-budget=8000 --window-size="$2,$3" \
  --screenshot="$OUT/$4" "http://127.0.0.1:$PORT/scene.html?mode=$1" 2>/dev/null
  # Guard: a real render is large; an error page is tiny.
  [ "$(wc -c < "$OUT/$4")" -gt 150000 ] || { echo "render of $4 looks wrong (too small)" >&2; exit 1; }; }
shot banner 1600 520 redfilade-banner-1600x520.png
shot social 1280 640 redfilade-social-1280x640.png
shot avatar 1024 1024 redfilade-avatar-1024.png
echo "Rendered into $OUT"
