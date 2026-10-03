#!/usr/bin/env bash
# Builds app/src/main/assets/vision/index.html from vision-web/zeekr-vision.src.html:
# inlines three.js (third_party/threejs) and drops the web-font links, so the page needs no network.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p app/src/main/assets/vision
python3 - <<'PY'
src = open('vision-web/zeekr-vision.src.html').read()
three = open('third_party/threejs/three.min.js').read()
lines = [l for l in src.split('\n') if 'fonts.googleapis.com' not in l and 'fonts.gstatic.com' not in l]
page = '<!doctype html>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">\n' + '\n'.join(lines)
assert '/*THREE_INLINE*/' in page
page = page.replace('/*THREE_INLINE*/', three)
assert 'https://' not in page.replace(three, ''), 'page must not reference the network'
open('app/src/main/assets/vision/index.html', 'w').write(page)
print('wrote app/src/main/assets/vision/index.html', len(page), 'bytes')
PY
