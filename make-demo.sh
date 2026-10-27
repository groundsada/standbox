#!/usr/bin/env bash
# Regenerates docs/standbox-demo.gif from docs/demo-session.sh.
# Requires: brew install asciinema agg
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

for tool in asciinema agg; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "error: $tool not installed. run: brew install asciinema agg" >&2
    exit 1
  }
done

asciinema rec -c "bash docs/demo-session.sh" --cols 100 --rows 34 -i 2 \
  docs/standbox-demo.cast
agg --speed 1.3 --font-size 14 --theme monokai \
  docs/standbox-demo.cast docs/standbox-demo.gif

echo "wrote docs/standbox-demo.gif ($(du -h docs/standbox-demo.gif | cut -f1))"
