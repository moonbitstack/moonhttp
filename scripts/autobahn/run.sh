#!/bin/sh
# The Autobahn conformance run for RFC 7692: cases 12.* and 13.*, against the echo
# endpoint this repo builds. Needs Docker.
#
#     sh scripts/autobahn/run.sh
#
# The endpoint is `src/examples/16-ws-echo`, which speaks this library's handshake,
# frames and compression over a socket from `moonbitlang/async`. The container
# shares the host's network so that ws://127.0.0.1:9001 reaches it.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(dirname "$(dirname "$here")")
cd "$root"

moon build src/examples/16-ws-echo --target native
./_build/native/debug/build/examples/16-ws-echo/16-ws-echo.exe &
endpoint=$!
trap 'kill $endpoint 2>/dev/null || true' EXIT
sleep 1

mkdir -p _build/autobahn
docker run --rm --network host \
  -v "$here:/config:ro" \
  -v "$root/_build/autobahn:/reports" \
  crossbario/autobahn-testsuite \
  wstest -m fuzzingclient -s /config/fuzzingclient.json

python3 "$here/summary.py" _build/autobahn/clients/index.json
