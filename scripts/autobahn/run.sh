#!/bin/sh
# The Autobahn conformance run for close handling and RFC 7692: cases 7.*, 12.*
# and 13.*, against the echo endpoint this repo builds. Needs Docker.
#
#     sh scripts/autobahn/run.sh          # one run
#     sh scripts/autobahn/run.sh 3        # three runs, one after another
#
# The endpoint is `src/examples/16-ws-echo`, which speaks this library's handshake,
# frames and compression over a socket from `moonbitlang/async`. The container
# shares the host's network so that ws://127.0.0.1:9001 reaches it.
#
# Each run writes its own report under `_build/autobahn/run-N`, and `summary.py`
# judges it: a case that failed, or one that took longer than it is allowed,
# fails the whole thing.
set -eu

runs=${1:-1}
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(dirname "$(dirname "$here")")
cd "$root"

# Release, or the compressed cases take hours: deflate is an order of magnitude
# slower in a debug build.
moon build src/examples/16-ws-echo --target native --release
./_build/native/release/build/examples/16-ws-echo/16-ws-echo.exe &
endpoint=$!
trap 'kill $endpoint 2>/dev/null || true' EXIT
# The endpoint prints when it is listening; a second is what the build leaves it.
sleep 1

# The reports of an earlier run are docker's, so they may not be ours to remove;
# a run overwrites its own directory either way.
rm -rf _build/autobahn 2>/dev/null || true
mkdir -p _build/autobahn
run=1
while [ "$run" -le "$runs" ]; do
  echo "autobahn: run $run of $runs"
  # The same cases against the same endpoint, each run into its own directory, so
  # three runs leave three reports rather than overwriting one.
  sed "s#\"outdir\": *\"[^\"]*\"#\"outdir\": \"/reports/run-$run/clients\"#" \
    "$here/fuzzingclient.json" >"_build/autobahn/fuzzingclient-$run.json"
  docker run --rm --network host \
    -v "$root/_build/autobahn/fuzzingclient-$run.json:/config/fuzzingclient.json:ro" \
    -v "$root/_build/autobahn:/reports" \
    crossbario/autobahn-testsuite \
    wstest -m fuzzingclient -s /config/fuzzingclient.json
  python3 "$here/summary.py" "_build/autobahn/run-$run/clients/index.json"
  run=$((run + 1))
done
