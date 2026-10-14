#!/usr/bin/env bash
set -euo pipefail

conduit_peer_repo="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$conduit_peer_repo"
conduit_peer_env="$conduit_peer_repo/.spawns/synapse-venv"
if [[ ! -x "$conduit_peer_env/bin/python" ]]; then
    uv venv "$conduit_peer_env" --python python3
fi

if ! "$conduit_peer_env/bin/python" -c 'import synapse, importlib.metadata; assert importlib.metadata.version("matrix-synapse") == "1.162.0"' >/dev/null 2>&1; then
    if [[ "$(uname -s)" == Darwin && "$(uname -r | cut -d. -f1)" -ge 27 ]]; then
        # Apple's SDK 27 linker emits an extension that dyld rejects here.
        # LLVM's Mach-O linker with an older installed SDK produces a loadable
        # peer. This changes only the isolated peer build, never Conduit flags.
        conduit_peer_sdk="${CONDUIT_PEER_SDK:-/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk}"
        test -f "$conduit_peer_sdk/usr/lib/libSystem.tbd"
        conduit_peer_rustlib="$(rustc --print target-libdir)"
        mkdir -p .spawns/synapse-linker
        ln -sf "$(dirname -- "$conduit_peer_rustlib")/bin/rust-lld" .spawns/synapse-linker/ld64.lld
        conduit_peer_flags="-C"$'\x1f'"link-arg=-fuse-ld=$conduit_peer_repo/.spawns/synapse-linker/ld64.lld"$'\x1f'"-C"$'\x1f'"link-arg=-Wl,-syslibroot,$conduit_peer_sdk"
        SDKROOT="$conduit_peer_sdk" CARGO_ENCODED_RUSTFLAGS="$conduit_peer_flags" \
        uv --no-cache pip install --python "$conduit_peer_env/bin/python" \
            --no-binary matrix-synapse --reinstall-package matrix-synapse \
            -r conduit-server/tests/peers/requirements.txt
    else
        uv pip install --python "$conduit_peer_env/bin/python" \
            -r conduit-server/tests/peers/requirements.txt
    fi
fi

SQLX_OFFLINE=true cargo build -p conduit-server
exec "$conduit_peer_env/bin/python" conduit-server/tests/peers/synapse_to_device.py
