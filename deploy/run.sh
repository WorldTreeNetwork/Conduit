#!/bin/bash
# nginx owns the gateway port. conduit-server stays on loopback.
# One process tree: nginx in front, the homeserver behind it.
set -euo pipefail

if [[ -f /run/mjolnir/secrets.env ]]; then
    set -a
    # shellcheck disable=SC1091
    source /run/mjolnir/secrets.env
    set +a
fi

mkdir -p /var/lib/conduit/media /var/log

export CONDUIT_LISTEN_ADDR=127.0.0.1:8009
export CONDUIT_SERVER_NAME=conduit.vm.worldtree.network
export CONDUIT_ALLOW_GUEST_ACCESS=false
export CONDUIT_MEDIA_ROOT=/var/lib/conduit/media
export CONDUIT_WELL_KNOWN_CLIENT_BASE_URL=https://conduit.vm.worldtree.network
export CONDUIT_WELL_KNOWN_SERVER=conduit.vm.worldtree.network:443
export CONDUIT_OIDC_REDIRECT_URI=https://conduit.vm.worldtree.network/_matrix/client/v3/login/identikey/callback

cd /app
./target/release/conduit-server &
server_pid=$!

cleanup() {
    kill "$server_pid" 2>/dev/null || true
}
trap cleanup EXIT

for _ in $(seq 1 60); do
    if ! kill -0 "$server_pid" 2>/dev/null; then
        wait "$server_pid"
        exit $?
    fi
    if (echo >/dev/tcp/127.0.0.1/8009) 2>/dev/null; then
        break
    fi
    sleep 0.5
done

if ! (echo >/dev/tcp/127.0.0.1/8009) 2>/dev/null; then
    echo "conduit-server did not listen on 127.0.0.1:8009" >&2
    exit 1
fi

exec nginx -c /app/deploy/nginx.conf -g 'daemon off;'
