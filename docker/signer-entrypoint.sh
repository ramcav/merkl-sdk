#!/bin/sh
# Entrypoint of the signer image. Started as root (a bind-mounted volume from
# the host arrives owned by whoever made it), it takes ownership of the volume
# and drops to the unprivileged `merkl` user before anything of the signer's
# runs. Started as any other user, it runs as that user and touches nothing.
#
# `signer serve` is the one command that becomes two processes: the signer on a
# Unix socket, and `merkl.signer.forward` on $MERKL_SIGNER_LISTEN relaying to
# it. merkl.signer.server refuses to bind anything but loopback or a socket —
# correctly, and that guard is not moving — so a container that must publish a
# port needs the proxy its refusal names. They are supervised as one pair: if
# either exits, so does the container, with that exit code. A signer whose
# forwarder died is unreachable, and a forwarder whose signer died forwards to
# nothing; neither half is worth keeping alive alone.
#
# Every other subcommand — treasury init, signer token, policy show — is exec'd
# straight through as it always was.
set -eu

HOME_DIR=/var/lib/merkl-signer

# Runtime state, not the treasury's: a fresh socket every boot, in the image's
# own filesystem rather than the volume. A bind mount from a macOS or Windows
# host cannot hold a Unix socket at all, and the volume is for things worth
# keeping.
: "${MERKL_SIGNER_SOCKET:=/run/merkl-signer/signer.sock}"
: "${MERKL_SIGNER_LISTEN:=0.0.0.0:8787}"

if [ "$(id -u)" = "0" ]; then
    chown -R merkl:merkl "$HOME_DIR"
    mkdir -p "$(dirname "$MERKL_SIGNER_SOCKET")"
    chown merkl:merkl "$(dirname "$MERKL_SIGNER_SOCKET")"
    export MERKL_SIGNER_SOCKET MERKL_SIGNER_LISTEN
    exec setpriv --reuid=merkl --regid=merkl --init-groups "$0" "$@"
fi

if [ "${1:-}" != "signer" ] || [ "${2:-}" != "serve" ]; then
    exec merkl "$@"
fi

# Where the signer will be listening, so the forwarder knows where to send. An
# explicit --socket or --host from the caller wins; otherwise the signer is
# given the socket above.
upstream=""
host=""
port=8787
previous=""
for argument in "$@"; do
    case "$previous" in
        --socket) upstream=$argument ;;
        --host) host=$argument ;;
        --port) port=$argument ;;
    esac
    previous=$argument
done

if [ -z "$upstream" ]; then
    if [ -n "$host" ]; then
        upstream="$host:$port"
    else
        upstream=$MERKL_SIGNER_SOCKET
        set -- "$@" --socket "$upstream"
    fi
fi

signer_pid=""
forwarder_pid=""
asked_to_stop=""

stop_both() {
    if [ -n "$signer_pid" ]; then
        kill "$signer_pid" 2>/dev/null || true
    fi
    if [ -n "$forwarder_pid" ]; then
        kill "$forwarder_pid" 2>/dev/null || true
    fi
}

# `docker stop` is not a failure. Reporting the signal we passed on as the
# container's exit code would make a restart policy of `on-failure` restart a
# container somebody deliberately stopped.
on_signal() {
    asked_to_stop=yes
    stop_both
}
trap on_signal HUP INT TERM

merkl "$@" &
signer_pid=$!

python -m merkl.signer.forward --listen "$MERKL_SIGNER_LISTEN" --upstream "$upstream" &
forwarder_pid=$!

# No `wait -n` here: /bin/sh is dash, and one dependency the image does not need
# is a second shell. Polling costs a fifth of a second of notice.
code=0
which="the signer"
while :; do
    if ! kill -0 "$signer_pid" 2>/dev/null; then
        wait "$signer_pid" || code=$?
        break
    fi
    if ! kill -0 "$forwarder_pid" 2>/dev/null; then
        wait "$forwarder_pid" || code=$?
        which="the forwarder"
        break
    fi
    sleep 0.2 || true
done

stop_both
wait 2>/dev/null || true

if [ -n "$asked_to_stop" ]; then
    echo "merkl-signer: stopped on a signal" >&2
    exit 0
fi
echo "merkl-signer: $which exited with $code; stopping the container" >&2
exit "$code"
