#!/bin/sh
# Entrypoint of the signer image. Started as root (a bind-mounted volume from
# the host arrives owned by whoever made it), it takes ownership of the volume
# and drops to the unprivileged `merkl` user before anything of the signer's
# runs. Started as any other user, it runs as that user and touches nothing.
#
# `signer serve` and `signer bootstrap` are the commands that become two
# processes: the signer on a Unix socket, and `merkl.signer.forward` on
# $MERKL_SIGNER_LISTEN relaying to it. merkl.signer.server refuses to bind
# anything but loopback or a socket — correctly, and that guard is not moving —
# so a container that must publish a port needs the proxy its refusal names.
# They are supervised as one pair: if either exits, so does the container, with
# that exit code. A signer whose forwarder died is unreachable, and a forwarder
# whose signer died forwards to nothing; neither half is worth keeping alive
# alone. `bootstrap` sets the treasury up first and only then serves, so the
# forwarder is up throughout — a customer watching the dashboard gets a clean
# 503 from it rather than a refused connection.
#
# Every other subcommand — treasury init, signer token, policy show — runs
# straight through as it always did, and then whatever landed in /agent is
# handed back to whoever owns that directory. On Linux with the printed
# `-v "$PWD/merkl-agent:/agent"`, that is the host user: the agent bundle is
# readable without sudo. When /agent is the image's own directory the owner is
# already `merkl` and the step is a no-op.
set -eu

: "${MERKL_HOME:=/var/lib/merkl-signer}"
HOME_DIR=$MERKL_HOME

# Where `treasury init` leaves the agent bundle. An environment variable rather
# than a constant so the suite can point it somewhere it is allowed to write.
: "${MERKL_AGENT_DIR:=/agent}"
AGENT_DIR=$MERKL_AGENT_DIR

# Runtime state, not the treasury's: a fresh socket every boot, in the image's
# own filesystem rather than the volume. A bind mount from a macOS or Windows
# host cannot hold a Unix socket at all, and the volume is for things worth
# keeping.
: "${MERKL_SIGNER_SOCKET:=/run/merkl-signer/signer.sock}"
: "${MERKL_SIGNER_LISTEN:=0.0.0.0:8787}"

# `stat` disagrees with itself across platforms and this script is run by the
# suite on macOS as well as by the image on Linux. GNU first, BSD second.
stat_field() {
    stat -c "$1" "$2" 2>/dev/null || stat -f "$1" "$2" 2>/dev/null || true
}

# Hand the bundle back to whoever owns the directory it was written into.
# Skipped in the child of a privileged run: root does it afterwards, once,
# with the rights to succeed.
reown_agent_dir() {
    [ -d "$AGENT_DIR" ] || return 0
    [ -z "${MERKL_ENTRYPOINT_PRIVILEGED:-}" ] || return 0
    owner=$(stat_field %u "$AGENT_DIR")
    group=$(stat_field %g "$AGENT_DIR")
    [ -n "$owner" ] || return 0
    [ -n "$group" ] || group=$owner
    chown -R "$owner:$group" "$AGENT_DIR" 2>/dev/null || true
}

# The two commands that need a forwarder in front of them.
is_served() {
    [ "${1:-}" = "signer" ] || return 1
    [ "${2:-}" = "serve" ] || [ "${2:-}" = "bootstrap" ]
}

if [ "$(id -u)" = "0" ]; then
    chown -R merkl:merkl "$HOME_DIR"
    mkdir -p "$(dirname "$MERKL_SIGNER_SOCKET")"
    chown merkl:merkl "$(dirname "$MERKL_SIGNER_SOCKET")"
    export MERKL_SIGNER_SOCKET MERKL_SIGNER_LISTEN MERKL_HOME MERKL_AGENT_DIR
    if is_served "$@"; then
        exec setpriv --reuid=merkl --regid=merkl --init-groups "$0" "$@"
    fi
    # A one-shot subcommand. Not exec'd, because there is one thing left to do
    # after it: the bundle it may have written belongs to whoever owns /agent.
    MERKL_ENTRYPOINT_PRIVILEGED=1
    export MERKL_ENTRYPOINT_PRIVILEGED
    code=0
    setpriv --reuid=merkl --regid=merkl --init-groups "$0" "$@" || code=$?
    unset MERKL_ENTRYPOINT_PRIVILEGED
    reown_agent_dir
    exit "$code"
fi

if ! is_served "$@"; then
    code=0
    merkl "$@" || code=$?
    reown_agent_dir
    exit "$code"
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

reown_agent_dir

if [ -n "$asked_to_stop" ]; then
    echo "merkl-signer: stopped on a signal" >&2
    exit 0
fi
echo "merkl-signer: $which exited with $code; stopping the container" >&2
exit "$code"
