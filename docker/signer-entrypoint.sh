#!/bin/sh
# Entrypoint of the signer image. Started as root (a bind-mounted volume from
# the host arrives owned by whoever made it), it takes ownership of the volume
# and drops to the unprivileged `merkl` user before the CLI runs. Started as
# any other user, it runs the CLI as that user and touches nothing.
set -eu

HOME_DIR=/var/lib/merkl-signer

if [ "$(id -u)" = "0" ]; then
    chown -R merkl:merkl "$HOME_DIR"
    exec setpriv --reuid=merkl --regid=merkl --init-groups merkl "$@"
fi

exec merkl "$@"
