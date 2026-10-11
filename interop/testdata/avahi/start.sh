#!/bin/sh
# Starts D-Bus (avahi-publish and avahi-browse talk to the daemon over it)
# and avahi-daemon, then keeps the container running.
set -e
mkdir -p /run/dbus /run/avahi-daemon
dbus-daemon --system
avahi-daemon --no-drop-root --no-chroot --no-rlimits -D
exec sleep 2147483647
