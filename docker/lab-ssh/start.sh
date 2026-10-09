#!/bin/sh
# Start rsyslog in the background, then run sshd in the foreground as the container's main process.
set -eu
mkdir -p /run/sshd /var/log/ssh
rm -f /run/rsyslogd.pid          # left over if the container was stopped abruptly
rsyslogd
exec /usr/sbin/sshd -D
