# Lab SSH server (DD-03): a real sshd whose auth log is written by rsyslog to
# /var/log/ssh/auth.log on a named volume the collector mounts read-only (DD-04).
# Lab use only: nothing here is hardened, and no user accounts exist, so every
# login attempt fails.
FROM debian:bookworm-slim

# tzdata lets the log use the zone from the TZ variable set in docker-compose.yml.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server rsyslog tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && ssh-keygen -A

COPY rsyslog.conf /etc/rsyslog.conf
COPY start.sh /usr/local/bin/start.sh
RUN chmod 0755 /usr/local/bin/start.sh

EXPOSE 22
CMD ["/usr/local/bin/start.sh"]
