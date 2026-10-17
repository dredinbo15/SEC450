# Lab web server (DD-03): nginx serving a small static site and proxying /api/ to the
# lab app. Access and error logs go to /var/log/lab-nginx on a named volume the
# collector mounts read-only (DD-04). Lab use only; nothing here is hardened.
FROM nginx:1.30.5-alpine

# tzdata lets the logs use the zone from the TZ variable set in docker-compose.yml.
RUN apk add --no-cache tzdata \
    && mkdir -p /usr/share/nginx/lab/files \
    && head -c 4194304 /dev/urandom > /usr/share/nginx/lab/files/dataset-2026.bin

COPY nginx.conf /etc/nginx/nginx.conf
COPY site/ /usr/share/nginx/lab/
