#!/bin/sh
# Startup checks shared by the collector and api containers, then runs the command.
set -eu

# Docker turns a missing bind-mounted file into an empty directory, which gives a
# confusing Python error later. Fail early with the fix instead.
if [ ! -f "$SEC450_CONFIG" ]; then
    echo "config.yaml not found. From the repo root run: cp config.example.yaml config.yaml" >&2
    exit 1
fi

# The api needs a TLS certificate (REQ-09). If none exists yet, create a
# self-signed one at the paths given in config.yaml. It lives on the certs
# volume, so it survives restarts. Replace it with a real certificate if you have one.
if [ "${SEC450_SELF_SIGNED_CERT:-0}" = "1" ]; then
    CERT=$(python -c "from sec450.config import load_config; print(load_config().api.tls_cert)")
    KEY=$(python -c "from sec450.config import load_config; print(load_config().api.tls_key)")
    if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
        echo "creating self-signed TLS certificate at $CERT"
        openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
            -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
            -keyout "$KEY" -out "$CERT" 2>/dev/null
        chmod 0600 "$KEY"
    fi
fi

exec "$@"
