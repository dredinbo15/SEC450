# One image for both the collector and the API; docker-compose.yml picks the command.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SEC450_CONFIG=/app/config.yaml

WORKDIR /app

# Dependencies first, so code edits don't reinstall them on every build.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sec450 ./sec450
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh

# Run as an unprivileged user. /data (database) and /certs are created here and
# owned by that user, so the named volumes mounted on them inherit the ownership.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin sec450 \
    && mkdir -p /data /certs \
    && chown sec450:sec450 /data /certs \
    && chmod 0755 /usr/local/bin/entrypoint.sh
USER sec450

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["python", "-m", "sec450.worker"]
