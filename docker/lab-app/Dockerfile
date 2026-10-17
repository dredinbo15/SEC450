# Lab application server (DD-03): a small JSON API reached through the lab nginx.
# Its log goes to /var/log/app on a named volume the collector mounts read-only (DD-04).
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
RUN useradd --uid 10003 --no-create-home --shell /usr/sbin/nologin app \
    && mkdir -p /var/log/app && chown app /var/log/app
WORKDIR /app
COPY app.py .
USER app
EXPOSE 8080
CMD ["python", "app.py"]
