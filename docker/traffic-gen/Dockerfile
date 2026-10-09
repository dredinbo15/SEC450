# Lab traffic generator: sends normal and attack traffic to the lab servers.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
RUN pip install --no-cache-dir paramiko==3.5.0 \
    && useradd --uid 10002 --no-create-home --shell /usr/sbin/nologin traffic
WORKDIR /app
COPY traffic.py .
USER traffic
CMD ["python", "traffic.py"]
