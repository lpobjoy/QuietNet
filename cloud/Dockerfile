# The QuietNet relay (host this on Railway or any Docker host).
# Build context must be the repository root so it can include the dashboard.
# Uses only the Python standard library - nothing is installed.
FROM python:3.13-slim
WORKDIR /app
COPY cloud/relay.py ./relay.py
COPY static ./static
ENV QUIETNET_RELAY_DATA=/data
# Attach a persistent volume at /data in your host (on Railway: add a Volume mounted
# at /data) so accounts survive redeploys. No VOLUME line here - Railway rejects it.
# Railway sets $PORT; relay.py reads it (defaults to 8080 locally).
CMD ["python3", "relay.py"]
