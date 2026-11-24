# The QuietNet relay (host this on Railway or any Docker host).
# Build context must be the repository root so it can include the dashboard.
# Uses only the Python standard library - nothing is installed.
FROM python:3.13-slim
WORKDIR /app
COPY cloud/relay.py ./relay.py
COPY static ./static
ENV QUIETNET_RELAY_DATA=/data
# Write each log line out at once: the host reads the output through a pipe, which Python would
# otherwise hold back in a buffer (and lose if the relay is stopped first).
ENV PYTHONUNBUFFERED=1
# Attach a persistent volume at /data in your host (on Railway: add a Volume mounted
# at /data) so accounts survive redeploys. No VOLUME line here - Railway rejects it.
# Railway sets $PORT; relay.py reads it (defaults to 8080 locally).
# No USER line: the container starts as root so the relay can take over Railway's root-owned
# volume. relay.py then hands /data to the "nobody" user (or QUIETNET_RUN_AS=uid:gid) and stops
# being root before it answers any request.
CMD ["python3", "relay.py"]
