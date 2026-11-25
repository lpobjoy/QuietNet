# QuietNet runs anywhere Docker does - a Raspberry Pi, a NAS, a spare PC.
# It installs NOTHING from the internet: QuietNet uses only the Python standard library.
FROM python:3.13-slim

# The only system tools QuietNet needs: the kernel's own firewall, used by the
# live-connection enforcer to drop blocked traffic (nftables), and the older iptables
# commands, used only to *read* the Pi's other firewall rules - Docker on some Pis keeps its
# rules where nft can't see them, and steering into a firewall we can't see could cut a
# device off. Also the time zone tables (tzdata), so schedules can follow the household's
# local time and its clock changes instead of UTC (see TZ in docker-compose.yml). And the `ip`
# tool (iproute2), to read the IPv6 neighbour table, which is how a device's IPv6 lookups are
# matched to its IPv4 address and so to its own rules.
# (No Python packages are installed.)
RUN apt-get update && apt-get install -y --no-install-recommends nftables iptables tzdata iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY server.py names.py enforcer.py announcer.py cloud_agent.py services.json junk_domains.txt ./
COPY static ./static

# History and your rules live here. Mount a volume so they survive restarts.
ENV QUIETNET_DATA=/data
# Show messages in "docker logs" straight away rather than holding them back.
ENV PYTHONUNBUFFERED=1
VOLUME ["/data"]

# 53 = the DNS filter devices point at; 8377 = the dashboard.
EXPOSE 53/udp 53/tcp 8377/tcp

ENTRYPOINT ["python3", "server.py"]
CMD ["--no-browser"]
