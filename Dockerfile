# QuietNet runs anywhere Docker does - a Raspberry Pi, a NAS, a spare PC.
# It installs NOTHING from the internet: QuietNet uses only the Python standard library.
FROM python:3.13-slim

# The only system tool QuietNet needs: the kernel's own firewall, used by the
# live-connection enforcer to drop blocked traffic. (No Python packages are installed.)
RUN apt-get update && apt-get install -y --no-install-recommends nftables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY server.py enforcer.py services.json junk_domains.txt ./
COPY static ./static

# History and your rules live here. Mount a volume so they survive restarts.
ENV QUIETNET_DATA=/data
VOLUME ["/data"]

# 53 = the DNS filter devices point at; 8377 = the dashboard.
EXPOSE 53/udp 53/tcp 8377/tcp

ENTRYPOINT ["python3", "server.py"]
CMD ["--no-browser"]
