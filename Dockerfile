# QuietNet runs anywhere Docker does - a Raspberry Pi, a NAS, a spare PC.
# It installs NOTHING from the internet: QuietNet uses only the Python standard library.
FROM python:3.13-slim

WORKDIR /app
COPY server.py services.json junk_domains.txt ./
COPY static ./static

# History and your rules live here. Mount a volume so they survive restarts.
ENV QUIETNET_DATA=/data
VOLUME ["/data"]

# 53 = the DNS filter devices point at; 8377 = the dashboard.
EXPOSE 53/udp 53/tcp 8377/tcp

ENTRYPOINT ["python3", "server.py"]
CMD ["--no-browser"]
