#!/bin/bash
# Double-click this file to start QuietNet.
cd "$(dirname "$0")"

# On a Mac, prefer the Python that Apple supplies: macOS lets it see the other
# devices on your network, which "Find devices on my network" depends on.
PY=""
if [ -x /usr/bin/python3 ] && /usr/bin/python3 -c "" >/dev/null 2>&1; then
  PY=/usr/bin/python3
elif command -v python3 >/dev/null; then
  PY=python3
fi
if [ -z "$PY" ]; then
  echo "QuietNet needs Python 3. Get it free from https://www.python.org/downloads/ then try again."
  read -n 1 -s -r -p "Press any key to close."
  exit 1
fi
"$PY" server.py
