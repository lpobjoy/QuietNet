#!/bin/bash
# Double-click this file to start QuietNet.
cd "$(dirname "$0")"

# On a Mac without Apple's Command Line Tools, /usr/bin/python3 is only a stand-in
# that offers to install them; it can't run QuietNet. "xcode-select -p" fails then.
apple_python_is_stub() {
  [ -x /usr/bin/xcode-select ] && ! /usr/bin/xcode-select -p >/dev/null 2>&1
}

# On a Mac, prefer the Python that Apple supplies: macOS lets it see the other
# devices on your network, which "Find devices on my network" depends on.
PY=""
if [ -x /usr/bin/python3 ] && ! apple_python_is_stub && /usr/bin/python3 -c "" >/dev/null 2>&1; then
  PY=/usr/bin/python3
else
  # Otherwise any other working Python 3 (python.org, Homebrew), but never Apple's
  # stand-in again: running it a second time only ends in an error from Apple's tools.
  OTHER="$(command -v python3 2>/dev/null)"
  if [ -n "$OTHER" ] && [ "$OTHER" != /usr/bin/python3 ] && "$OTHER" -c "" >/dev/null 2>&1; then
    PY="$OTHER"
  fi
fi
if [ -z "$PY" ]; then
  echo "QuietNet needs Python 3. Either get it free from https://www.python.org/downloads/"
  echo "or install Apple's tools by typing  xcode-select --install  in Terminal, then try again."
  read -n 1 -s -r -p "Press any key to close."
  exit 1
fi
"$PY" server.py
