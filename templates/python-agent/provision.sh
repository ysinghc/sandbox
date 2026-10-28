#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Runs as root inside the new image, after the packages are installed. Keep it
# deterministic: no unpinned downloads, no dates, no random values.
set -euo pipefail

# Lets a guest (and a person debugging one) tell which template it came from.
echo "python-agent" > /etc/sandbox-template

# Compile the standard library's bytecode now, so a read-only root never has to.
python3 -m compileall -q /usr/lib/python3 >/dev/null 2>&1 || true
