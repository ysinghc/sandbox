#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# check-spdx — fail if any tracked source file lacks an SPDX licence tag.
#
# Scans src/, include/, tests/ and scripts/ for .c .h .hpp .cpp and .sh files
# and asserts each carries an SPDX-License-Identifier within its first three
# lines (three, not one, so a `#!/usr/bin/env bash` shebang may precede it).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$REPO_DIR"

missing=0
while IFS= read -r f; do
    if ! head -3 "$f" | grep -q 'SPDX-License-Identifier'; then
        printf 'missing SPDX header: %s\n' "$f"
        missing=1
    fi
done < <(find src include tests scripts -type f \
             \( -name '*.c' -o -name '*.h' -o -name '*.hpp' -o -name '*.cpp' -o -name '*.sh' \) \
           | sort)

if [ "$missing" -ne 0 ]; then
    echo
    echo "Add a 'SPDX-License-Identifier: GPL-2.0-only' comment to each file above."
    exit 1
fi

echo "SPDX headers OK"
