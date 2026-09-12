#!/bin/sh
# CTest FIXTURES_CLEANUP for the network test: remove everything the test may
# have leaked, including on abort/core-dump paths. Idempotent, always exits 0.
# Only touches test artifacts (sbtest* netns, tap-vmt* rules, test routes).

pkill -9 -f '[1]92\.0\.2\.1' 2>/dev/null

for ns in $(ip netns list 2>/dev/null | grep -o 'sbtest[0-9]*'); do
    ip netns del "$ns" 2>/dev/null
done

ip route del 169.254.0.2/32 2>/dev/null
ip route del 192.0.2.1/32 2>/dev/null

# Delete this run's (and any stale) tap rules by handle.
nft -a list chain ip sandbox_policy forward 2>/dev/null | grep 'tap-vmt' | \
while IFS= read -r line; do
    h=$(printf '%s' "$line" | sed -n 's/.*# handle //p')
    if [ -n "$h" ]; then
        nft delete rule ip sandbox_policy forward handle "$h" 2>/dev/null
    fi
done

# Restore the pre-test ip_forward value saved by the test itself.
if [ -f /tmp/sandbox_ipforward.txt ]; then
    read -r v < /tmp/sandbox_ipforward.txt
    if [ "$v" = "0" ] || [ "$v" = "1" ]; then
        echo "$v" > /proc/sys/net/ipv4/ip_forward 2>/dev/null
    fi
    rm -f /tmp/sandbox_ipforward.txt
fi

exit 0
