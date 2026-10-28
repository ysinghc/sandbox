#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# #25: the template spec is parsed as data, validated, and identified by a
# digest. Needs no root: it only runs `build-template.sh --check`.
set -u
cd "$(dirname "$0")/.."
BT=scripts/build-template.sh
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
fail=0
ok()  { printf '[test] %-62s PASS\n' "$1"; }
bad() { printf '[test] %-62s FAIL\n' "$1"; fail=$((fail + 1)); }
mk()  { mkdir -p "$T/$1"; printf '%b' "$2" > "$T/$1/template.conf"; }
rejects() { # name spec expected-message
    mk "$1" "$2"
    out="$(bash $BT "$T/$1" --check 2>&1)"; rc=$?
    if [ $rc -ne 0 ] && grep -q -- "$3" <<<"$out"; then ok "rejects: $1"; else bad "rejects: $1 (rc=$rc: $out)"; fi
}

out="$(bash $BT templates/python-agent --check 2>&1)" && grep -q '^spec_sha256=[0-9a-f]\{64\}$' <<<"$out" \
    && ok "the checked-in python-agent spec is valid" || bad "the checked-in python-agent spec is valid ($out)"

mk same 'base=debian\npackages=git\n'
mk same2 'base=debian\npackages=git\n'
mk diff 'base=debian\npackages=curl\n'
a="$(bash $BT "$T/same" --check | grep spec_sha256)"
b="$(bash $BT "$T/same2" --check | grep spec_sha256)"
c="$(bash $BT "$T/diff" --check | grep spec_sha256)"
[ -n "$a" ] && [ "$a" = "$b" ] && ok "the same spec has the same digest" || bad "the same spec has the same digest"
[ "$a" != "$c" ] && ok "a different spec has a different digest" || bad "a different spec has a different digest"

mk prov 'base=debian\nprovision=p.sh\n'
echo 'echo one' > "$T/prov/p.sh"
p1="$(bash $BT "$T/prov" --check | grep spec_sha256)"
echo 'echo two' > "$T/prov/p.sh"
p2="$(bash $BT "$T/prov" --check | grep spec_sha256)"
[ "$p1" != "$p2" ] && ok "the provision script is part of the digest" || bad "the provision script is part of the digest"

mk comments '# a comment\n\nbase=debian   # trailing\npackages=git\n'
bash $BT "$T/comments" --check >/dev/null 2>&1 && ok "comments and blank lines are fine" || bad "comments and blank lines are fine"

rejects unknown-key   'base=debian\nfoo=bar\n'                    "unknown key 'foo'"
rejects not-kv        'base=debian\njust words\n'                 "expected key=value"
rejects bad-base      'base=alpine\n'                             "not supported"
rejects bad-packages  'base=debian\npackages=git;rm -rf /\n'     "bad packages"
rejects bad-suite     'base=debian\nsuite=../x\n'                 "bad suite"
rejects bad-snapshot  'base=debian\nsnapshot=yesterday\n'         "snapshot must"
rejects zero-memory   'base=debian\nmemory_mib=0\n'               "positive integer"
rejects traversal     'base=debian\nprovision=../../etc/passwd\n' "file name in the spec directory"
rejects missing-prov  'base=debian\nprovision=nope.sh\n'          "not found"
# A spec is data: shell syntax in a value must never run.
mk inject 'base=debian\ndescription=$(touch '"$T"'/pwned)\n'
bash $BT "$T/inject" --check >/dev/null 2>&1
[ ! -e "$T/pwned" ] && ok "shell syntax in a value is not executed" || bad "shell syntax in a value is not executed"

bash $BT "$T/nonexistent" --check >/dev/null 2>&1 && bad "a missing spec is an error" || ok "a missing spec is an error"
if [ $fail -eq 0 ]; then echo "ALL PASSED"; else echo "FAILED ($fail)"; fi
exit $((fail ? 1 : 0))
