// SPDX-License-Identifier: GPL-2.0-only
// Per-session egress policy (#26): which upstream hosts a sandbox may reach.
//
// A policy is a list of entries. The guest has no network except the broker, so
// "egress" means what the broker will relay for that session's token; the list
// is copied into the token when the sandbox is created and cannot be changed by
// anything running inside the guest.
//
// Entry grammar (case-insensitive hostnames):
//   *                 any host (only meaningful as the daemon-wide ceiling)
//   *.example.org     any subdomain of example.org (not example.org itself)
//   host              exactly that host, on any port
//   host:port         exactly that host and port
//   *.example.org:443 subdomains, one port
//
// A request without an explicit port is an https request: port 443.

#ifndef EGRESS_POLICY_H
#define EGRESS_POLICY_H

#include <stdbool.h>

#define EGRESS_MAX_ENTRIES 64   // matches the token's service list
#define EGRESS_ENTRY_MAX 253    // fits the broker<->engine wire (1-byte length)

// True if `entry` is a well-formed policy entry.
bool egress_entry_valid(const char* entry);

// Does `host_header` (a Host value, optionally "host:port") fall under any entry?
// *via_named is set when the match came from an entry other than "*": the
// developer named that destination, so the broker may relay to it without a
// stored credential. A bare "*" never does -- it is a ceiling, not a statement
// of intent.
bool egress_match(char* const* entries, const char* host_header, bool* via_named);

// Is every destination `want` allows also allowed by `ceiling`? Used to keep a
// session's policy inside the daemon-wide one.
bool egress_entry_covered(const char* ceiling, const char* want);

// Work out a session's effective policy from the daemon-wide `ceiling` and what
// the developer asked for:
//   deny_all          -> empty (nothing reachable); `want` must be empty.
//   n_want == 0       -> the ceiling, unchanged (the pre-#26 behaviour).
//   otherwise         -> exactly `want`, each entry valid and covered by the
//                        ceiling, otherwise failure (never silently dropped).
// On success *out is a NULL-terminated array of malloc'd strings (free with
// egress_free) and *n_out its length. Returns 0, or -1 on an invalid or
// out-of-ceiling entry, or a conflict.
int egress_resolve(char* const* ceiling, const char* const* want, int n_want,
                   bool deny_all, char*** out, int* n_out);

void egress_free(char** entries);

#endif  // EGRESS_POLICY_H
