// SPDX-License-Identifier: GPL-2.0-only
// Per-session egress policy (#26). See include/egress_policy.h.

#include "egress_policy.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

enum { K_ANY, K_SUFFIX, K_HOST };

typedef struct {
    int kind;
    char name[EGRESS_ENTRY_MAX + 1];  // lowercase; suffix without the "*."
    unsigned port;                    // 0 = any
} pat_t;

static bool label_char(char c) {
    return isalnum((unsigned char)c) || c == '-' || c == '_';
}

// Hostname (or IPv4 literal): dot-separated non-empty labels of [A-Za-z0-9_-].
static bool host_ok(const char* h) {
    size_t n = strlen(h);
    if (n == 0 || n > 253) return false;
    size_t run = 0;
    for (size_t i = 0; i < n; i++) {
        if (h[i] == '.') {
            if (run == 0) return false;
            run = 0;
        } else if (label_char(h[i])) {
            if (++run > 63) return false;
        } else {
            return false;
        }
    }
    return run > 0;
}

static bool parse_port(const char* s, unsigned* out) {
    if (!*s || strlen(s) > 5) return false;
    unsigned v = 0;
    for (; *s; s++) {
        if (!isdigit((unsigned char)*s)) return false;
        v = v * 10 + (unsigned)(*s - '0');
    }
    if (v == 0 || v > 65535) return false;
    *out = v;
    return true;
}

// Split "name[:port]" into lowercase name and port. IPv6 literals are not
// supported (the broker is name-based), so one colon at most.
static bool split_hostport(const char* s, char* name, size_t cap, unsigned* port) {
    *port = 0;
    const char* colon = strchr(s, ':');
    size_t nl = colon ? (size_t)(colon - s) : strlen(s);
    if (nl == 0 || nl >= cap) return false;
    if (colon) {
        if (strchr(colon + 1, ':')) return false;
        if (!parse_port(colon + 1, port)) return false;
    }
    for (size_t i = 0; i < nl; i++) name[i] = (char)tolower((unsigned char)s[i]);
    name[nl] = '\0';
    return true;
}

static bool parse_entry(const char* e, pat_t* p) {
    memset(p, 0, sizeof(*p));
    if (!e || !*e || strlen(e) > EGRESS_ENTRY_MAX) return false;
    if (strcmp(e, "*") == 0) {
        p->kind = K_ANY;
        return true;
    }
    char name[EGRESS_ENTRY_MAX + 1];
    unsigned port;
    if (!split_hostport(e, name, sizeof(name), &port)) return false;
    if (strncmp(name, "*.", 2) == 0) {
        if (!host_ok(name + 2)) return false;
        p->kind = K_SUFFIX;
        memcpy(p->name, name + 2, strlen(name + 2) + 1);
    } else {
        if (!host_ok(name)) return false;
        p->kind = K_HOST;
        memcpy(p->name, name, strlen(name) + 1);
    }
    p->port = port;
    return true;
}

bool egress_entry_valid(const char* entry) {
    pat_t p;
    return parse_entry(entry, &p);
}

static bool ends_with_label(const char* host, const char* suffix) {
    size_t hl = strlen(host), sl = strlen(suffix);
    return hl > sl && host[hl - sl - 1] == '.' && strcmp(host + hl - sl, suffix) == 0;
}

bool egress_match(char* const* entries, const char* host_header, bool* via_named) {
    if (via_named) *via_named = false;
    if (!entries || !host_header || !*host_header) return false;
    char host[EGRESS_ENTRY_MAX + 1];
    unsigned port;
    if (!split_hostport(host_header, host, sizeof(host), &port)) return false;
    if (port == 0) port = 443;
    bool matched = false;
    for (char* const* p = entries; *p; p++) {
        pat_t e;
        if (!parse_entry(*p, &e)) continue;  // a malformed entry allows nothing
        bool hit = false;
        if (e.kind == K_ANY) {
            hit = true;
        } else {
            if (e.port && e.port != port) continue;
            hit = e.kind == K_HOST ? strcmp(e.name, host) == 0
                                   : ends_with_label(host, e.name);
        }
        if (!hit) continue;
        matched = true;
        if (e.kind != K_ANY) {
            if (via_named) *via_named = true;
            break;  // named is the stronger fact; no need to look further
        }
    }
    return matched;
}

bool egress_entry_covered(const char* ceiling, const char* want) {
    pat_t c, w;
    if (!parse_entry(ceiling, &c) || !parse_entry(want, &w)) return false;
    if (c.kind == K_ANY) return true;
    if (w.kind == K_ANY) return false;
    if (c.port && c.port != w.port) return false;  // want's "any port" is wider
    if (c.kind == K_HOST) return w.kind == K_HOST && strcmp(c.name, w.name) == 0;
    // c is a suffix: covers a suffix at or below it, or a host under it.
    if (w.kind == K_SUFFIX)
        return strcmp(c.name, w.name) == 0 || ends_with_label(w.name, c.name);
    return ends_with_label(w.name, c.name);
}

void egress_free(char** entries) {
    if (!entries) return;
    for (char** p = entries; *p; p++) free(*p);
    free(entries);
}

static char** dup_list(const char* const* src, int n) {
    char** out = calloc((size_t)n + 1, sizeof(char*));
    if (!out) return NULL;
    for (int i = 0; i < n; i++) {
        out[i] = strdup(src[i]);
        if (!out[i]) {
            egress_free(out);
            return NULL;
        }
    }
    return out;
}

int egress_resolve(char* const* ceiling, const char* const* want, int n_want,
                   bool deny_all, char*** out, int* n_out) {
    if (!out || !n_out) return -1;
    *out = NULL;
    *n_out = 0;
    if (n_want < 0 || n_want > EGRESS_MAX_ENTRIES) return -1;
    if (deny_all && n_want > 0) return -1;  // contradictory

    if (deny_all) {
        *out = calloc(1, sizeof(char*));
        return *out ? 0 : -1;
    }
    if (n_want == 0) {
        int n = 0;
        while (ceiling && ceiling[n]) n++;
        *out = dup_list((const char* const*)ceiling, n);
        if (!*out) return -1;
        *n_out = n;
        return 0;
    }
    for (int i = 0; i < n_want; i++) {
        if (!want[i] || !egress_entry_valid(want[i])) return -1;
        bool ok = false;
        for (char* const* c = ceiling; c && *c && !ok; c++)
            ok = egress_entry_covered(*c, want[i]);
        if (!ok) return -1;
    }
    *out = dup_list(want, n_want);
    if (!*out) return -1;
    *n_out = n_want;
    return 0;
}
