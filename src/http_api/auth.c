// SPDX-License-Identifier: GPL-2.0-only
// Principals for the control-plane API (#27).
//
// A principal is whoever a request is attributed to: a bearer token's owner on
// TCP, the peer uid on the Unix socket. Sessions are owned by exactly one
// principal, and every request is scoped to the caller's own sessions.
//
//   [alice]
//   token_sha256 = <64 hex>      # sha256 of the token; the token itself is never stored
//   max_sessions = 8
//   templates    = python-agent,other
//
//   [uid:1000]                   # limits for a Unix-socket caller (no token)
//   max_sessions = 4

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "api_internal.h"
#include "sha256.h"

struct api_auth {
    api_principal_t* list;
    size_t n_tokens;
};

static char* trim(char* s) {
    while (*s && isspace((unsigned char)*s)) s++;
    char* e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = '\0';
    return s;
}

static int name_ok(const char* n) {
    size_t l = strlen(n);
    if (l == 0 || l > 63) return 0;
    for (size_t i = 0; i < l; i++)
        if (!isalnum((unsigned char)n[i]) && n[i] != '-' && n[i] != '_' && n[i] != '.' && n[i] != ':')
            return 0;
    return 1;
}

static int hex_to_bytes(const char* h, uint8_t* out, size_t n) {
    if (strlen(h) != n * 2) return -1;
    for (size_t i = 0; i < n; i++) {
        int v = 0;
        for (int k = 0; k < 2; k++) {
            char c = h[i * 2 + k];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= c - '0';
            else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10;
            else return -1;
        }
        out[i] = (uint8_t)v;
    }
    return 0;
}

static char** split_csv(const char* v) {
    char* copy = strdup(v);
    size_t cap = 8, n = 0;
    char** out = calloc(cap + 1, sizeof(*out));
    if (!copy || !out) { free(copy); free(out); return NULL; }
    char* save = NULL;
    for (char* t = strtok_r(copy, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
        t = trim(t);
        if (!*t) continue;
        if (n == cap) {
            cap *= 2;
            char** no = realloc(out, (cap + 1) * sizeof(*out));
            if (!no) break;
            out = no;
        }
        out[n++] = strdup(t);
        out[n] = NULL;
    }
    free(copy);
    return out;
}

static void free_principal(api_principal_t* p) {
    if (p->templates) {
        for (char** t = p->templates; *t; t++) free(*t);
        free(p->templates);
    }
    free(p);
}

void auth_free(api_auth_t* a) {
    if (!a) return;
    for (api_principal_t* p = a->list; p;) {
        api_principal_t* n = p->next;
        free_principal(p);
        p = n;
    }
    free(a);
}

size_t auth_count_tokens(const api_auth_t* a) { return a ? a->n_tokens : 0; }

api_auth_t* auth_load(const char* path, char* err, size_t errcap) {
    api_auth_t* a = calloc(1, sizeof(*a));
    if (!a) return NULL;
    if (!path) return a;
    struct stat st;
    if (stat(path, &st) < 0) {
        snprintf(err, errcap, "%s: %s", path, strerror(errno));
        free(a);
        return NULL;
    }
    // Whoever can write this file can mint a principal.
    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
        snprintf(err, errcap, "%s is writable by group or others; refusing it", path);
        free(a);
        return NULL;
    }
    FILE* f = fopen(path, "r");
    if (!f) {
        snprintf(err, errcap, "%s: %s", path, strerror(errno));
        free(a);
        return NULL;
    }
    api_principal_t* cur = NULL;
    char line[1024];
    int ln = 0;
    while (fgets(line, sizeof(line), f)) {
        ln++;
        char* c = strpbrk(line, "#;");
        if (c) *c = '\0';
        char* s = trim(line);
        if (!*s) continue;
        if (*s == '[') {
            char* e = strchr(s, ']');
            if (!e || e[1] != '\0') { snprintf(err, errcap, "%s:%d: bad section", path, ln); goto fail; }
            *e = '\0';
            if (!name_ok(s + 1)) { snprintf(err, errcap, "%s:%d: bad principal name", path, ln); goto fail; }
            for (api_principal_t* p = a->list; p; p = p->next)
                if (!strcmp(p->name, s + 1)) { snprintf(err, errcap, "%s:%d: duplicate principal", path, ln); goto fail; }
            cur = calloc(1, sizeof(*cur));
            if (!cur) goto fail;
            snprintf(cur->name, sizeof(cur->name), "%s", s + 1);
            cur->next = a->list;
            a->list = cur;
            continue;
        }
        char* eq = strchr(s, '=');
        if (!cur || !eq) { snprintf(err, errcap, "%s:%d: expected key = value inside a section", path, ln); goto fail; }
        *eq = '\0';
        char* k = trim(s);
        char* v = trim(eq + 1);
        if (!strcmp(k, "token_sha256")) {
            if (hex_to_bytes(v, cur->token_hash, 32) < 0) { snprintf(err, errcap, "%s:%d: token_sha256 must be 64 hex digits", path, ln); goto fail; }
            if (!cur->has_token) a->n_tokens++;
            cur->has_token = true;
        } else if (!strcmp(k, "max_sessions")) {
            char* e;
            long n = strtol(v, &e, 10);
            if (*e || n < 1 || n > 100000) { snprintf(err, errcap, "%s:%d: max_sessions must be a positive integer", path, ln); goto fail; }
            cur->max_sessions = (unsigned)n;
        } else if (!strcmp(k, "templates")) {
            cur->templates = split_csv(v);
        } else {
            snprintf(err, errcap, "%s:%d: unknown key '%s'", path, ln, k);
            goto fail;
        }
    }
    fclose(f);
    // A token that two principals share would make the second unreachable and the
    // first ambiguous.
    for (api_principal_t* p = a->list; p; p = p->next)
        for (api_principal_t* q = p->next; q; q = q->next)
            if (p->has_token && q->has_token && !memcmp(p->token_hash, q->token_hash, 32)) {
                snprintf(err, errcap, "principals %s and %s share a token", p->name, q->name);
                auth_free(a);
                return NULL;
            }
    return a;
fail:
    fclose(f);
    auth_free(a);
    return NULL;
}

const api_principal_t* auth_by_token(const api_auth_t* a, const char* token) {
    if (!a || !token || !*token) return NULL;
    uint8_t h[32];
    sha256(token, strlen(token), h);
    const api_principal_t* hit = NULL;
    // No early exit: how long this takes must not depend on which entry matched.
    for (const api_principal_t* p = a->list; p; p = p->next) {
        if (!p->has_token) continue;
        uint8_t diff = 0;
        for (int i = 0; i < 32; i++) diff |= (uint8_t)(p->token_hash[i] ^ h[i]);
        if (diff == 0) hit = p;
    }
    return hit;
}

void auth_for_uid(const api_auth_t* a, uid_t uid, api_principal_t* out) {
    memset(out, 0, sizeof(*out));
    snprintf(out->name, sizeof(out->name), "uid:%u", (unsigned)uid);
    if (!a) return;
    for (const api_principal_t* p = a->list; p; p = p->next) {
        if (strcmp(p->name, out->name) != 0) continue;
        out->max_sessions = p->max_sessions;
        out->templates = p->templates;  // borrowed: the auth set outlives callers
        return;
    }
}
