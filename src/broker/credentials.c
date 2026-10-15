// Credential store (§5.8 / §7.2): parse an INI file of "[host]" sections each
// carrying a "credential = VALUE" key. The engine holds no credentials; only
// the broker reads this file (chmod 600, root-owned in production).

#include "broker.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char* host;
    char* credential;
} cred_entry_t;

struct credential_store_t {
    cred_entry_t* entries;
    size_t count;
    size_t cap;
};

static char* trim(char* s) {
    while (*s && isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    char* end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

static int store_add(credential_store_t* store, const char* host, const char* cred) {
    if (store->count == store->cap) {
        size_t ncap = store->cap ? store->cap * 2 : 8;
        cred_entry_t* n = realloc(store->entries, ncap * sizeof(*n));
        if (!n) return -1;
        store->entries = n;
        store->cap = ncap;
    }
    char* h = strdup(host);
    char* c = strdup(cred);
    if (!h || !c) {
        free(h);
        free(c);
        return -1;
    }
    store->entries[store->count].host = h;
    store->entries[store->count].credential = c;
    store->count++;
    return 0;
}

credential_store_t* credentials_load(const char* path) {
    if (!path) {
        errno = EINVAL;
        return NULL;
    }
    FILE* f = fopen(path, "r");
    if (!f) return NULL;

    credential_store_t* store = calloc(1, sizeof(*store));
    if (!store) {
        fclose(f);
        return NULL;
    }

    char line[4096];
    char* cur_host = NULL;
    while (fgets(line, sizeof(line), f)) {
        char* p = trim(line);
        if (*p == '\0' || *p == '#' || *p == ';') continue;
        if (*p == '[') {
            char* end = strchr(p, ']');
            if (!end) {
                errno = EINVAL;
                goto fail;
            }
            *end = '\0';
            char* h = trim(p + 1);
            if (*h == '\0') {
                errno = EINVAL;
                goto fail;
            }
            char* nh = strdup(h);
            if (!nh) goto fail;
            free(cur_host);
            cur_host = nh;
            continue;
        }
        char* eq = strchr(p, '=');
        if (!eq) continue;  // unknown line shape; ignore like a lenient INI
        *eq = '\0';
        char* key = trim(p);
        char* val = trim(eq + 1);
        if (strcmp(key, "credential") == 0 && cur_host && *val) {
            if (store_add(store, cur_host, val) < 0) goto fail;
        }
    }
    free(cur_host);
    fclose(f);
    return store;

fail:
    free(cur_host);
    fclose(f);
    credentials_free(store);
    return NULL;
}

void credentials_free(credential_store_t* store) {
    if (!store) return;
    for (size_t i = 0; i < store->count; i++) {
        free(store->entries[i].host);
        free(store->entries[i].credential);
    }
    free(store->entries);
    free(store);
}

// Copy host with any ":port" removed and ASCII case folded.
static void host_key(const char* host, char* out, size_t n) {
    size_t i = 0;
    if (!host) {
        out[0] = '\0';
        return;
    }
    for (const char* p = host; *p && i + 1 < n; p++) {
        if (*p == ':') break;
        out[i++] = (char)tolower((unsigned char)*p);
    }
    out[i] = '\0';
}

const char* credential_store_lookup(const credential_store_t* store, const char* host) {
    if (!store || !host) return NULL;
    char key[256];
    host_key(host, key, sizeof(key));
    for (size_t i = 0; i < store->count; i++) {
        char entry[256];
        host_key(store->entries[i].host, entry, sizeof(entry));
        if (strcmp(entry, key) == 0) return store->entries[i].credential;
    }
    return NULL;
}
