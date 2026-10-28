// SPDX-License-Identifier: GPL-2.0-only
#include "json.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

// ---- reader ----------------------------------------------------------------

typedef struct {
    const char* start;
    const char* p;
    const char* end;
    char* err;
    size_t errcap;
    size_t elems;
} parser_t;

static jv_t* fail(parser_t* ps, const char* msg) {
    if (ps->err && ps->errcap)
        snprintf(ps->err, ps->errcap, "%s at byte %zu", msg, (size_t)(ps->p - ps->start));
    return NULL;
}

static void skip_ws(parser_t* ps) {
    while (ps->p < ps->end && (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r'))
        ps->p++;
}

static jv_t* new_v(jtype_t t) {
    jv_t* v = calloc(1, sizeof(*v));
    if (v) v->type = t;
    return v;
}

void json_free(jv_t* v) {
    if (!v) return;
    free(v->s);
    for (size_t i = 0; i < v->n; i++) {
        json_free(v->items[i]);
        if (v->keys) free(v->keys[i]);
    }
    free(v->items);
    free(v->keys);
    free(v);
}

static int hex4(const char* p, uint32_t* out) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        char c = p[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (uint32_t)(c - 'A' + 10);
        else return -1;
    }
    *out = v;
    return 0;
}

static size_t put_utf8(char* o, uint32_t cp) {
    if (cp < 0x80) { o[0] = (char)cp; return 1; }
    if (cp < 0x800) { o[0] = (char)(0xC0 | (cp >> 6)); o[1] = (char)(0x80 | (cp & 0x3F)); return 2; }
    if (cp < 0x10000) {
        o[0] = (char)(0xE0 | (cp >> 12)); o[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        o[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    }
    o[0] = (char)(0xF0 | (cp >> 18)); o[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    o[2] = (char)(0x80 | ((cp >> 6) & 0x3F)); o[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}

// Parses a string whose opening quote has been consumed. Returns malloc'd text.
static char* parse_string(parser_t* ps, size_t* outlen) {
    size_t cap = 32, n = 0;
    char* o = malloc(cap);
    if (!o) return NULL;
    for (;;) {
        if (ps->p >= ps->end) goto bad;
        unsigned char c = (unsigned char)*ps->p++;
        if (n + 8 > cap) {
            cap *= 2;
            char* t = realloc(o, cap);
            if (!t) goto bad;
            o = t;
        }
        if (c == '"') break;
        if (c < 0x20) goto bad;  // raw control characters are not JSON
        if (c != '\\') { o[n++] = (char)c; continue; }
        if (ps->p >= ps->end) goto bad;
        char e = *ps->p++;
        switch (e) {
        case '"': o[n++] = '"'; break;
        case '\\': o[n++] = '\\'; break;
        case '/': o[n++] = '/'; break;
        case 'b': o[n++] = '\b'; break;
        case 'f': o[n++] = '\f'; break;
        case 'n': o[n++] = '\n'; break;
        case 'r': o[n++] = '\r'; break;
        case 't': o[n++] = '\t'; break;
        case 'u': {
            uint32_t cp;
            if (ps->end - ps->p < 4 || hex4(ps->p, &cp) < 0) goto bad;
            ps->p += 4;
            if (cp >= 0xD800 && cp <= 0xDBFF) {  // high surrogate: needs a low one
                uint32_t lo;
                if (ps->end - ps->p < 6 || ps->p[0] != '\\' || ps->p[1] != 'u' ||
                    hex4(ps->p + 2, &lo) < 0 || lo < 0xDC00 || lo > 0xDFFF)
                    goto bad;
                ps->p += 6;
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                goto bad;  // lone low surrogate
            }
            n += put_utf8(o + n, cp);
            break;
        }
        default: goto bad;
        }
    }
    o[n] = '\0';
    if (outlen) *outlen = n;
    return o;
bad:
    free(o);
    return NULL;
}

static jv_t* parse_value(parser_t* ps, int depth);

static int grow(jv_t* v, size_t* cap, int is_obj) {
    if (v->n < *cap) return 0;
    size_t nc = *cap ? *cap * 2 : 4;
    jv_t** ni = realloc(v->items, nc * sizeof(*ni));
    if (!ni) return -1;
    v->items = ni;
    if (is_obj) {
        char** nk = realloc(v->keys, nc * sizeof(*nk));
        if (!nk) return -1;
        v->keys = nk;
    }
    *cap = nc;
    return 0;
}

static jv_t* parse_container(parser_t* ps, int depth, int is_obj) {
    jv_t* v = new_v(is_obj ? J_OBJ : J_ARR);
    if (!v) return NULL;
    size_t cap = 0;
    skip_ws(ps);
    char close = is_obj ? '}' : ']';
    if (ps->p < ps->end && *ps->p == close) { ps->p++; return v; }
    for (;;) {
        if (++ps->elems > JSON_MAX_ELEMS) { json_free(v); return fail(ps, "too many elements"); }
        if (grow(v, &cap, is_obj) < 0) { json_free(v); return NULL; }
        char* key = NULL;
        if (is_obj) {
            skip_ws(ps);
            if (ps->p >= ps->end || *ps->p != '"') { json_free(v); return fail(ps, "expected a string key"); }
            ps->p++;
            key = parse_string(ps, NULL);
            if (!key) { json_free(v); return fail(ps, "bad string"); }
            skip_ws(ps);
            if (ps->p >= ps->end || *ps->p != ':') { free(key); json_free(v); return fail(ps, "expected ':'"); }
            ps->p++;
        }
        jv_t* item = parse_value(ps, depth + 1);
        if (!item) { free(key); json_free(v); return NULL; }
        v->items[v->n] = item;
        if (is_obj) v->keys[v->n] = key;
        v->n++;
        skip_ws(ps);
        if (ps->p >= ps->end) { json_free(v); return fail(ps, "unterminated"); }
        if (*ps->p == ',') { ps->p++; continue; }
        if (*ps->p == close) { ps->p++; return v; }
        json_free(v);
        return fail(ps, "expected ',' or closing bracket");
    }
}

static jv_t* parse_value(parser_t* ps, int depth) {
    if (depth > JSON_MAX_DEPTH) return fail(ps, "nested too deeply");
    skip_ws(ps);
    if (ps->p >= ps->end) return fail(ps, "unexpected end");
    char c = *ps->p;
    if (c == '{') { ps->p++; return parse_container(ps, depth, 1); }
    if (c == '[') { ps->p++; return parse_container(ps, depth, 0); }
    if (c == '"') {
        ps->p++;
        jv_t* v = new_v(J_STR);
        if (!v) return NULL;
        v->s = parse_string(ps, &v->slen);
        if (!v->s) { json_free(v); return fail(ps, "bad string"); }
        return v;
    }
    if (ps->end - ps->p >= 4 && !strncmp(ps->p, "true", 4)) { ps->p += 4; jv_t* v = new_v(J_BOOL); if (v) v->b = true; return v; }
    if (ps->end - ps->p >= 5 && !strncmp(ps->p, "false", 5)) { ps->p += 5; return new_v(J_BOOL); }
    if (ps->end - ps->p >= 4 && !strncmp(ps->p, "null", 4)) { ps->p += 4; return new_v(J_NULL); }
    if (c == '-' || (c >= '0' && c <= '9')) {
        char buf[40];
        size_t n = 0;
        int is_int = 1;
        while (ps->p < ps->end && n < sizeof(buf) - 1) {
            char d = *ps->p;
            if ((d >= '0' && d <= '9') || d == '-' || d == '+') buf[n++] = d;
            else if (d == '.' || d == 'e' || d == 'E') { buf[n++] = d; is_int = 0; }
            else break;
            ps->p++;
        }
        buf[n] = '\0';
        char* e;
        errno = 0;
        double d = strtod(buf, &e);
        if (*e || errno == ERANGE) return fail(ps, "bad number");
        jv_t* v = new_v(J_NUM);
        if (!v) return NULL;
        v->num = d;
        if (is_int) {
            errno = 0;
            long long ll = strtoll(buf, &e, 10);
            if (!*e && errno != ERANGE) { v->is_int = true; v->i = ll; }
        }
        return v;
    }
    return fail(ps, "unexpected character");
}

jv_t* json_parse(const char* text, size_t len, char* err, size_t errcap) {
    parser_t ps = { .start = text, .p = text, .end = text + len, .err = err, .errcap = errcap };
    if (err && errcap) err[0] = '\0';
    jv_t* v = parse_value(&ps, 0);
    if (!v) {
        if (err && errcap && !err[0]) snprintf(err, errcap, "invalid JSON");
        return NULL;
    }
    skip_ws(&ps);
    if (ps.p != ps.end) {
        json_free(v);
        if (err && errcap) snprintf(err, errcap, "trailing data after the JSON value");
        return NULL;
    }
    return v;
}

const jv_t* json_get(const jv_t* obj, const char* key) {
    if (!obj || obj->type != J_OBJ) return NULL;
    for (size_t i = 0; i < obj->n; i++)
        if (!strcmp(obj->keys[i], key)) return obj->items[i];
    return NULL;
}

int json_get_str(const jv_t* obj, const char* key, const char** out) {
    const jv_t* v = json_get(obj, key);
    if (!v || v->type == J_NULL) return 1;
    if (v->type != J_STR) return -1;
    *out = v->s;
    return 0;
}

int json_get_int(const jv_t* obj, const char* key, int64_t* out) {
    const jv_t* v = json_get(obj, key);
    if (!v || v->type == J_NULL) return 1;
    if (v->type != J_NUM || !v->is_int) return -1;
    *out = v->i;
    return 0;
}

int json_get_bool(const jv_t* obj, const char* key, bool* out) {
    const jv_t* v = json_get(obj, key);
    if (!v || v->type == J_NULL) return 1;
    if (v->type != J_BOOL) return -1;
    *out = v->b;
    return 0;
}

// ---- writer ----------------------------------------------------------------

void jb_init(jbuf_t* b) { memset(b, 0, sizeof(*b)); }
void jb_free(jbuf_t* b) { free(b->p); memset(b, 0, sizeof(*b)); }

static int jb_reserve(jbuf_t* b, size_t extra) {
    if (b->oom) return -1;
    if (b->len + extra + 1 <= b->cap) return 0;
    size_t nc = b->cap ? b->cap : 256;
    while (nc < b->len + extra + 1) nc *= 2;
    char* np = realloc(b->p, nc);
    if (!np) { b->oom = true; return -1; }
    b->p = np;
    b->cap = nc;
    return 0;
}

void jb_bytes(jbuf_t* b, const void* s, size_t n) {
    if (jb_reserve(b, n) < 0) return;
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = '\0';
}

void jb_raw(jbuf_t* b, const char* s) { jb_bytes(b, s, strlen(s)); }

void jb_fmt(jbuf_t* b, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char tmp[512];
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0) { b->oom = true; return; }
    if ((size_t)n < sizeof(tmp)) { jb_bytes(b, tmp, (size_t)n); return; }
    if (jb_reserve(b, (size_t)n) < 0) return;
    va_start(ap, fmt);
    vsnprintf(b->p + b->len, (size_t)n + 1, fmt, ap);
    va_end(ap);
    b->len += (size_t)n;
}

// Length of the valid UTF-8 sequence at s (0 if invalid).
static size_t utf8_len(const unsigned char* s, size_t n) {
    if (s[0] < 0x80) return 1;
    if (s[0] >= 0xC2 && s[0] <= 0xDF) return (n >= 2 && (s[1] & 0xC0) == 0x80) ? 2 : 0;
    if (s[0] >= 0xE0 && s[0] <= 0xEF) {
        if (n < 3 || (s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80) return 0;
        if (s[0] == 0xE0 && s[1] < 0xA0) return 0;   // overlong
        if (s[0] == 0xED && s[1] >= 0xA0) return 0;  // surrogate
        return 3;
    }
    if (s[0] >= 0xF0 && s[0] <= 0xF4) {
        if (n < 4 || (s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80 || (s[3] & 0xC0) != 0x80) return 0;
        if (s[0] == 0xF0 && s[1] < 0x90) return 0;
        if (s[0] == 0xF4 && s[1] >= 0x90) return 0;
        return 4;
    }
    return 0;
}

void jb_str(jbuf_t* b, const char* s, size_t n) {
    jb_bytes(b, "\"", 1);
    const unsigned char* u = (const unsigned char*)s;
    for (size_t i = 0; i < n;) {
        unsigned char c = u[i];
        if (c == '"') { jb_bytes(b, "\\\"", 2); i++; }
        else if (c == '\\') { jb_bytes(b, "\\\\", 2); i++; }
        else if (c == '\n') { jb_bytes(b, "\\n", 2); i++; }
        else if (c == '\r') { jb_bytes(b, "\\r", 2); i++; }
        else if (c == '\t') { jb_bytes(b, "\\t", 2); i++; }
        else if (c < 0x20 || c == 0x7f) { jb_fmt(b, "\\u%04x", c); i++; }
        else if (c < 0x80) { jb_bytes(b, &u[i], 1); i++; }
        else {
            size_t l = utf8_len(u + i, n - i);
            if (l) { jb_bytes(b, u + i, l); i += l; }
            else { jb_bytes(b, "\xEF\xBF\xBD", 3); i++; }  // U+FFFD
        }
    }
    jb_bytes(b, "\"", 1);
}

void jb_cstr(jbuf_t* b, const char* s) {
    if (!s) jb_raw(b, "null");
    else jb_str(b, s, strlen(s));
}

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void jb_b64(jbuf_t* b, const void* data, size_t n) {
    const uint8_t* d = data;
    jb_bytes(b, "\"", 1);
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)d[i] << 16;
        if (i + 1 < n) v |= (uint32_t)d[i + 1] << 8;
        if (i + 2 < n) v |= d[i + 2];
        char q[4] = { B64[v >> 18], B64[(v >> 12) & 63],
                      i + 1 < n ? B64[(v >> 6) & 63] : '=',
                      i + 2 < n ? B64[v & 63] : '=' };
        jb_bytes(b, q, 4);
    }
    jb_bytes(b, "\"", 1);
}

ssize_t b64_decode(const char* in, size_t n, uint8_t* out) {
    if (n % 4) return -1;
    size_t o = 0;
    for (size_t i = 0; i < n; i += 4) {
        int v[4], pad = 0;
        for (int k = 0; k < 4; k++) {
            char c = in[i + k];
            if (c >= 'A' && c <= 'Z') v[k] = c - 'A';
            else if (c >= 'a' && c <= 'z') v[k] = c - 'a' + 26;
            else if (c >= '0' && c <= '9') v[k] = c - '0' + 52;
            else if (c == '+') v[k] = 62;
            else if (c == '/') v[k] = 63;
            else if (c == '=' && i + 4 == n && k >= 2) { v[k] = 0; pad++; }
            else return -1;
        }
        if (pad == 1 && in[i + 2] == '=') return -1;  // "=x" is not padding
        uint32_t x = ((uint32_t)v[0] << 18) | ((uint32_t)v[1] << 12) | ((uint32_t)v[2] << 6) | (uint32_t)v[3];
        out[o++] = (uint8_t)(x >> 16);
        if (pad < 2) out[o++] = (uint8_t)(x >> 8);
        if (pad < 1) out[o++] = (uint8_t)x;
    }
    return (ssize_t)o;
}
