// SPDX-License-Identifier: GPL-2.0-only
#ifndef HTTP_API_JSON_H
#define HTTP_API_JSON_H

// Small JSON reader and writer for the control-plane API (#27). The reader is a
// bounded recursive-descent parser (size, depth and element limits: it sits
// behind a network port); the writer is a growable buffer with correct string
// escaping, including for bytes that are not valid UTF-8 (command output is
// arbitrary).

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } jtype_t;

typedef struct jv {
    jtype_t type;
    bool b;
    double num;
    int64_t i;        // valid when is_int
    bool is_int;
    char* s;          // J_STR: NUL-terminated, unescaped (may hold embedded NULs: see slen)
    size_t slen;
    struct jv** items;  // J_ARR elements, J_OBJ values
    char** keys;        // J_OBJ keys
    size_t n;
} jv_t;

#define JSON_MAX_DEPTH 16
#define JSON_MAX_ELEMS 4096

// Parse `len` bytes. NULL on error with a short message in err.
jv_t* json_parse(const char* text, size_t len, char* err, size_t errcap);
void json_free(jv_t* v);

// Object member (first match), or NULL.
const jv_t* json_get(const jv_t* obj, const char* key);
// Typed getters: return 0 and set *out if the member exists with that type,
// 1 if it is absent, -1 if present with the wrong type.
int json_get_str(const jv_t* obj, const char* key, const char** out);
int json_get_int(const jv_t* obj, const char* key, int64_t* out);
int json_get_bool(const jv_t* obj, const char* key, bool* out);

// ---- writer ----------------------------------------------------------------
typedef struct {
    char* p;
    size_t len, cap;
    bool oom;
} jbuf_t;

void jb_init(jbuf_t* b);
void jb_free(jbuf_t* b);
void jb_raw(jbuf_t* b, const char* s);
void jb_bytes(jbuf_t* b, const void* s, size_t n);
void jb_fmt(jbuf_t* b, const char* fmt, ...) __attribute__((format(printf, 2, 3)));
// A quoted JSON string. Bytes that are not valid UTF-8 become U+FFFD, so the
// output is always valid JSON.
void jb_str(jbuf_t* b, const char* s, size_t n);
void jb_cstr(jbuf_t* b, const char* s);  // NULL writes null
// Standard base64 (RFC 4648) of n bytes as a JSON string.
void jb_b64(jbuf_t* b, const void* data, size_t n);

// Base64 decode; returns the decoded length or -1. out must hold n/4*3 bytes.
ssize_t b64_decode(const char* in, size_t n, uint8_t* out);

#endif
