// SPDX-License-Identifier: GPL-2.0-only
// #27: the control-plane JSON reader/writer. It sits behind a network port, so the
// parser's limits and its refusals matter as much as its happy path.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/http_api/json.h"

static int g_fail;
#define CHECK(c, m) do { if (c) printf("[test] %-64s PASS\n", m); else { printf("[test] %-64s FAIL\n", m); g_fail++; } } while (0)

static jv_t* P(const char* s) { char e[96]; return json_parse(s, strlen(s), e, sizeof(e)); }
static int bad(const char* s) { jv_t* v = P(s); if (v) { json_free(v); return 0; } return 1; }

int main(void) {
    jv_t* v = P("{\"a\":1,\"b\":\"x\\ny\",\"c\":[true,false,null,2.5],\"d\":{\"e\":-7}}");
    CHECK(v && v->type == J_OBJ && v->n == 4, "an object parses");
    int64_t i; const char* s; bool b;
    CHECK(json_get_int(v, "a", &i) == 0 && i == 1, "integer member");
    CHECK(json_get_str(v, "b", &s) == 0 && !strcmp(s, "x\ny"), "string member with an escape");
    CHECK(json_get_int(v, "b", &i) == -1 && json_get_str(v, "zz", &s) == 1, "wrong type is -1, absent is 1");
    const jv_t* c = json_get(v, "c");
    CHECK(c && c->type == J_ARR && c->n == 4 && c->items[0]->b && !c->items[1]->b &&
              c->items[2]->type == J_NULL && c->items[3]->num == 2.5 && !c->items[3]->is_int,
          "array of mixed values");
    CHECK(json_get_int(json_get(v, "d"), "e", &i) == 0 && i == -7, "nested object, negative integer");
    json_free(v);

    v = P("\"\\u00e9\\ud83d\\ude00\"");
    CHECK(v && v->type == J_STR && !strcmp(v->s, "\xc3\xa9\xf0\x9f\x98\x80"), "\\u escapes and a surrogate pair become UTF-8");
    json_free(v);
    v = P("  [ ]  "); CHECK(v && v->type == J_ARR && v->n == 0, "whitespace and an empty array"); json_free(v);
    v = P("\"a\\u0000b\"");
    CHECK(v && v->slen == 3, "an escaped NUL keeps the string's length"); json_free(v);

    CHECK(bad(""), "empty input is refused");
    CHECK(bad("{"), "an unterminated object is refused");
    CHECK(bad("{\"a\":1,}") && bad("[1,]"), "trailing commas are refused");
    CHECK(bad("{'a':1}"), "single quotes are refused");
    CHECK(bad("{\"a\":1} x"), "trailing data is refused");
    CHECK(bad("\"a\nb\""), "a raw newline in a string is refused");
    CHECK(bad("\"\\ud800\"") && bad("\"\\udc00\""), "lone surrogates are refused");
    CHECK(bad("\"\\x41\""), "an unknown escape is refused");
    CHECK(bad("01x") && bad("-"), "malformed numbers are refused");
    CHECK(bad("nul") && bad("tru"), "truncated literals are refused");

    char deep[64 + 1];
    memset(deep, '[', 40); deep[40] = '\0';
    CHECK(bad(deep), "nesting past the depth limit is refused");
    char* many = malloc(JSON_MAX_ELEMS * 2 + 16);
    strcpy(many, "[");
    for (int k = 0; k < JSON_MAX_ELEMS + 10; k++) strcat(many, k ? ",1" : "1");
    strcat(many, "]");
    CHECK(bad(many), "more elements than the limit is refused");
    free(many);

    jbuf_t w; jb_init(&w);
    jb_str(&w, "a\"b\\c\n\t\x01", 8);
    CHECK(!strcmp(w.p, "\"a\\\"b\\\\c\\n\\t\\u0001\""), "writer escapes quotes, backslashes and controls");
    jb_free(&w); jb_init(&w);
    jb_str(&w, "ok\xff\xfe" "end\xc3\xa9", 9);
    CHECK(!strcmp(w.p, "\"ok\xef\xbf\xbd\xef\xbf\xbd" "end\xc3\xa9\""), "invalid UTF-8 becomes U+FFFD, valid UTF-8 is kept");
    jb_free(&w); jb_init(&w);
    jb_str(&w, "\xed\xa0\x80\xc0\xaf", 5);  // encoded surrogate, overlong '/'
    CHECK(strstr(w.p, "\xed") == NULL && strstr(w.p, "\xc0") == NULL, "encoded surrogates and overlong forms are replaced");
    jb_free(&w); jb_init(&w);
    jb_str(&w, "x", 1); { jv_t* r = json_parse(w.p, w.len, NULL, 0); CHECK(r && r->type == J_STR, "writer output parses back"); json_free(r); }
    jb_free(&w); jb_init(&w);
    for (int k = 0; k < 2000; k++) jb_fmt(&w, "item-%d,", k);
    CHECK(w.len > 10000 && !w.oom, "the buffer grows past its first allocation");
    jb_free(&w);

    const char* vec[][2] = { {"", ""}, {"f", "Zg=="}, {"fo", "Zm8="}, {"foo", "Zm9v"}, {"foob", "Zm9vYg=="}, {"fooba", "Zm9vYmE="}, {"foobar", "Zm9vYmFy"} };
    int ok = 1;
    for (int k = 0; k < 7; k++) {
        jb_init(&w); jb_b64(&w, vec[k][0], strlen(vec[k][0]));
        char want[32]; snprintf(want, sizeof(want), "\"%s\"", vec[k][1]);
        if (strcmp(w.p, want)) ok = 0;
        uint8_t out[16]; ssize_t n = b64_decode(vec[k][1], strlen(vec[k][1]), out);
        if (n != (ssize_t)strlen(vec[k][0]) || memcmp(out, vec[k][0], (size_t)n)) ok = 0;
        jb_free(&w);
    }
    CHECK(ok, "base64 matches the RFC 4648 vectors both ways");
    uint8_t o2[8];
    CHECK(b64_decode("Zm9", 3, o2) < 0 && b64_decode("Zm9v!A==", 8, o2) < 0 && b64_decode("Z===", 4, o2) < 0,
          "malformed base64 is refused");

    printf("%s\n", g_fail ? "FAILED" : "ALL PASSED");
    return g_fail ? 1 : 0;
}
