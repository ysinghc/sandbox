// SPDX-License-Identifier: GPL-2.0-only
// #26: the per-session egress policy (include/egress_policy.h): entry grammar,
// matching, the daemon-wide ceiling, and how a session's policy is resolved.
// Pure logic, no root and no sockets.

#include "egress_policy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(c, m)                                   \
    do {                                              \
        if (!(c)) {                                   \
            fprintf(stderr, "  FAIL: %s\n", (m));     \
            g_fail++;                                 \
        }                                             \
    } while (0)

static int m(char* const* l, const char* host) { return egress_match(l, host, NULL); }

static void test_grammar(void) {
    const char* ok[] = {"pypi.org", "pypi.org:443", "*.pythonhosted.org", "*.x.org:8443",
                        "127.0.0.1", "127.0.0.1:8080", "a", "my_host-1.example.com",
                        "PyPI.org", "*"};
    for (size_t i = 0; i < sizeof(ok) / sizeof(*ok); i++) {
        char msg[128];
        snprintf(msg, sizeof(msg), "valid: %s", ok[i]);
        CHECK(egress_entry_valid(ok[i]), msg);
    }
    const char* bad[] = {"", NULL, "a b", "pypi.org:", "pypi.org:0", "pypi.org:65536",
                         "pypi.org:80:80", ".pypi.org", "pypi..org", "pypi.org.", "*.",
                         "*pypi.org", "foo.*.org", "**", "*.*.org", "http://pypi.org",
                         "pypi.org/simple", "[::1]", "pypi.org:12x", "a\nb", "-:1:"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); i++) {
        char msg[128];
        snprintf(msg, sizeof(msg), "invalid: %s", bad[i] ? bad[i] : "(null)");
        CHECK(!egress_entry_valid(bad[i]), msg);
    }
    char longname[400];
    memset(longname, 'a', sizeof(longname));
    longname[sizeof(longname) - 1] = '\0';
    CHECK(!egress_entry_valid(longname), "over-long entry is invalid");
    char label64[80];
    memset(label64, 'a', 64);
    strcpy(label64 + 64, ".com");
    CHECK(!egress_entry_valid(label64), "64-char label is invalid");
}

static void test_match(void) {
    char* l1[] = {"pypi.org", NULL};
    CHECK(m(l1, "pypi.org"), "exact");
    CHECK(m(l1, "PYPI.ORG"), "case-insensitive request");
    CHECK(m(l1, "pypi.org:443"), "explicit default port");
    CHECK(m(l1, "pypi.org:8443"), "unported entry allows any port");
    CHECK(!m(l1, "files.pypi.org"), "no implicit subdomains");
    CHECK(!m(l1, "evilpypi.org"), "no suffix confusion");
    CHECK(!m(l1, "pypi.org.evil.com"), "no prefix confusion");
    CHECK(!m(l1, "pypi.org@evil.com"), "userinfo trick is not a host");
    CHECK(!m(l1, ""), "empty host");
    CHECK(!m(l1, NULL), "null host");
    CHECK(!m(NULL, "pypi.org"), "null list denies");
    char* empty[] = {NULL};
    CHECK(!m(empty, "pypi.org"), "empty list denies");

    char* l2[] = {"*.pythonhosted.org", NULL};
    CHECK(m(l2, "files.pythonhosted.org"), "wildcard subdomain");
    CHECK(m(l2, "a.b.pythonhosted.org"), "wildcard deep subdomain");
    CHECK(!m(l2, "pythonhosted.org"), "wildcard excludes the apex");
    CHECK(!m(l2, "xpythonhosted.org"), "wildcard needs a label boundary");

    char* l3[] = {"registry.npmjs.org:443", NULL};
    CHECK(m(l3, "registry.npmjs.org"), "port entry matches default 443");
    CHECK(m(l3, "registry.npmjs.org:443"), "port entry matches explicit port");
    CHECK(!m(l3, "registry.npmjs.org:80"), "port entry rejects another port");
    char* l4[] = {"deb.debian.org:80", NULL};
    CHECK(m(l4, "deb.debian.org:80"), "non-default port entry");
    CHECK(!m(l4, "deb.debian.org"), "no port means 443, not 80");

    char* l5[] = {"*", NULL};
    CHECK(m(l5, "anything.example"), "star matches all");

    char* l6[] = {"a.example", "pypi.org", NULL};
    CHECK(m(l6, "pypi.org") && m(l6, "a.example"), "any entry may match");

    char* bad[] = {"not a host", "pypi.org", NULL};
    CHECK(m(bad, "pypi.org"), "a malformed entry is skipped, not fatal");
    CHECK(!m(bad, "not a host"), "a malformed entry allows nothing");

    bool named = true;
    CHECK(egress_match(l5, "x.example", &named) && !named, "star is not 'named'");
    CHECK(egress_match(l1, "pypi.org", &named) && named, "an exact entry is 'named'");
    CHECK(egress_match(l2, "f.pythonhosted.org", &named) && named, "wildcard is 'named'");
    char* l7[] = {"*", "pypi.org", NULL};
    CHECK(egress_match(l7, "pypi.org", &named) && named, "named wins over star");
    CHECK(egress_match(l7, "other.org", &named) && !named, "star alone is not named");
    CHECK(!egress_match(l1, "x.org", &named) && !named, "no match clears named");
}

static void test_covered(void) {
    CHECK(egress_entry_covered("*", "pypi.org"), "star covers a host");
    CHECK(egress_entry_covered("*", "*.x.org"), "star covers a suffix");
    CHECK(egress_entry_covered("*", "*"), "star covers star");
    CHECK(!egress_entry_covered("pypi.org", "*"), "host does not cover star");
    CHECK(egress_entry_covered("pypi.org", "pypi.org"), "same host");
    CHECK(egress_entry_covered("pypi.org", "PYPI.org:443"), "narrower port is covered");
    CHECK(!egress_entry_covered("pypi.org:443", "pypi.org"), "any-port is wider than 443");
    CHECK(!egress_entry_covered("pypi.org:443", "pypi.org:80"), "different port");
    CHECK(egress_entry_covered("pypi.org:443", "pypi.org:443"), "same port");
    CHECK(!egress_entry_covered("pypi.org", "files.pypi.org"), "host does not cover subdomain");
    CHECK(egress_entry_covered("*.x.org", "a.x.org"), "suffix covers host below");
    CHECK(!egress_entry_covered("*.x.org", "x.org"), "suffix does not cover the apex");
    CHECK(egress_entry_covered("*.x.org", "*.x.org"), "suffix covers itself");
    CHECK(egress_entry_covered("*.x.org", "*.a.x.org"), "suffix covers a deeper suffix");
    CHECK(!egress_entry_covered("*.a.x.org", "*.x.org"), "deeper suffix does not cover wider");
    CHECK(!egress_entry_covered("*.x.org", "*.y.org"), "unrelated suffix");
    CHECK(!egress_entry_covered("*.x.org", "ax.org"), "label boundary");
    CHECK(!egress_entry_covered("*.x.org:443", "a.x.org"), "ported suffix, unported want");
    CHECK(egress_entry_covered("*.x.org", "a.x.org:8443"), "unported suffix covers a port");
    CHECK(!egress_entry_covered("bogus entry", "pypi.org"), "invalid ceiling covers nothing");
    CHECK(!egress_entry_covered("*", "bogus entry"), "invalid want is never covered");
}

static void test_resolve(void) {
    char* ceil[] = {"api.example.com", "*.internal", NULL};
    char** out = NULL;
    int n = -1;

    // No request: the daemon's policy, unchanged.
    CHECK(egress_resolve(ceil, NULL, 0, false, &out, &n) == 0 && n == 2 && out &&
              strcmp(out[0], "api.example.com") == 0 && strcmp(out[1], "*.internal") == 0 &&
              out[2] == NULL,
          "empty request inherits the ceiling");
    egress_free(out);

    // deny_all: empty list, and it is a real (empty) list.
    CHECK(egress_resolve(ceil, NULL, 0, true, &out, &n) == 0 && n == 0 && out && !out[0],
          "deny_all gives an empty list");
    egress_free(out);
    const char* some[] = {"api.example.com"};
    CHECK(egress_resolve(ceil, some, 1, true, &out, &n) != 0 && !out,
          "deny_all with entries is a contradiction");

    // Narrowing within the ceiling.
    const char* narrow[] = {"api.example.com"};
    CHECK(egress_resolve(ceil, narrow, 1, false, &out, &n) == 0 && n == 1 &&
              strcmp(out[0], "api.example.com") == 0 && !out[1],
          "narrow to one allowed host");
    egress_free(out);
    const char* sub[] = {"db.internal:5432", "x.y.internal"};
    CHECK(egress_resolve(ceil, sub, 2, false, &out, &n) == 0 && n == 2 &&
              strcmp(out[0], "db.internal:5432") == 0,
          "hosts under a ceiling suffix");
    egress_free(out);

    // Anything wider, unknown or malformed is refused outright, not trimmed.
    const char* evil[] = {"evil.com"};
    CHECK(egress_resolve(ceil, evil, 1, false, &out, &n) != 0 && !out, "outside the ceiling");
    const char* mixed[] = {"api.example.com", "evil.com"};
    CHECK(egress_resolve(ceil, mixed, 2, false, &out, &n) != 0 && !out,
          "one bad entry rejects the whole policy");
    const char* star[] = {"*"};
    CHECK(egress_resolve(ceil, star, 1, false, &out, &n) != 0, "cannot ask for star");
    const char* apex[] = {"internal"};
    CHECK(egress_resolve(ceil, apex, 1, false, &out, &n) != 0, "suffix apex not covered");
    const char* junk[] = {"not a host"};
    CHECK(egress_resolve(ceil, junk, 1, false, &out, &n) != 0, "malformed entry");
    const char* nul[] = {NULL};
    CHECK(egress_resolve(ceil, nul, 1, false, &out, &n) != 0, "null entry");

    // A star ceiling lets a session name anything valid.
    char* open[] = {"*", NULL};
    const char* any[] = {"pypi.org", "*.pythonhosted.org"};
    CHECK(egress_resolve(open, any, 2, false, &out, &n) == 0 && n == 2, "star ceiling");
    egress_free(out);

    // An empty ceiling allows nothing to be requested, and inherits to nothing.
    char* none[] = {NULL};
    CHECK(egress_resolve(none, narrow, 1, false, &out, &n) != 0, "empty ceiling refuses asks");
    CHECK(egress_resolve(none, NULL, 0, false, &out, &n) == 0 && n == 0 && !out[0],
          "empty ceiling inherits empty");
    egress_free(out);
    CHECK(egress_resolve(NULL, NULL, 0, false, &out, &n) == 0 && n == 0 && out && !out[0],
          "null ceiling inherits empty");
    egress_free(out);

    // Bounds.
    const char* many[EGRESS_MAX_ENTRIES + 1];
    for (int i = 0; i <= EGRESS_MAX_ENTRIES; i++) many[i] = "pypi.org";
    CHECK(egress_resolve(open, many, EGRESS_MAX_ENTRIES + 1, false, &out, &n) != 0,
          "too many entries");
    CHECK(egress_resolve(open, many, EGRESS_MAX_ENTRIES, false, &out, &n) == 0 &&
              n == EGRESS_MAX_ENTRIES,
          "exactly the maximum is fine");
    egress_free(out);
    CHECK(egress_resolve(open, NULL, 0, false, NULL, &n) != 0, "null out");
}

int main(void) {
    test_grammar();
    test_match();
    test_covered();
    test_resolve();
    printf("%s\n", g_fail ? "[test] egress: FAIL" : "[test] egress: ALL PASS");
    return g_fail ? 1 : 0;
}
