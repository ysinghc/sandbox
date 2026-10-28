// SPDX-License-Identifier: GPL-2.0-only
// #25: the content-addressed template store. Needs no root and no KVM: the
// templates here are tiny fabricated ones with a valid manifest.

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sha256.h"
#include "snapshot_manager.h"
#include "template_store.h"

static int g_fail;
#define CHECK(c, m)                                         \
    do {                                                    \
        if (c) printf("[test] %-62s PASS\n", m);            \
        else { printf("[test] %-62s FAIL\n", m); g_fail++; } \
    } while (0)

static char g_root[512];

static void put(const char* dir, const char* file, const char* content, size_t reps) {
    char p[2048];
    snprintf(p, sizeof(p), "%s/%s", dir, file);
    FILE* f = fopen(p, "w");
    for (size_t i = 0; i < reps; i++) fputs(content, f);
    fclose(f);
}

// A template whose contents depend only on `seed`.
static void make_template(const char* ref, const char* seed) {
    char dir[1024], p[2048], buf[128];
    snprintf(dir, sizeof(dir), "%s/%s", g_root, ref);
    mkdir(dir, 0755);
    snprintf(buf, sizeof(buf), "memory-%s-", seed);
    put(dir, "memory.snap", buf, 4096 * 4 / strlen(buf) + 1);
    snprintf(buf, sizeof(buf), "vmstate-%s", seed);
    put(dir, "vmstate", buf, 1);
    snprintf(buf, sizeof(buf), "rootfs-%s-", seed);
    put(dir, "rootfs.ext4", buf, 100);

    put(dir, "vmlinux", "kernel-A", 1);
    snprintf(p, sizeof(p), "%s/memory.snap", dir);
    snap_manifest_t* m = build_manifest(p);
    snprintf(p, sizeof(p), "%s/vmstate", dir);
    sha256_file(p, m->vmstate_sha256);
    snprintf(p, sizeof(p), "%s/rootfs.ext4", dir);
    sha256_file(p, m->rootfs_sha256);
    struct stat st;
    stat(p, &st);
    m->rootfs_size = (uint64_t)st.st_size;
    m->version = 1;
    snprintf(p, sizeof(p), "%s/manifest.bin", dir);
    write_manifest(p, m);
    free(m);
}

static const char* g_root_build_kern(void) {
    static char p[1100];
    snprintf(p, sizeof(p), "%s/.build-kern", g_root);
    return p;
}

static int exists(const char* rel) {
    char p[1024];
    struct stat st;
    snprintf(p, sizeof(p), "%s/%s", g_root, rel);
    return lstat(p, &st) == 0;
}

static unsigned store_count(void) {
    char cmd[1400];
    snprintf(cmd, sizeof(cmd), "ls %s/.store | grep -cE '^[0-9a-f]{64}$' > %s/.n", g_root, g_root);
    (void)!system(cmd);
    char p[1100];
    snprintf(p, sizeof(p), "%s/.n", g_root);
    FILE* f = fopen(p, "r");
    unsigned n = 0;
    if (f) { (void)!fscanf(f, "%u", &n); fclose(f); }
    return n;
}

static volatile int g_stop, g_bad;
static void* reader(void* a) {
    (void)a;
    char p[1100], tgt[300];
    snprintf(p, sizeof(p), "%s/flip", g_root);
    while (!g_stop)
        if (readlink(p, tgt, sizeof(tgt)) < 0) g_bad++;
    return NULL;
}

int main(void) {
    char tmpl[] = "/tmp/test_tstore_XXXXXX";
    if (!mkdtemp(tmpl)) return 1;
    snprintf(g_root, sizeof(g_root), "%s", tmpl);
    setenv("SANDBOX_SNAPSHOT_ROOT", g_root, 1);
    char a[65], b[65], c[65], got[65];

    CHECK(tstore_name_valid("python-agent_1.2") && !tstore_name_valid("") &&
              !tstore_name_valid(".store") && !tstore_name_valid("../x") &&
              !tstore_name_valid("a/b"),
          "names: plain names ok, dot/slash/empty refused");
    CHECK(tstore_digest_valid("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") &&
              !tstore_digest_valid("0123") && !tstore_digest_valid("history"),
          "digests: 64 lowercase hex only");

    // ---- publish ----
    make_template(".build-py", "one");
    CHECK(tstore_publish("py", ".build-py", NULL, a) == 0, "publish a staged template");
    char want[1100];
    snprintf(want, sizeof(want), ".store/%s", a);
    CHECK(exists(want) && !exists(".build-py"), "it moved into the store under its digest");
    CHECK(tstore_resolve("py", got) == 0 && strcmp(got, a) == 0, "the name points at that digest");
    CHECK(snapshot_verify("py") == 0, "the daemon's path (via the name) still verifies");
    char p[2048];
    snprintf(p, sizeof(p), "%s/.store/%s", g_root, a);
    struct stat st;
    CHECK(stat(p, &st) == 0 && (st.st_mode & 0222) == 0, "the stored directory is read-only");
    snprintf(want, sizeof(want), ".store/%s/template.json", a);
    CHECK(exists(want), "template.json records the build");
    CHECK(tstore_verify("py") == 0 && tstore_verify(a) == 0, "verify by name and by digest");

    // ---- content addressing ----
    make_template(".build-py", "one");
    char a2[65];
    CHECK(tstore_publish("py", ".build-py", NULL, a2) == 0 && strcmp(a, a2) == 0 &&
              store_count() == 1 && !exists(".build-py"),
          "identical content is the same digest, stored once");
    make_template(".build-other", "one");
    CHECK(tstore_publish("other", ".build-other", NULL, a2) == 0 && strcmp(a, a2) == 0 &&
              store_count() == 1,
          "another name for the same content shares the entry");
    make_template(".build-py", "two");
    CHECK(tstore_publish("py", ".build-py", NULL, b) == 0 && strcmp(a, b) != 0 &&
              store_count() == 2,
          "different content is a different digest");
    CHECK(tstore_resolve("py", got) == 0 && strcmp(got, b) == 0, "the name moved to the new one");

    // ---- the manifest version tracks the content ----
    CHECK(read_manifest_version("py") != 0 && read_manifest_version("py") != 1,
          "the version is derived from the digest, not a build counter");
    CHECK(read_manifest_version("other") != read_manifest_version("py"),
          "different content has a different version");

    // ---- the kernel is part of the identity ----
    make_template(".build-kern", "one");  // identical, then swap only the kernel
    put(g_root_build_kern(), "vmlinux", "kernel-B", 1);
    char kd[65];
    CHECK(tstore_publish("kern", ".build-kern", NULL, kd) == 0 && strcmp(kd, a) != 0,
          "a different kernel is a different template");
    tstore_unpublish("kern");
    {
        tstore_gc_result_t kr;
        CHECK(tstore_gc(2, 0, 0, NULL, &kr) == 0 && kr.removed == 1,
              "...and unpublishing it makes exactly its entry collectable");
    }

    // ---- rollback ----
    CHECK(tstore_rollback("py", got) == 0 && strcmp(got, a) == 0, "rollback returns to the previous");
    CHECK(tstore_resolve("py", got) == 0 && strcmp(got, a) == 0, "...and the name follows");
    CHECK(tstore_rollback("py", got) == 0 && strcmp(got, b) == 0, "rollback again returns to the newer");
    CHECK(tstore_rollback("other", got) < 0 && errno == ENOENT, "nothing earlier to roll back to");

    // ---- refusals ----
    make_template(".build-bad", "bad");
    snprintf(p, sizeof(p), "%s/.build-bad/rootfs.ext4", g_root);
    FILE* f = fopen(p, "a");
    fputs("tamper", f);
    fclose(f);
    char before[65];
    tstore_resolve("py", before);
    CHECK(tstore_publish("py", ".build-bad", NULL, got) < 0 && tstore_resolve("py", got) == 0 &&
              strcmp(got, before) == 0,
          "a staged template that fails its hashes is refused, name unchanged");
    CHECK(tstore_publish("../evil", ".build-bad", NULL, got) < 0 &&
              tstore_publish("py", "a/b", NULL, got) < 0 &&
              tstore_publish(".store", ".build-bad", NULL, got) < 0,
          "bad names and staging paths are refused");
    CHECK(tstore_publish("py", ".build-missing", NULL, got) < 0, "a missing staged template is refused");

    // ---- adopting a pre-store template ----
    make_template("legacy", "old");
    make_template(".build-legacy", "new");
    char la[65], lb[65];
    tstore_digest("legacy", la);
    CHECK(tstore_publish("legacy", ".build-legacy", NULL, lb) == 0 && strcmp(la, lb) != 0,
          "publishing over a legacy directory");
    CHECK(tstore_resolve("legacy", got) == 0 && strcmp(got, lb) == 0, "the name is now a store link");
    CHECK(tstore_rollback("legacy", got) == 0 && strcmp(got, la) == 0,
          "the legacy template was adopted and can be rolled back to");

    // ---- tamper detection ----
    snprintf(p, sizeof(p), "%s/.store/%s", g_root, b);
    chmod(p, 0755);
    snprintf(p, sizeof(p), "%s/.store/%s/vmstate", g_root, b);
    chmod(p, 0644);
    f = fopen(p, "a");
    fputs("x", f);
    fclose(f);
    CHECK(tstore_verify(b) < 0, "a modified stored template fails verify");
    snprintf(p, sizeof(p), "%s/.store/%s/vmstate", g_root, b);
    f = fopen(p, "w");
    fputs("vmstate-two", f);
    fclose(f);
    CHECK(tstore_verify(b) == 0, "...and passes again once restored");

    // ---- list ----
    char lpath[1100];
    snprintf(lpath, sizeof(lpath), "%s/.list", g_root);
    f = fopen(lpath, "w");
    tstore_list(f);
    fclose(f);
    f = fopen(lpath, "r");
    char buf[8192] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = 0;
    fclose(f);
    char needle[200];
    snprintf(needle, sizeof(needle), "{\"name\":\"py\",\"digest\":\"%s\",\"legacy\":false}", b);
    CHECK(strstr(buf, needle) != NULL, "list shows each name with its digest");

    // ---- garbage collection ----
    make_template(".build-py", "three");
    CHECK(tstore_publish("py", ".build-py", NULL, c) == 0, "publish a third version");
    // py history: a, b, b(rollback->a?) ... newest distinct two are c and b.
    tstore_gc_result_t r;
    snprintf(want, sizeof(want), ".store/%s", a);
    CHECK(tstore_gc(2, 3600, 0, NULL, &r) == 0 && exists(want),
          "a young unreferenced entry is kept inside its grace period");
    CHECK(tstore_gc(2, 0, 1, NULL, &r) == 0 && exists(want),
          "a dry run deletes nothing");
    // `other` still points at a, so a is referenced: not collectable yet.
    CHECK(r.removed == 0, "an entry another name points at is not collectable");
    CHECK(tstore_unpublish("other") == 0 && !exists("other"), "unpublish withdraws a name");
    CHECK(tstore_gc(2, 0, 1, stdout, &r) == 0 && r.removed >= 1 && exists(want),
          "the dry run now reports the unreferenced entry");
    CHECK(tstore_gc(2, 0, 0, NULL, &r) == 0 && !exists(want) && r.bytes_reclaimed > 0,
          "gc removes it and reports the bytes");
    snprintf(want, sizeof(want), ".store/%s", b);
    CHECK(exists(want), "the previous version stays for rollback (keep=2)");
    tstore_gc(1, 0, 0, NULL, &r);
    CHECK(!exists(want) && tstore_resolve("py", got) == 0 && strcmp(got, c) == 0 &&
              snapshot_verify("py") == 0,
          "keep=1 drops it, and the current template is untouched");
    CHECK(tstore_unpublish("legacy") == 0 && tstore_unpublish("py") == 0, "unpublish the rest");
    tstore_gc(2, 0, 0, NULL, &r);
    CHECK(store_count() == 0, "nothing referenced, nothing left");

    // ---- the name never goes missing while it is repointed ----
    make_template(".build-flip", "f0");
    tstore_publish("flip", ".build-flip", NULL, got);
    pthread_t t;
    pthread_create(&t, NULL, reader, NULL);
    for (int i = 1; i <= 60; i++) {
        char seed[16];
        snprintf(seed, sizeof(seed), "f%d", i);
        make_template(".build-flip", seed);
        if (tstore_publish("flip", ".build-flip", NULL, got) < 0) g_fail++;
    }
    g_stop = 1;
    pthread_join(t, NULL);
    CHECK(g_bad == 0, "a concurrent reader never finds the name missing");

    char cmd[1100];
    snprintf(cmd, sizeof(cmd), "chmod -R u+w %s; rm -rf %s", g_root, g_root);
    (void)!system(cmd);
    printf("%s\n", g_fail ? "FAILED" : "ALL PASSED");
    return g_fail ? 1 : 0;
}
