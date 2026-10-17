// bench_client — Sandbox Engine benchmark client.
//
// Drives the public C API (libsandbox) to measure real sandbox lifecycle
// latency against a running daemon. The C API holds one session per process,
// so concurrency is expressed by forking worker *processes* (each with its own
// session), which is also how real clients behave.
//
// Modes:
//   --concurrency 1   (default) sequential create/destroy in this process
//   --concurrency C   fork C workers, each doing its own create/destroy loop
//
// It reports create/destroy (and optionally pause/resume) latency percentiles
// and aggregate throughput, as human text and/or JSON.
//
// Exit codes: 0 ok, 2 usage error, 3 no sandboxes could be created.

#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "libsandbox.h"

#define BENCH_VERSION "1.0"

typedef struct {
    const char* socket;
    const char* template_name;
    int iterations;
    int warmup;
    int concurrency;
    int pause_cycles;
    uint64_t memory_mib;
    uint32_t vcpus;
    uint32_t wait_ms;
    const char* json_path;
    const char* label;
    int quiet;
} params_t;

// ---- small dynamic vector of samples (nanoseconds) --------------------------

typedef struct {
    uint64_t* v;
    size_t n, cap;
} vec_t;

static void vec_push(vec_t* a, uint64_t x) {
    if (a->n == a->cap) {
        a->cap = a->cap ? a->cap * 2 : 256;
        a->v = realloc(a->v, a->cap * sizeof(uint64_t));
        if (!a->v) { perror("realloc"); exit(1); }
    }
    a->v[a->n++] = x;
}

static int cmp_u64(const void* a, const void* b) {
    uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
    return (x > y) - (x < y);
}

typedef struct {
    size_t n;
    uint64_t min_ns, max_ns;
    double avg_ms, p50_ms, p90_ms, p99_ms;
} stats_t;

static stats_t stats_of(vec_t a) {
    stats_t s;
    memset(&s, 0, sizeof(s));
    s.n = a.n;
    if (a.n == 0) return s;
    qsort(a.v, a.n, sizeof(uint64_t), cmp_u64);
    long double sum = 0;
    for (size_t i = 0; i < a.n; i++) sum += a.v[i];
    s.min_ns = a.v[0];
    s.max_ns = a.v[a.n - 1];
    s.avg_ms = (double)(sum / (long double)a.n) / 1e6;
    size_t i50 = a.n * 50 / 100; if (i50 >= a.n) i50 = a.n - 1;
    size_t i90 = a.n * 90 / 100; if (i90 >= a.n) i90 = a.n - 1;
    size_t i99 = a.n * 99 / 100; if (i99 >= a.n) i99 = a.n - 1;
    s.p50_ms = a.v[i50] / 1e6;
    s.p90_ms = a.v[i90] / 1e6;
    s.p99_ms = a.v[i99] / 1e6;
    return s;
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

// ---- worker -----------------------------------------------------------------

// Results for one process's run.
typedef struct {
    vec_t create, destroy, pause, resume, inspect;
    int failures;      // create() calls that returned non-OK
    int created;       // create() calls that succeeded
    int init_failed;   // session could not be established
} result_t;

static void result_free(result_t* r) {
    free(r->create.v); free(r->destroy.v); free(r->pause.v);
    free(r->resume.v); free(r->inspect.v);
    memset(r, 0, sizeof(*r));
}

static void one_create_destroy(const params_t* p, result_t* r, int do_pause) {
    sandbox_spec_t spec;
    memset(&spec, 0, sizeof(spec));
    spec.memory_mib = p->memory_mib;
    spec.vcpu_count = p->vcpus;
    spec.template_name = p->template_name;
    spec.env_vars = NULL;
    spec.pool_wait_ms = p->wait_ms;

    sandbox_handle_t* h = NULL;
    uint64_t t0 = now_ns();
    sandbox_error_t rc = sandbox_create(&spec, &h);
    uint64_t t1 = now_ns();
    if (rc != SANDBOX_OK) { r->failures++; return; }
    r->created++;
    vec_push(&r->create, t1 - t0);

    if (do_pause && p->pause_cycles > 0) {
        for (int k = 0; k < p->pause_cycles; k++) {
            uint64_t a = now_ns();
            if (sandbox_pause(h) == SANDBOX_OK) vec_push(&r->pause, now_ns() - a);
            uint64_t b = now_ns();
            if (sandbox_resume(h) == SANDBOX_OK) vec_push(&r->resume, now_ns() - b);
        }
    }

    sandbox_status_t st;
    uint64_t t2 = now_ns();
    (void)sandbox_inspect(h, &st);
    vec_push(&r->inspect, now_ns() - t2);

    uint64_t t3 = now_ns();
    sandbox_destroy(h);
    vec_push(&r->destroy, now_ns() - t3);
}

static int run_worker(const params_t* p, result_t* r, int do_pause) {
    if (sandbox_init(p->socket) != SANDBOX_OK) { r->init_failed = 1; return -1; }
    for (int i = 0; i < p->warmup; i++) {
        result_t tmp; memset(&tmp, 0, sizeof(tmp));
        one_create_destroy(p, &tmp, 0);
        result_free(&tmp);
    }
    for (int i = 0; i < p->iterations; i++) one_create_destroy(p, r, do_pause);
    sandbox_cleanup();
    return 0;
}

// ---- concurrency (fork) -----------------------------------------------------

static void write_samples(const char* path, const result_t* r) {
    FILE* f = fopen(path, "w");
    if (!f) { perror(path); return; }
    for (size_t i = 0; i < r->create.n; i++)  fprintf(f, "C %llu\n", (unsigned long long)r->create.v[i]);
    for (size_t i = 0; i < r->destroy.n; i++) fprintf(f, "D %llu\n", (unsigned long long)r->destroy.v[i]);
    for (size_t i = 0; i < r->inspect.n; i++) fprintf(f, "I %llu\n", (unsigned long long)r->inspect.v[i]);
    fprintf(f, "F %d\n", r->failures);
    fprintf(f, "N %d\n", r->init_failed);
    fclose(f);
}

static void read_samples(const char* path, result_t* agg) {
    FILE* f = fopen(path, "r");
    if (!f) return;
    char tag;
    unsigned long long val;
    while (fscanf(f, " %c %llu", &tag, &val) == 2) {
        switch (tag) {
            case 'C': vec_push(&agg->create, val); agg->created++; break;
            case 'D': vec_push(&agg->destroy, val); break;
            case 'I': vec_push(&agg->inspect, val); break;
            case 'F': agg->failures += (int)val; break;
            case 'N': agg->init_failed += (int)val; break;
            default: break;
        }
    }
    fclose(f);
}

// ---- reporting --------------------------------------------------------------

static void print_stats(const char* name, stats_t s) {
    if (s.n == 0) { printf("  %-8s (no samples)\n", name); return; }
    printf("  %-8s n=%-4zu  avg=%7.2fms  p50=%7.2fms  p90=%7.2fms  p99=%7.2fms  "
           "min=%7.2fms  max=%7.2fms\n",
           name, s.n, s.avg_ms, s.p50_ms, s.p90_ms, s.p99_ms,
           s.min_ns / 1e6, s.max_ns / 1e6);
}

static void json_stats(FILE* f, const char* name, stats_t s, int last) {
    fprintf(f,
            "    \"%s\": {\"samples\": %zu, \"avg_ms\": %.3f, \"p50_ms\": %.3f, "
            "\"p90_ms\": %.3f, \"p99_ms\": %.3f, \"min_ms\": %.3f, \"max_ms\": %.3f}%s\n",
            name, s.n, s.avg_ms, s.p50_ms, s.p90_ms, s.p99_ms,
            s.min_ns / 1e6, s.max_ns / 1e6, last ? "" : ",");
}

int main(int argc, char** argv) {
    params_t p;
    memset(&p, 0, sizeof(p));
    p.socket = "/var/run/sandbox-engine/engine.sock";
    p.template_name = "e2e";
    p.iterations = 20;
    p.warmup = 3;
    p.concurrency = 1;
    p.pause_cycles = 0;
    p.memory_mib = 256;
    p.vcpus = 1;
    p.wait_ms = 2000;
    p.label = "seq";

    static const struct option opts[] = {
        {"socket", required_argument, 0, 's'},
        {"template", required_argument, 0, 't'},
        {"iterations", required_argument, 0, 'n'},
        {"warmup", required_argument, 0, 'w'},
        {"concurrency", required_argument, 0, 'c'},
        {"pause-cycles", required_argument, 0, 'p'},
        {"memory", required_argument, 0, 'm'},
        {"vcpus", required_argument, 0, 'v'},
        {"wait", required_argument, 0, 'W'},
        {"json", required_argument, 0, 'j'},
        {"label", required_argument, 0, 'l'},
        {"quiet", no_argument, 0, 'q'},
        {"version", no_argument, 0, 'V'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0},
    };
    int c;
    while ((c = getopt_long(argc, argv, "s:t:n:w:c:p:m:v:W:j:l:qVh", opts, NULL)) != -1) {
        switch (c) {
            case 's': p.socket = optarg; break;
            case 't': p.template_name = optarg; break;
            case 'n': p.iterations = atoi(optarg); break;
            case 'w': p.warmup = atoi(optarg); break;
            case 'c': p.concurrency = atoi(optarg); break;
            case 'p': p.pause_cycles = atoi(optarg); break;
            case 'm': p.memory_mib = strtoull(optarg, NULL, 10); break;
            case 'v': p.vcpus = (uint32_t)strtoul(optarg, NULL, 10); break;
            case 'W': p.wait_ms = (uint32_t)strtoul(optarg, NULL, 10); break;
            case 'j': p.json_path = optarg; break;
            case 'l': p.label = optarg; break;
            case 'q': p.quiet = 1; break;
            case 'V': printf("bench_client %s\n", BENCH_VERSION); return 0;
            case 'h':
            default:
                printf("usage: bench_client [options]\n"
                       "  -s, --socket PATH      daemon socket (default /var/run/sandbox-engine/engine.sock)\n"
                       "  -t, --template NAME    snapshot template (default e2e)\n"
                       "  -n, --iterations N     measured create/destroy cycles per worker (default 20)\n"
                       "  -w, --warmup N         unmeasured warm-up cycles per worker (default 3)\n"
                       "  -c, --concurrency C    fork C worker processes, one session each (default 1)\n"
                       "  -p, --pause-cycles K   pause/resume the first sandbox K times to time it\n"
                       "  -m, --memory MiB       guest memory (default 256)\n"
                       "  -v, --vcpus N          guest vCPUs (default 1)\n"
                       "  -W, --wait MS          pool_wait_ms per create (default 2000)\n"
                       "  -j, --json FILE        write JSON results\n"
                       "  -l, --label STR        label for this run (default seq)\n"
                       "  -q, --quiet            suppress the human summary\n");
                return c == 'h' ? 0 : 2;
        }
    }
    if (p.iterations < 1) p.iterations = 1;
    if (p.concurrency < 1) p.concurrency = 1;
    if (p.warmup < 0) p.warmup = 0;

    result_t agg;
    memset(&agg, 0, sizeof(agg));

    uint64_t wall0 = now_ns();
    int do_pause = 1;  // only the first worker times pause/resume

    if (p.concurrency == 1) {
        run_worker(&p, &agg, do_pause);
    } else {
        char tmpdir[] = "/tmp/bench_client.XXXXXX";
        if (!mkdtemp(tmpdir)) { perror("mkdtemp"); return 1; }
        pid_t* kids = calloc((size_t)p.concurrency, sizeof(pid_t));
        for (int i = 0; i < p.concurrency; i++) {
            char path[512];
            snprintf(path, sizeof(path), "%s/w%d", tmpdir, i);
            pid_t pid = fork();
            if (pid == 0) {
                result_t r;
                memset(&r, 0, sizeof(r));
                run_worker(&p, &r, i == 0);
                write_samples(path, &r);
                _exit(r.init_failed ? 4 : 0);
            }
            kids[i] = pid;
        }
        int any_ok = 0;
        for (int i = 0; i < p.concurrency; i++) {
            int st = 0;
            waitpid(kids[i], &st, 0);
            if (WIFEXITED(st) && WEXITSTATUS(st) == 0) any_ok = 1;
        }
        for (int i = 0; i < p.concurrency; i++) {
            char path[512];
            snprintf(path, sizeof(path), "%s/w%d", tmpdir, i);
            read_samples(path, &agg);
            unlink(path);
        }
        rmdir(tmpdir);
        free(kids);
        (void)any_ok;
    }
    uint64_t wall1 = now_ns();
    double wall_s = (wall1 - wall0) / 1e9;

    stats_t cs = stats_of(agg.create);
    stats_t ds = stats_of(agg.destroy);
    stats_t ps = stats_of(agg.pause);
    stats_t rs = stats_of(agg.resume);
    stats_t is = stats_of(agg.inspect);
    double throughput = wall_s > 0 ? (double)agg.created / wall_s : 0.0;

    if (!p.quiet) {
        printf("\n--- bench_client (%s) ---\n", p.label);
        printf("  template=%s memory=%lluMiB vcpus=%u concurrency=%d iterations=%d warmup=%d wait=%ums\n",
               p.template_name, (unsigned long long)p.memory_mib, p.vcpus,
               p.concurrency, p.iterations, p.warmup, p.wait_ms);
        printf("  created=%d failed=%d init_failed=%d wall=%.2fs throughput=%.2f creates/s\n",
               agg.created, agg.failures, agg.init_failed, wall_s, throughput);
        print_stats("create", cs);
        print_stats("destroy", ds);
        print_stats("inspect", is);
        if (ps.n) print_stats("pause", ps);
        if (rs.n) print_stats("resume", rs);
    }

    if (p.json_path) {
        FILE* f = fopen(p.json_path, "w");
        if (!f) { perror(p.json_path); } else {
            fprintf(f, "{\n");
            fprintf(f, "  \"tool\": \"bench_client\", \"version\": \"%s\",\n", BENCH_VERSION);
            fprintf(f, "  \"label\": \"%s\", \"template\": \"%s\",\n", p.label, p.template_name);
            fprintf(f, "  \"config\": {\"memory_mib\": %llu, \"vcpus\": %u, \"concurrency\": %d, "
                       "\"iterations\": %d, \"warmup\": %d, \"pool_wait_ms\": %u},\n",
                    (unsigned long long)p.memory_mib, p.vcpus, p.concurrency,
                    p.iterations, p.warmup, p.wait_ms);
            fprintf(f, "  \"totals\": {\"created\": %d, \"failed\": %d, \"init_failed\": %d, "
                       "\"wall_s\": %.3f, \"throughput_creates_per_s\": %.3f},\n",
                    agg.created, agg.failures, agg.init_failed, wall_s, throughput);
            fprintf(f, "  \"latency\": {\n");
            json_stats(f, "create", cs, 0);
            json_stats(f, "destroy", ds, 0);
            json_stats(f, "inspect", is, 0);
            json_stats(f, "pause", ps, 0);
            json_stats(f, "resume", rs, 1);
            fprintf(f, "  }\n}\n");
            fclose(f);
        }
    }

    int created = agg.created, init_failed = agg.init_failed;
    result_free(&agg);
    if (created == 0) return 3;  // never useful if nothing was created
    if (init_failed) return 3;
    return 0;
}
