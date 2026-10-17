// Standalone driver so the fuzz targets also build/run without libFuzzer
// (e.g. gcc + ASan): each argv file is fed once to LLVMFuzzerTestOneInput.
// Reads stdin when no files are given.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

static void run_one(FILE* f) {
    size_t cap = 1 << 16, len = 0;
    uint8_t* buf = malloc(cap);
    if (!buf) return;
    for (;;) {
        if (len == cap) {
            cap *= 2;
            uint8_t* nb = realloc(buf, cap);
            if (!nb) break;
            buf = nb;
        }
        size_t r = fread(buf + len, 1, cap - len, f);
        len += r;
        if (r == 0) break;
    }
    LLVMFuzzerTestOneInput(buf, len);
    free(buf);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        run_one(stdin);
        return 0;
    }
    for (int i = 1; i < argc; i++) {
        FILE* f = fopen(argv[i], "rb");
        if (!f) continue;
        run_one(f);
        fclose(f);
    }
    return 0;
}
