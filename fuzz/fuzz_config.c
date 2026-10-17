// §10.14 fuzz target: engine config parser (src/daemon/config.c).
// config_parse_buffer() consumes an in-memory body, so no temp files needed.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "engine_config.h"

#define MAX_INPUT (64 * 1024)

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0 || size > MAX_INPUT) return 0;
    char* text = malloc(size + 1);
    if (!text) return 0;
    memcpy(text, data, size);
    text[size] = '\0';

    engine_config_t c;
    config_defaults(&c);
    config_parse_buffer(&c, text);

    free(text);
    return 0;
}
