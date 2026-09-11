#include "snapshot_manager.h"
#include <stddef.h>
#include <stdbool.h>

int create_snapshot_template(const char* template_name, const template_config_t* config) {
    (void)template_name; (void)config;
    return 0;
}

snap_manifest_t* build_manifest(const char* memory_path) {
    (void)memory_path;
    return NULL;
}

int write_manifest(const char* path, const snap_manifest_t* manifest) {
    (void)path; (void)manifest;
    return 0;
}

uint32_t read_manifest_version(const char* template_name) {
    (void)template_name;
    return 0;
}

bool snapshot_page_present(const snap_manifest_t* manifest, uint64_t offset) {
    (void)manifest; (void)offset;
    return false;
}
