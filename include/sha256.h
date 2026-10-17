#ifndef SHA256_H
#define SHA256_H

// Minimal self-contained SHA-256 (FIPS 180-4). Used for snapshot integrity
// (§10.10) — manifest stores the hash of memory.snap and vmstate so a corrupt
// or truncated snapshot is refused before it reaches the UFFD handler.

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;   // total message length in bits
    uint8_t data[64];
    uint32_t datalen;  // bytes currently buffered in data[]
} sha256_ctx;

void sha256_init(sha256_ctx* ctx);
void sha256_update(sha256_ctx* ctx, const void* data, size_t len);
void sha256_final(sha256_ctx* ctx, uint8_t out[32]);

// One-shot: hash a buffer.
void sha256(const void* data, size_t len, uint8_t out[32]);

// Hash a whole file (streaming). Returns 0 on success, -1 on I/O error.
int sha256_file(const char* path, uint8_t out[32]);

// Lowercase hex of a 32-byte digest (out must be >= 65 bytes).
void sha256_hex(const uint8_t digest[32], char out[65]);

#endif // SHA256_H
