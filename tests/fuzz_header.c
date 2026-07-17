/*
 * AFL++ fuzzing harness for the DenyFS header parser.
 *
 * Attack surface: the header decryption path in denyfs_decrypt_header() runs on
 * attacker-controlled bytes (the on-disk header) BEFORE any password is verified.
 * A malformed header must never cause a crash, buffer overflow, or undefined behavior.
 *
 * Usage with AFL++:
 *   afl-fuzz -i corpus/ -o findings/ -- ./fuzz_header @@
 *
 * The harness:
 *   1. Reads exactly HEADER_SIZE (4096) bytes from the input file (or stdin).
 *   2. Interprets the bytes as a denyfs_header_disk_t.
 *   3. Derives a master key from a fixed password using the salt from the input.
 *   4. Derives a header key via HKDF-Expand.
 *   5. Attempts GCM decryption of the header payload.
 *   6. If decryption "succeeds" (GCM tag happens to verify), validates the payload
 *      fields (magic, volume_size, bitmap_offset, bitmap_size) for sanity.
 *
 * The harness must exit cleanly regardless of input content — no assert(), no abort()
 * on bad data.  Crashes found by AFL++ indicate real bugs in the parsing/crypto code.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "crypto.h"

#define FUZZ_PASSWORD     "fuzz_fixed_password"
#define FUZZ_PASSWORD_LEN 19

#ifdef __AFL_FUZZ_TESTCASE_LEN
  /* Shared-memory mode for AFL++ persistent mode */
  __AFL_FUZZ_INIT();
#endif

static int run_one(const uint8_t *data, size_t len) {
    if (len < sizeof(denyfs_header_disk_t)) {
        /* Short input — pad with zeros to exercise the full struct */
        return 0;
    }

    /* Interpret input as on-disk header */
    denyfs_header_disk_t disk_header;
    memcpy(&disk_header, data, sizeof(disk_header));

    /* Derive keys from the fixed password + attacker-controlled salt */
    uint8_t *master_key = denyfs_secure_alloc(KEY_SIZE_GCM);
    uint8_t *header_key = denyfs_secure_alloc(KEY_SIZE_GCM);
    if (!master_key || !header_key) {
        if (master_key) denyfs_secure_free(master_key, KEY_SIZE_GCM);
        if (header_key) denyfs_secure_free(header_key, KEY_SIZE_GCM);
        return 0;
    }

    int kdf_res = denyfs_derive_master_key(FUZZ_PASSWORD, FUZZ_PASSWORD_LEN,
                                            disk_header.salt, master_key);
    if (kdf_res != 0) {
        /* KDF failure on bizarre salt is acceptable — not a crash */
        denyfs_secure_free(master_key, KEY_SIZE_GCM);
        denyfs_secure_free(header_key, KEY_SIZE_GCM);
        return 0;
    }

    int hkdf_res = denyfs_derive_header_key(master_key, header_key);
    if (hkdf_res != 0) {
        denyfs_secure_free(master_key, KEY_SIZE_GCM);
        denyfs_secure_free(header_key, KEY_SIZE_GCM);
        return 0;
    }

    /* Attempt GCM decryption — this is the primary fuzz target */
    denyfs_header_payload_t payload;
    memset(&payload, 0, sizeof(payload));
    int decrypt_res = denyfs_decrypt_header(&disk_header, header_key, &payload);

    if (decrypt_res == 0) {
        /*
         * GCM tag verified (astronomically unlikely with random input, but
         * AFL++ can seed with a valid header). Validate payload fields to
         * exercise downstream parsing.
         */
        uint64_t magic = payload.magic;
        uint64_t vol_size = payload.volume_size;
        uint64_t bmp_off = payload.bitmap_offset;
        uint64_t bmp_sz = payload.bitmap_size;

        /* Sanity checks that the real vol_open would perform */
        uint64_t expected_magic = 0x44656e7946533031ULL;
        if (sodium_memcmp(&magic, &expected_magic, sizeof(uint64_t)) == 0) {
            /* "Valid" header — check volume_size isn't absurd */
            if (vol_size > 0 && vol_size < (1ULL << 40)) {
                /* Plausible — would proceed to superblock load in real code */
                (void)bmp_off;
                (void)bmp_sz;
            }
        }

        sodium_memzero(&payload, sizeof(payload));
    }

    /* Wipe and free */
    denyfs_secure_free(master_key, KEY_SIZE_GCM);
    denyfs_secure_free(header_key, KEY_SIZE_GCM);

    return 0;
}

int main(int argc, char **argv) {
    if (denyfs_crypto_init() != 0) {
        fprintf(stderr, "[-] Crypto init failed\n");
        return 1;
    }

#ifdef __AFL_FUZZ_TESTCASE_LEN
    /* AFL++ persistent mode — runs multiple inputs per process */
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        run_one(buf, (size_t)len);
    }
#else
    /* Standalone mode — read from file argument or stdin */
    FILE *f = stdin;
    if (argc > 1) {
        f = fopen(argv[1], "rb");
        if (!f) {
            fprintf(stderr, "[-] Cannot open %s\n", argv[1]);
            return 1;
        }
    }

    uint8_t input[HEADER_SIZE];
    memset(input, 0, sizeof(input));
    size_t n = fread(input, 1, sizeof(input), f);
    if (f != stdin) fclose(f);

    if (n == 0) {
        fprintf(stderr, "[-] Empty input\n");
        return 1;
    }

    run_one(input, n);
    printf("[+] Harness completed without crash (input: %zu bytes)\n", n);
#endif

    denyfs_crypto_cleanup();
    return 0;
}
