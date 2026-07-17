/*
 * AFL++ fuzzing harness for the DenyFS XTS sector encryption/decryption.
 *
 * Attack surface: sector crypt operates on attacker-controlled ciphertext blocks
 * read from the container. A malformed sector must never cause a crash.
 *
 * The harness:
 *   1. Reads up to SECTOR_SIZE (4096) bytes from input.
 *   2. Uses a fixed XTS key and variable LBA (derived from trailing input bytes).
 *   3. Runs decrypt, then re-encrypts and verifies roundtrip (if decrypt succeeded).
 *
 * Usage with AFL++:
 *   afl-fuzz -i corpus/ -o findings/ -- ./fuzz_sector @@
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "crypto.h"

/* Fixed XTS key for deterministic fuzzing */
static const uint8_t FUZZ_XTS_KEY[KEY_SIZE_XTS] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40
};

#ifdef __AFL_FUZZ_TESTCASE_LEN
  __AFL_FUZZ_INIT();
#endif

static int run_one(const uint8_t *data, size_t len) {
    if (len < SECTOR_SIZE) return 0;

    /* Extract LBA from extra bytes if available, else use 0 */
    uint64_t lba = 0;
    if (len > SECTOR_SIZE) {
        memcpy(&lba, data + SECTOR_SIZE, (len - SECTOR_SIZE) < 8 ? (len - SECTOR_SIZE) : 8);
    }

    uint8_t decrypted[SECTOR_SIZE];
    uint8_t re_encrypted[SECTOR_SIZE];

    /* Decrypt the fuzzed sector */
    int dec_res = denyfs_crypt_sector(data, decrypted, lba, FUZZ_XTS_KEY, 0);
    if (dec_res != 0) return 0; /* XTS failure is not a crash */

    /* Re-encrypt for roundtrip verification */
    int enc_res = denyfs_crypt_sector(decrypted, re_encrypted, lba, FUZZ_XTS_KEY, 1);
    if (enc_res != 0) return 0;

    /* Roundtrip check — re-encrypted must match original input */
    if (memcmp(data, re_encrypted, SECTOR_SIZE) != 0) {
        /* Roundtrip failure is a real bug */
        fprintf(stderr, "[-] XTS roundtrip mismatch at LBA %lu\n", (unsigned long)lba);
        abort();
    }

    return 0;
}

int main(int argc, char **argv) {
    if (denyfs_crypto_init() != 0) {
        fprintf(stderr, "[-] Crypto init failed\n");
        return 1;
    }

#ifdef __AFL_FUZZ_TESTCASE_LEN
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        run_one(buf, (size_t)len);
    }
#else
    FILE *f = stdin;
    if (argc > 1) {
        f = fopen(argv[1], "rb");
        if (!f) {
            fprintf(stderr, "[-] Cannot open %s\n", argv[1]);
            return 1;
        }
    }

    uint8_t input[SECTOR_SIZE + 8];
    memset(input, 0, sizeof(input));
    size_t n = fread(input, 1, sizeof(input), f);
    if (f != stdin) fclose(f);

    if (n < SECTOR_SIZE) {
        fprintf(stderr, "[-] Input too short (need >= %d bytes)\n", SECTOR_SIZE);
        return 1;
    }

    run_one(input, n);
    printf("[+] Sector fuzz harness completed without crash (input: %zu bytes)\n", n);
#endif

    denyfs_crypto_cleanup();
    return 0;
}
