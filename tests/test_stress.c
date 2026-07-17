/*
 * Phase 6 (brain file Phase 7): Stress tests and seeded correctness cases.
 *
 * Covers:
 *   1. Corrupted outer header rejection (flip bytes in GCM ciphertext).
 *   2. Corrupted hidden header region rejection.
 *   3. Corrupted superblock rejection after successful auth.
 *   4. Filesystem stress: create all 63 files, fill to capacity, delete all.
 *   5. Filesystem stress: rapid create/delete cycles.
 *   6. Boundary write: max file size (96KB) write and read-back.
 *   7. Oversized write rejection (beyond 96KB limit).
 *   8. Name boundary: max-length filename (250 chars).
 *   9. Name boundary: empty and overlength filenames.
 *  10. Concurrent-style interleaved operations (create, write, read, delete loop).
 *
 * All tests run under ASan/UBSan. No test should crash, leak, or trigger UB.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sodium.h>
#include "crypto.h"
#include "fs.h"

#define STRESS_CONTAINER  "test_stress.img"
#define STRESS_PASSWORD   "stress_pass_42"
#define STRESS_HIDDEN_PW  "hidden_stress_99"
#define STRESS_SIZE_MB    10
#define HIDDEN_SIZE_MB    2

/* ======================================================================== */
/* Test 1: Corrupted outer header rejection                                 */
/* ======================================================================== */

void test_corrupted_outer_header(void) {
    printf("[*] Test 1: Corrupted outer header rejection...\n");

    int res = denyfs_container_create(STRESS_CONTAINER, STRESS_SIZE_MB,
                                      STRESS_PASSWORD, strlen(STRESS_PASSWORD));
    assert(res == 0);

    /* Flip bytes in the GCM ciphertext region of the outer header */
    FILE *f = fopen(STRESS_CONTAINER, "r+b");
    assert(f != NULL);

    /* Corrupt bytes at offset SALT_SIZE + IV_SIZE + TAG_SIZE + 10 (inside ciphertext) */
    long corrupt_offset = SALT_SIZE + IV_SIZE + TAG_SIZE + 10;
    fseek(f, corrupt_offset, SEEK_SET);
    uint8_t byte;
    fread(&byte, 1, 1, f);
    byte ^= 0xFF;
    fseek(f, corrupt_offset, SEEK_SET);
    fwrite(&byte, 1, 1, f);
    fclose(f);

    /* Open must fail — GCM authentication should reject */
    denyfs_volume_t *vol = denyfs_vol_open(STRESS_CONTAINER,
                                            STRESS_PASSWORD, strlen(STRESS_PASSWORD),
                                            NULL, 0, 0);
    assert(vol == NULL);

    remove(STRESS_CONTAINER);
    printf("[+] Corrupted outer header correctly rejected.\n");
}

/* ======================================================================== */
/* Test 2: Corrupted hidden header region rejection                         */
/* ======================================================================== */

void test_corrupted_hidden_header(void) {
    printf("[*] Test 2: Corrupted hidden header region rejection...\n");

    int res = denyfs_container_create(STRESS_CONTAINER, STRESS_SIZE_MB,
                                      STRESS_PASSWORD, strlen(STRESS_PASSWORD));
    assert(res == 0);

    res = denyfs_container_create_hidden(STRESS_CONTAINER,
                                          STRESS_PASSWORD, strlen(STRESS_PASSWORD),
                                          STRESS_HIDDEN_PW, strlen(STRESS_HIDDEN_PW),
                                          HIDDEN_SIZE_MB);
    assert(res == 0);

    /* Verify hidden volume opens before corruption */
    denyfs_volume_t *vol = denyfs_vol_open(STRESS_CONTAINER,
                                            STRESS_HIDDEN_PW, strlen(STRESS_HIDDEN_PW),
                                            NULL, 0, 0);
    assert(vol != NULL);
    assert(vol->is_hidden == 1);
    denyfs_vol_close(vol);

    /* Corrupt the hidden header (at EOF - 32KB + 20 bytes into ciphertext) */
    FILE *f = fopen(STRESS_CONTAINER, "r+b");
    assert(f != NULL);
    fseek(f, 0, SEEK_END);
    long container_size = ftell(f);
    long hidden_header_pos = container_size - DENYFS_HIDDEN_HEADER_OFFSET_FROM_EOF;
    long corrupt_pos = hidden_header_pos + SALT_SIZE + IV_SIZE + TAG_SIZE + 20;
    fseek(f, corrupt_pos, SEEK_SET);
    uint8_t byte;
    fread(&byte, 1, 1, f);
    byte ^= 0xFF;
    fseek(f, corrupt_pos, SEEK_SET);
    fwrite(&byte, 1, 1, f);
    fclose(f);

    /* Hidden password should now fail (GCM auth failure) */
    vol = denyfs_vol_open(STRESS_CONTAINER,
                          STRESS_HIDDEN_PW, strlen(STRESS_HIDDEN_PW),
                          NULL, 0, 0);
    assert(vol == NULL);

    /* Outer volume should still open fine (its header is untouched) */
    vol = denyfs_vol_open(STRESS_CONTAINER,
                          STRESS_PASSWORD, strlen(STRESS_PASSWORD),
                          NULL, 0, 0);
    assert(vol != NULL);
    assert(vol->is_hidden == 0);
    denyfs_vol_close(vol);

    remove(STRESS_CONTAINER);
    printf("[+] Corrupted hidden header correctly rejected; outer still works.\n");
}

/* ======================================================================== */
/* Test 3: Corrupted superblock rejection                                   */
/* ======================================================================== */

void test_corrupted_superblock(void) {
    printf("[*] Test 3: Corrupted superblock rejection after auth...\n");

    int res = denyfs_container_create(STRESS_CONTAINER, STRESS_SIZE_MB,
                                      STRESS_PASSWORD, strlen(STRESS_PASSWORD));
    assert(res == 0);

    /*
     * Corrupt the encrypted superblock. The superblock is at volume block 0,
     * which starts at byte offset HEADER_SIZE (4096). XTS operates on 16-byte
     * blocks — flipping bytes in the first 16-byte AES block of the superblock
     * will garble the magic field (bytes 0–7 of the decrypted superblock).
     * We flip multiple bytes to guarantee corruption survives XTS decryption.
     */
    FILE *f = fopen(STRESS_CONTAINER, "r+b");
    assert(f != NULL);
    /* Corrupt the first 16 bytes of the encrypted superblock (XTS block 0) */
    for (int offset = 0; offset < 16; offset++) {
        long sb_offset = HEADER_SIZE + offset;
        fseek(f, sb_offset, SEEK_SET);
        uint8_t byte;
        fread(&byte, 1, 1, f);
        byte ^= 0xFF;
        fseek(f, sb_offset, SEEK_SET);
        fwrite(&byte, 1, 1, f);
    }
    fclose(f);

    /* Open should fail — superblock magic won't match after XTS decryption of corrupted data */
    denyfs_volume_t *vol = denyfs_vol_open(STRESS_CONTAINER,
                                            STRESS_PASSWORD, strlen(STRESS_PASSWORD),
                                            NULL, 0, 0);
    assert(vol == NULL);

    remove(STRESS_CONTAINER);
    printf("[+] Corrupted superblock correctly rejected.\n");
}


/* ======================================================================== */
/* Test 4: Fill filesystem to max capacity (63 files)                       */
/* ======================================================================== */

void test_fill_max_files(void) {
    printf("[*] Test 4: Fill filesystem to max capacity (63 files)...\n");

    int res = denyfs_container_create(STRESS_CONTAINER, STRESS_SIZE_MB,
                                      STRESS_PASSWORD, strlen(STRESS_PASSWORD));
    assert(res == 0);

    denyfs_volume_t *vol = denyfs_vol_open(STRESS_CONTAINER,
                                            STRESS_PASSWORD, strlen(STRESS_PASSWORD),
                                            NULL, 0, 0);
    assert(vol != NULL);

    /* Create all 63 files (inode 0 is root) */
    char name[256];
    for (int i = 0; i < 63; i++) {
        snprintf(name, sizeof(name), "file_%03d.dat", i);
        uint32_t ino;
        res = denyfs_vol_create(vol, name, &ino);
        assert(res == 0);
        assert(ino >= 1);
    }

    /* 64th file must fail — no free inodes */
    uint32_t dummy;
    res = denyfs_vol_create(vol, "overflow.dat", &dummy);
    assert(res == -ENOSPC);

    /* Verify all 63 files can be looked up */
    for (int i = 0; i < 63; i++) {
        snprintf(name, sizeof(name), "file_%03d.dat", i);
        uint32_t ino;
        res = denyfs_vol_lookup(vol, name, &ino);
        assert(res == 0);
    }

    /* Delete all 63 files */
    for (int i = 0; i < 63; i++) {
        snprintf(name, sizeof(name), "file_%03d.dat", i);
        res = denyfs_vol_unlink(vol, name);
        assert(res == 0);
    }

    /* All inodes should be free again */
    assert(vol->sb.free_inodes == 63);

    denyfs_vol_close(vol);
    remove(STRESS_CONTAINER);
    printf("[+] Max file capacity test passed (63 create + 63 delete).\n");
}

/* ======================================================================== */
/* Test 5: Rapid create/delete cycles                                       */
/* ======================================================================== */

void test_rapid_create_delete_cycles(void) {
    printf("[*] Test 5: Rapid create/delete cycles (500 iterations)...\n");

    int res = denyfs_container_create(STRESS_CONTAINER, STRESS_SIZE_MB,
                                      STRESS_PASSWORD, strlen(STRESS_PASSWORD));
    assert(res == 0);

    denyfs_volume_t *vol = denyfs_vol_open(STRESS_CONTAINER,
                                            STRESS_PASSWORD, strlen(STRESS_PASSWORD),
                                            NULL, 0, 0);
    assert(vol != NULL);

    for (int cycle = 0; cycle < 500; cycle++) {
        char name[64];
        snprintf(name, sizeof(name), "cycle_%d.tmp", cycle % 10);

        /* Delete if exists */
        uint32_t ino;
        if (denyfs_vol_lookup(vol, name, &ino) == 0) {
            res = denyfs_vol_unlink(vol, name);
            assert(res == 0);
        }

        /* Create */
        res = denyfs_vol_create(vol, name, &ino);
        assert(res == 0);

        /* Write small payload */
        uint8_t data[64];
        memset(data, (uint8_t)(cycle & 0xFF), sizeof(data));
        int wr = denyfs_vol_write(vol, ino, data, sizeof(data), 0);
        assert(wr == sizeof(data));

        /* Read back and verify */
        uint8_t readback[64];
        int rd = denyfs_vol_read(vol, ino, readback, sizeof(readback), 0);
        assert(rd == sizeof(readback));
        assert(memcmp(data, readback, sizeof(data)) == 0);
    }

    denyfs_vol_close(vol);
    remove(STRESS_CONTAINER);
    printf("[+] 500 rapid create/delete cycles completed cleanly.\n");
}

/* ======================================================================== */
/* Test 6: Max file size write (96KB)                                       */
/* ======================================================================== */

void test_max_file_size(void) {
    printf("[*] Test 6: Max file size boundary (96KB write/read)...\n");

    int res = denyfs_container_create(STRESS_CONTAINER, STRESS_SIZE_MB,
                                      STRESS_PASSWORD, strlen(STRESS_PASSWORD));
    assert(res == 0);

    denyfs_volume_t *vol = denyfs_vol_open(STRESS_CONTAINER,
                                            STRESS_PASSWORD, strlen(STRESS_PASSWORD),
                                            NULL, 0, 0);
    assert(vol != NULL);

    uint32_t ino;
    res = denyfs_vol_create(vol, "maxfile.bin", &ino);
    assert(res == 0);

    /* Write exactly 96KB = 24 blocks * 4096 bytes */
    size_t max_size = DENYFS_DIRECT_BLOCKS * SECTOR_SIZE; /* 98304 */
    uint8_t *data = malloc(max_size);
    assert(data != NULL);
    /* Fill with a non-trivial pattern */
    for (size_t i = 0; i < max_size; i++) {
        data[i] = (uint8_t)((i * 7 + 13) & 0xFF);
    }

    int wr = denyfs_vol_write(vol, ino, data, max_size, 0);
    assert(wr == (int)max_size);

    /* Read back and verify full content */
    uint8_t *readback = malloc(max_size);
    assert(readback != NULL);
    int rd = denyfs_vol_read(vol, ino, readback, max_size, 0);
    assert(rd == (int)max_size);
    assert(memcmp(data, readback, max_size) == 0);

    free(data);
    free(readback);
    denyfs_vol_close(vol);
    remove(STRESS_CONTAINER);
    printf("[+] 96KB max file size write/read verified.\n");
}

/* ======================================================================== */
/* Test 7: Oversized write rejection                                        */
/* ======================================================================== */

void test_oversized_write_rejection(void) {
    printf("[*] Test 7: Oversized write rejection (>96KB)...\n");

    int res = denyfs_container_create(STRESS_CONTAINER, STRESS_SIZE_MB,
                                      STRESS_PASSWORD, strlen(STRESS_PASSWORD));
    assert(res == 0);

    denyfs_volume_t *vol = denyfs_vol_open(STRESS_CONTAINER,
                                            STRESS_PASSWORD, strlen(STRESS_PASSWORD),
                                            NULL, 0, 0);
    assert(vol != NULL);

    uint32_t ino;
    res = denyfs_vol_create(vol, "toobig.bin", &ino);
    assert(res == 0);

    /* Attempt to write 96KB + 1 byte from offset 0 */
    size_t over_size = DENYFS_DIRECT_BLOCKS * SECTOR_SIZE + 1;
    uint8_t *data = calloc(1, over_size);
    assert(data != NULL);

    int wr = denyfs_vol_write(vol, ino, data, over_size, 0);
    assert(wr == -ENOSPC);

    /* Attempt to write 1 byte past the end of max file capacity */
    size_t max_size = DENYFS_DIRECT_BLOCKS * SECTOR_SIZE;
    wr = denyfs_vol_write(vol, ino, data, 1, max_size);
    assert(wr == -ENOSPC);

    free(data);
    denyfs_vol_close(vol);
    remove(STRESS_CONTAINER);
    printf("[+] Oversized writes correctly rejected.\n");
}

/* ======================================================================== */
/* Test 8: Max-length filename (250 chars)                                  */
/* ======================================================================== */

void test_max_length_filename(void) {
    printf("[*] Test 8: Max-length filename (250 chars)...\n");

    int res = denyfs_container_create(STRESS_CONTAINER, STRESS_SIZE_MB,
                                      STRESS_PASSWORD, strlen(STRESS_PASSWORD));
    assert(res == 0);

    denyfs_volume_t *vol = denyfs_vol_open(STRESS_CONTAINER,
                                            STRESS_PASSWORD, strlen(STRESS_PASSWORD),
                                            NULL, 0, 0);
    assert(vol != NULL);

    /* Create a 250-character filename (max allowed = DENYFS_MAX_NAME_LEN - 1 = 250) */
    char long_name[256];
    memset(long_name, 'A', 250);
    long_name[250] = '\0';

    uint32_t ino;
    res = denyfs_vol_create(vol, long_name, &ino);
    assert(res == 0);

    /* Lookup should succeed */
    uint32_t found;
    res = denyfs_vol_lookup(vol, long_name, &found);
    assert(res == 0);
    assert(found == ino);

    denyfs_vol_close(vol);
    remove(STRESS_CONTAINER);
    printf("[+] 250-char filename created and looked up successfully.\n");
}

/* ======================================================================== */
/* Test 9: Invalid filename rejection                                       */
/* ======================================================================== */

void test_invalid_filename_rejection(void) {
    printf("[*] Test 9: Invalid filename rejection...\n");

    int res = denyfs_container_create(STRESS_CONTAINER, STRESS_SIZE_MB,
                                      STRESS_PASSWORD, strlen(STRESS_PASSWORD));
    assert(res == 0);

    denyfs_volume_t *vol = denyfs_vol_open(STRESS_CONTAINER,
                                            STRESS_PASSWORD, strlen(STRESS_PASSWORD),
                                            NULL, 0, 0);
    assert(vol != NULL);

    /* Empty name should fail */
    uint32_t ino;
    res = denyfs_vol_create(vol, "", &ino);
    assert(res != 0);

    /* 251-character name should fail (exceeds DENYFS_MAX_NAME_LEN - 1) */
    char too_long[256];
    memset(too_long, 'B', 251);
    too_long[251] = '\0';
    res = denyfs_vol_create(vol, too_long, &ino);
    assert(res != 0);

    denyfs_vol_close(vol);
    remove(STRESS_CONTAINER);
    printf("[+] Invalid filenames correctly rejected.\n");
}

/* ======================================================================== */
/* Test 10: Interleaved operations stress                                   */
/* ======================================================================== */

void test_interleaved_operations(void) {
    printf("[*] Test 10: Interleaved operations stress (200 iterations)...\n");

    int res = denyfs_container_create(STRESS_CONTAINER, STRESS_SIZE_MB,
                                      STRESS_PASSWORD, strlen(STRESS_PASSWORD));
    assert(res == 0);

    denyfs_volume_t *vol = denyfs_vol_open(STRESS_CONTAINER,
                                            STRESS_PASSWORD, strlen(STRESS_PASSWORD),
                                            NULL, 0, 0);
    assert(vol != NULL);

    for (int i = 0; i < 200; i++) {
        char name_a[64], name_b[64];
        snprintf(name_a, sizeof(name_a), "interleave_a_%d.dat", i % 5);
        snprintf(name_b, sizeof(name_b), "interleave_b_%d.dat", i % 5);

        /* Clean up if they exist from a previous iteration */
        uint32_t dummy;
        if (denyfs_vol_lookup(vol, name_a, &dummy) == 0) denyfs_vol_unlink(vol, name_a);
        if (denyfs_vol_lookup(vol, name_b, &dummy) == 0) denyfs_vol_unlink(vol, name_b);

        /* Create both */
        uint32_t ino_a, ino_b;
        res = denyfs_vol_create(vol, name_a, &ino_a);
        assert(res == 0);
        res = denyfs_vol_create(vol, name_b, &ino_b);
        assert(res == 0);

        /* Write to A */
        uint8_t buf_a[128];
        memset(buf_a, (uint8_t)(i & 0xFF), sizeof(buf_a));
        int wr = denyfs_vol_write(vol, ino_a, buf_a, sizeof(buf_a), 0);
        assert(wr == sizeof(buf_a));

        /* Truncate B to 4096 then write */
        res = denyfs_vol_truncate(vol, ino_b, 4096);
        assert(res == 0);
        uint8_t buf_b[256];
        memset(buf_b, (uint8_t)((i + 1) & 0xFF), sizeof(buf_b));
        wr = denyfs_vol_write(vol, ino_b, buf_b, sizeof(buf_b), 0);
        assert(wr == sizeof(buf_b));

        /* Read back A */
        uint8_t check_a[128];
        int rd = denyfs_vol_read(vol, ino_a, check_a, sizeof(check_a), 0);
        assert(rd == sizeof(check_a));
        assert(memcmp(buf_a, check_a, sizeof(buf_a)) == 0);

        /* Read back B */
        uint8_t check_b[256];
        rd = denyfs_vol_read(vol, ino_b, check_b, sizeof(check_b), 0);
        assert(rd == sizeof(check_b));
        assert(memcmp(buf_b, check_b, sizeof(buf_b)) == 0);

        /* Delete A, keep B for next iteration's cleanup */
        res = denyfs_vol_unlink(vol, name_a);
        assert(res == 0);
    }

    denyfs_vol_close(vol);

    /* Verify persistence — reopen and check we didn't leak state */
    vol = denyfs_vol_open(STRESS_CONTAINER,
                          STRESS_PASSWORD, strlen(STRESS_PASSWORD),
                          NULL, 0, 0);
    assert(vol != NULL);
    /* Should have some files left from last iteration */
    denyfs_vol_close(vol);

    remove(STRESS_CONTAINER);
    printf("[+] 200 interleaved operation iterations completed cleanly.\n");
}

/* ======================================================================== */
/* Main                                                                      */
/* ======================================================================== */

int main(void) {
    if (denyfs_crypto_init() != 0) {
        fprintf(stderr, "[-] Crypto init failed\n");
        return 1;
    }

    printf("=== DenyFS Phase 6: Stress Tests & Seeded Correctness ===\n\n");

    test_corrupted_outer_header();
    test_corrupted_hidden_header();
    test_corrupted_superblock();
    test_fill_max_files();
    test_rapid_create_delete_cycles();
    test_max_file_size();
    test_oversized_write_rejection();
    test_max_length_filename();
    test_invalid_filename_rejection();
    test_interleaved_operations();

    printf("\n[+] All Phase 6 stress tests passed successfully.\n");

    denyfs_crypto_cleanup();
    return 0;
}
