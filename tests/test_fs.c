#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sodium.h>
#include "crypto.h"
#include "fs.h"

/*
 * Phase 3 & 4 integration tests: filesystem layer (no FUSE).
 */

#define TEST_CONTAINER "test_fs.img"
#define TEST_PASSWORD  "fs_test_pass_99"
#define TEST_SIZE_MB   10

static int dir_count;
static char dir_names[64][256];

static int count_cb(const char *name, uint32_t ino, void *userdata) {
    (void)ino; (void)userdata;
    if (dir_count < 64) {
        strncpy(dir_names[dir_count], name, 255);
        dir_names[dir_count][255] = '\0';
    }
    dir_count++;
    return 0;
}

void test_create_and_format(void) {
    printf("[*] Testing container creation and format...\n");

    int res = denyfs_container_create(TEST_CONTAINER, TEST_SIZE_MB,
                                      TEST_PASSWORD, strlen(TEST_PASSWORD));
    assert(res == 0);

    // Open and verify metadata
    denyfs_volume_t *vol = denyfs_vol_open(TEST_CONTAINER,
                                           TEST_PASSWORD, strlen(TEST_PASSWORD),
                                           NULL, 0, 0);
    assert(vol != NULL);
    assert(vol->sb.magic == DENYFS_SB_MAGIC);
    assert(vol->sb.block_size == SECTOR_SIZE);
    assert(vol->sb.inode_count == DENYFS_MAX_INODES);
    assert(vol->sb.data_start == 1 + vol->sb.bitmap_blocks + vol->sb.inode_blocks);

    // Root dir exists (inode 0)
    assert(vol->inodes[0].type == DENYFS_ITYPE_DIR);
    assert(vol->inodes[0].block_count == 1);

    // Empty directory
    dir_count = 0;
    denyfs_vol_readdir(vol, count_cb, NULL);
    assert(dir_count == 0);

    denyfs_vol_close(vol);
    printf("[+] Container created and formatted correctly.\n");
}

void test_file_create_lookup(void) {
    printf("[*] Testing file create and lookup...\n");

    denyfs_volume_t *vol = denyfs_vol_open(TEST_CONTAINER,
                                           TEST_PASSWORD, strlen(TEST_PASSWORD),
                                           NULL, 0, 0);
    assert(vol != NULL);

    uint32_t ino;
    int res = denyfs_vol_create(vol, "hello.txt", &ino);
    assert(res == 0);
    assert(ino >= 1 && ino < DENYFS_MAX_INODES);

    // Lookup should find it
    uint32_t found_ino;
    res = denyfs_vol_lookup(vol, "hello.txt", &found_ino);
    assert(res == 0);
    assert(found_ino == ino);

    // Duplicate name should fail
    res = denyfs_vol_create(vol, "hello.txt", &ino);
    assert(res != 0);

    denyfs_vol_close(vol);
    printf("[+] File create and lookup work correctly.\n");
}

void test_write_read(void) {
    printf("[*] Testing file write and read...\n");

    denyfs_volume_t *vol = denyfs_vol_open(TEST_CONTAINER,
                                           TEST_PASSWORD, strlen(TEST_PASSWORD),
                                           NULL, 0, 0);
    assert(vol != NULL);

    uint32_t ino;
    assert(denyfs_vol_lookup(vol, "hello.txt", &ino) == 0);

    const char *msg = "DenyFS filesystem layer test data — round-trip verification.";
    size_t msg_len = strlen(msg);
    int written = denyfs_vol_write(vol, ino, msg, msg_len, 0);
    assert(written == (int)msg_len);

    char readback[256];
    memset(readback, 0, sizeof(readback));
    int nread = denyfs_vol_read(vol, ino, readback, msg_len, 0);
    assert(nread == (int)msg_len);
    assert(memcmp(readback, msg, msg_len) == 0);

    nread = denyfs_vol_read(vol, ino, readback, 10, (uint64_t)msg_len + 100);
    assert(nread == 0);

    memset(readback, 0, sizeof(readback));
    nread = denyfs_vol_read(vol, ino, readback, 6, 0);
    assert(nread == 6);
    assert(memcmp(readback, "DenyFS", 6) == 0);

    denyfs_vol_close(vol);
    printf("[+] Write/read roundtrip verified.\n");
}

void test_multi_block_write(void) {
    printf("[*] Testing multi-block write...\n");

    denyfs_volume_t *vol = denyfs_vol_open(TEST_CONTAINER,
                                           TEST_PASSWORD, strlen(TEST_PASSWORD),
                                           NULL, 0, 0);
    assert(vol != NULL);

    uint32_t ino;
    assert(denyfs_vol_create(vol, "bigfile.bin", &ino) == 0);

    uint8_t *data = malloc(10000);
    assert(data != NULL);
    for (int i = 0; i < 10000; i++) data[i] = (uint8_t)(i & 0xFF);

    int written = denyfs_vol_write(vol, ino, data, 10000, 0);
    assert(written == 10000);

    uint8_t *readback = malloc(10000);
    assert(readback != NULL);
    int nread = denyfs_vol_read(vol, ino, readback, 10000, 0);
    assert(nread == 10000);
    assert(memcmp(data, readback, 10000) == 0);

    free(data);
    free(readback);
    denyfs_vol_close(vol);
    printf("[+] Multi-block write/read verified.\n");
}

void test_readdir(void) {
    printf("[*] Testing readdir...\n");

    denyfs_volume_t *vol = denyfs_vol_open(TEST_CONTAINER,
                                           TEST_PASSWORD, strlen(TEST_PASSWORD),
                                           NULL, 0, 0);
    assert(vol != NULL);

    uint32_t ino;
    denyfs_vol_create(vol, "notes.md", &ino);
    denyfs_vol_create(vol, "data.csv", &ino);

    dir_count = 0;
    denyfs_vol_readdir(vol, count_cb, NULL);
    assert(dir_count == 4);

    denyfs_vol_close(vol);
    printf("[+] Readdir lists all files correctly.\n");
}

void test_truncate(void) {
    printf("[*] Testing truncate...\n");

    denyfs_volume_t *vol = denyfs_vol_open(TEST_CONTAINER,
                                           TEST_PASSWORD, strlen(TEST_PASSWORD),
                                           NULL, 0, 0);
    assert(vol != NULL);

    uint32_t ino;
    assert(denyfs_vol_lookup(vol, "hello.txt", &ino) == 0);

    assert(denyfs_vol_truncate(vol, ino, 0) == 0);
    assert(vol->inodes[ino].size == 0);

    denyfs_vol_close(vol);
    printf("[+] Truncate works correctly.\n");
}

void test_unlink(void) {
    printf("[*] Testing unlink...\n");

    denyfs_volume_t *vol = denyfs_vol_open(TEST_CONTAINER,
                                           TEST_PASSWORD, strlen(TEST_PASSWORD),
                                           NULL, 0, 0);
    assert(vol != NULL);

    uint32_t free_inodes_before = vol->sb.free_inodes;
    assert(denyfs_vol_unlink(vol, "notes.md") == 0);

    uint32_t ino;
    assert(denyfs_vol_lookup(vol, "notes.md", &ino) != 0);
    assert(vol->sb.free_inodes == free_inodes_before + 1);

    denyfs_vol_close(vol);
    printf("[+] Unlink works correctly.\n");
}

void test_persistence(void) {
    printf("[*] Testing persistence across close/reopen...\n");

    {
        denyfs_volume_t *vol = denyfs_vol_open(TEST_CONTAINER,
                                               TEST_PASSWORD, strlen(TEST_PASSWORD),
                                               NULL, 0, 0);
        assert(vol != NULL);
        uint32_t ino;
        assert(denyfs_vol_lookup(vol, "data.csv", &ino) == 0);
        const char *csv = "name,val\na,1\n";
        denyfs_vol_write(vol, ino, csv, strlen(csv), 0);
        denyfs_vol_close(vol);
    }

    {
        denyfs_volume_t *vol = denyfs_vol_open(TEST_CONTAINER,
                                               TEST_PASSWORD, strlen(TEST_PASSWORD),
                                               NULL, 0, 0);
        assert(vol != NULL);
        uint32_t ino;
        assert(denyfs_vol_lookup(vol, "data.csv", &ino) == 0);
        char readback[128];
        memset(readback, 0, sizeof(readback));
        denyfs_vol_read(vol, ino, readback, sizeof(readback), 0);
        assert(strcmp(readback, "name,val\na,1\n") == 0);
        denyfs_vol_close(vol);
    }
    printf("[+] Persistence verified.\n");
}

void test_bitmap_hmac_corruption(void) {
    printf("[*] Testing bitmap HMAC integrity check...\n");

    const char *corrupt_img = "test_corrupt.img";
    assert(denyfs_container_create(corrupt_img, 4, TEST_PASSWORD,
                                    strlen(TEST_PASSWORD)) == 0);

    {
        denyfs_volume_t *vol = denyfs_vol_open(corrupt_img,
                                               TEST_PASSWORD, strlen(TEST_PASSWORD),
                                               NULL, 0, 0);
        assert(vol != NULL);
        uint32_t ino;
        assert(denyfs_vol_create(vol, "test.txt", &ino) == 0);
        denyfs_vol_close(vol);
    }

    {
        FILE *f = fopen(corrupt_img, "r+b");
        assert(f != NULL);
        long bm_offset = HEADER_SIZE + SECTOR_SIZE;
        fseek(f, bm_offset + 42, SEEK_SET);
        uint8_t byte;
        assert(fread(&byte, 1, 1, f) == 1);
        byte ^= 0xFF;
        fseek(f, bm_offset + 42, SEEK_SET);
        assert(fwrite(&byte, 1, 1, f) == 1);
        fclose(f);
    }

    denyfs_volume_t *vol = denyfs_vol_open(corrupt_img,
                                           TEST_PASSWORD, strlen(TEST_PASSWORD),
                                           NULL, 0, 0);
    assert(vol == NULL);
    remove(corrupt_img);
    printf("[+] Bitmap HMAC corruption correctly detected.\n");
}

void test_wrong_password(void) {
    printf("[*] Testing wrong password rejection...\n");
    denyfs_volume_t *vol = denyfs_vol_open(TEST_CONTAINER, "wrong_password_123", 18, NULL, 0, 0);
    assert(vol == NULL);
    printf("[+] Wrong password correctly rejected.\n");
}

void test_hidden_volume_functionality(void) {
    printf("[*] Testing hidden volume formatting, mounting, and protection...\n");

    const char *hidden_pass = "hidden_secret_999";
    uint64_t hidden_size_mb = 2;

    // 1. Create hidden volume inside TEST_CONTAINER
    int res = denyfs_container_create_hidden(TEST_CONTAINER,
                                             TEST_PASSWORD, strlen(TEST_PASSWORD),
                                             hidden_pass, strlen(hidden_pass),
                                             hidden_size_mb);
    assert(res == 0);

    // 2. Open hidden volume
    denyfs_volume_t *vol_hidden = denyfs_vol_open(TEST_CONTAINER,
                                                  hidden_pass, strlen(hidden_pass),
                                                  NULL, 0, 0);
    assert(vol_hidden != NULL);
    assert(vol_hidden->is_hidden == 1);
    assert(vol_hidden->volume_size == hidden_size_mb * 1024 * 1024);

    // Verify it is empty and format succeeded
    assert(vol_hidden->sb.magic == DENYFS_SB_MAGIC);
    dir_count = 0;
    denyfs_vol_readdir(vol_hidden, count_cb, NULL);
    assert(dir_count == 0);

    // Create file inside hidden volume
    uint32_t h_ino;
    assert(denyfs_vol_create(vol_hidden, "secret.key", &h_ino) == 0);
    const char *secret_data = "HIDDEN_SECRET_PAYLOAD_HERE";
    assert(denyfs_vol_write(vol_hidden, h_ino, secret_data, strlen(secret_data), 0) == (int)strlen(secret_data));

    denyfs_vol_close(vol_hidden);
    printf("[+] Hidden volume format and write succeeded.\n");

    // 3. Open outer volume normally
    denyfs_volume_t *vol_outer = denyfs_vol_open(TEST_CONTAINER,
                                                 TEST_PASSWORD, strlen(TEST_PASSWORD),
                                                 NULL, 0, 0);
    assert(vol_outer != NULL);
    assert(vol_outer->is_hidden == 0);

    // Outer volume should NOT see the hidden volume's files
    uint32_t dummy;
    assert(denyfs_vol_lookup(vol_outer, "secret.key", &dummy) != 0);

    denyfs_vol_close(vol_outer);
    printf("[+] Outer volume cannot see hidden volume files.\n");

    // 4. Open outer volume WITH hidden volume protection
    vol_outer = denyfs_vol_open(TEST_CONTAINER,
                                TEST_PASSWORD, strlen(TEST_PASSWORD),
                                hidden_pass, strlen(hidden_pass),
                                1);
    assert(vol_outer != NULL);
    assert(vol_outer->protect_hidden == 1);
    assert(vol_outer->protect_start_sector > 0);
    assert(vol_outer->protect_end_sector > vol_outer->protect_start_sector);

    denyfs_vol_close(vol_outer);
    printf("[+] Outer-mount protection activated and mapped correctly.\n");
}

int main(void) {
    if (denyfs_crypto_init() != 0) {
        fprintf(stderr, "[-] Crypto library init failed.\n");
        return 1;
    }

    printf("[*] Running Phase 3 & 4 Filesystem Tests...\n");

    test_create_and_format();
    test_file_create_lookup();
    test_write_read();
    test_multi_block_write();
    test_readdir();
    test_truncate();
    test_unlink();
    test_persistence();
    test_bitmap_hmac_corruption();
    test_wrong_password();
    test_hidden_volume_functionality();

    remove(TEST_CONTAINER);

    denyfs_crypto_cleanup();
    printf("[+] All Phase 3 & 4 tests passed successfully.\n");
    return 0;
}
