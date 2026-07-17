#include "fs.h"
#include "crypto.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sodium.h>

// ---------------------------------------------------------------------------
// Block-level I/O helpers (encrypt/decrypt + seek + read/write)
// ---------------------------------------------------------------------------

static int read_block(denyfs_volume_t *vol, uint32_t block_num, uint8_t *out) {
    uint8_t cipher[SECTOR_SIZE];
    long offset = (long)vol->vol_start_offset + (long)block_num * SECTOR_SIZE;
    if (fseek(vol->fp, offset, SEEK_SET) != 0) return -1;
    if (fread(cipher, 1, SECTOR_SIZE, vol->fp) != SECTOR_SIZE) return -1;
    return denyfs_crypt_sector(cipher, out, (uint64_t)block_num, vol->volume_key, 0);
}

static int write_block(denyfs_volume_t *vol, uint32_t block_num, const uint8_t *data) {
    // Outer-mount protection: block writes inside the hidden volume boundaries
    if (vol->protect_hidden) {
        uint64_t absolute_sector = (vol->vol_start_offset / SECTOR_SIZE) + block_num;
        if (absolute_sector >= vol->protect_start_sector && absolute_sector <= vol->protect_end_sector) {
            return -ENOSPC;
        }
    }
    
    uint8_t cipher[SECTOR_SIZE];
    if (denyfs_crypt_sector(data, cipher, (uint64_t)block_num, vol->volume_key, 1) != 0)
        return -1;
    long offset = (long)vol->vol_start_offset + (long)block_num * SECTOR_SIZE;
    if (fseek(vol->fp, offset, SEEK_SET) != 0) return -1;
    if (fwrite(cipher, 1, SECTOR_SIZE, vol->fp) != SECTOR_SIZE) return -1;
    fflush(vol->fp);
    return 0;
}

// Low-level helper for formatting (where no denyfs_volume_t exists yet)
static int write_block_raw(FILE *fp, const uint8_t *volume_key, uint64_t start_offset,
                           uint32_t block_num, const uint8_t *data) {
    uint8_t cipher[SECTOR_SIZE];
    if (denyfs_crypt_sector(data, cipher, (uint64_t)block_num, volume_key, 1) != 0)
        return -1;
    long offset = (long)start_offset + (long)block_num * SECTOR_SIZE;
    if (fseek(fp, offset, SEEK_SET) != 0) return -1;
    if (fwrite(cipher, 1, SECTOR_SIZE, fp) != SECTOR_SIZE) return -1;
    fflush(fp);
    return 0;
}

// ---------------------------------------------------------------------------
// Bitmap helpers
// ---------------------------------------------------------------------------

static int alloc_block(denyfs_volume_t *vol) {
    for (uint32_t i = vol->sb.data_start; i < vol->sb.total_blocks; i++) {
        if (!(vol->bitmap[i / 8] & (1 << (i % 8)))) {
            vol->bitmap[i / 8] |= (uint8_t)(1 << (i % 8));
            vol->sb.free_blocks--;
            return (int)i;
        }
    }
    return -1;
}

static void free_block(denyfs_volume_t *vol, uint32_t block_num) {
    if (block_num >= vol->sb.data_start && block_num < vol->sb.total_blocks) {
        vol->bitmap[block_num / 8] &= (uint8_t)~(1 << (block_num % 8));
        vol->sb.free_blocks++;
    }
}

// ---------------------------------------------------------------------------
// Directory helpers
// ---------------------------------------------------------------------------

static int add_dirent(denyfs_volume_t *vol, const char *name, uint32_t ino) {
    denyfs_inode_t *root = &vol->inodes[0];
    size_t name_len = strlen(name);
    if (name_len == 0 || name_len >= DENYFS_MAX_NAME_LEN) return -ENAMETOOLONG;

    // Search existing blocks for a free slot
    for (uint32_t bi = 0; bi < DENYFS_DIRECT_BLOCKS; bi++) {
        if (root->direct[bi] == DENYFS_INVALID_BLOCK) break;

        uint8_t block_data[SECTOR_SIZE];
        if (read_block(vol, root->direct[bi], block_data) != 0)
            return -EIO;

        denyfs_dirent_t *entries = (denyfs_dirent_t *)block_data;
        for (int i = 0; i < DENYFS_DIRENTS_PER_BLOCK; i++) {
            if (entries[i].inode == DENYFS_INVALID_INO) {
                entries[i].inode = ino;
                entries[i].name_len = (uint8_t)name_len;
                memset(entries[i].name, 0, sizeof(entries[i].name));
                memcpy(entries[i].name, name, name_len);
                return write_block(vol, root->direct[bi], block_data);
            }
        }
    }

    // All existing blocks full — allocate a new block for root dir
    if (root->block_count >= DENYFS_DIRECT_BLOCKS) return -ENOSPC;

    int new_blk = alloc_block(vol);
    if (new_blk < 0) return -ENOSPC;

    // Initialize new block with free entries
    uint8_t block_data[SECTOR_SIZE];
    memset(block_data, 0, sizeof(block_data));
    denyfs_dirent_t *entries = (denyfs_dirent_t *)block_data;
    for (int i = 0; i < DENYFS_DIRENTS_PER_BLOCK; i++)
        entries[i].inode = DENYFS_INVALID_INO;

    // Set first entry
    entries[0].inode = ino;
    entries[0].name_len = (uint8_t)name_len;
    memcpy(entries[0].name, name, name_len);

    root->direct[root->block_count] = (uint32_t)new_blk;
    root->block_count++;

    return write_block(vol, (uint32_t)new_blk, block_data);
}

static int remove_dirent(denyfs_volume_t *vol, const char *name) {
    denyfs_inode_t *root = &vol->inodes[0];
    size_t name_len = strlen(name);

    for (uint32_t bi = 0; bi < DENYFS_DIRECT_BLOCKS; bi++) {
        if (root->direct[bi] == DENYFS_INVALID_BLOCK) continue;

        uint8_t block_data[SECTOR_SIZE];
        if (read_block(vol, root->direct[bi], block_data) != 0)
            return -EIO;

        denyfs_dirent_t *entries = (denyfs_dirent_t *)block_data;
        for (int i = 0; i < DENYFS_DIRENTS_PER_BLOCK; i++) {
            if (entries[i].inode != DENYFS_INVALID_INO &&
                entries[i].name_len == name_len &&
                memcmp(entries[i].name, name, name_len) == 0) {
                entries[i].inode = DENYFS_INVALID_INO;
                entries[i].name_len = 0;
                memset(entries[i].name, 0, sizeof(entries[i].name));
                return write_block(vol, root->direct[bi], block_data);
            }
        }
    }
    return -ENOENT;
}

// ---------------------------------------------------------------------------
// Inode helpers
// ---------------------------------------------------------------------------

static int alloc_inode(denyfs_volume_t *vol) {
    // Inode 0 is root dir — start search at 1
    for (uint32_t i = 1; i < DENYFS_MAX_INODES; i++) {
        if (vol->inodes[i].type == DENYFS_ITYPE_FREE) {
            vol->sb.free_inodes--;
            return (int)i;
        }
    }
    return -1;
}

static void free_inode(denyfs_volume_t *vol, uint32_t ino) {
    denyfs_inode_t *inode = &vol->inodes[ino];

    // Free all data blocks
    for (uint32_t i = 0; i < DENYFS_DIRECT_BLOCKS; i++) {
        if (inode->direct[i] != DENYFS_INVALID_BLOCK) {
            free_block(vol, inode->direct[i]);
            inode->direct[i] = DENYFS_INVALID_BLOCK;
        }
    }

    inode->type = DENYFS_ITYPE_FREE;
    inode->size = 0;
    inode->block_count = 0;
    inode->mtime = 0;
    vol->sb.free_inodes++;
}

// ---------------------------------------------------------------------------
// Format — write initial filesystem metadata into an already-open container
// ---------------------------------------------------------------------------

static int format_volume(FILE *fp, const uint8_t *volume_key,
                         const uint8_t *hmac_key, uint64_t volume_size,
                         uint64_t start_offset) {
    uint32_t total_blocks = (uint32_t)(volume_size / SECTOR_SIZE);
    uint32_t bitmap_bytes_needed = (total_blocks + 7) / 8;
    uint32_t bitmap_blocks = (bitmap_bytes_needed + SECTOR_SIZE - 1) / SECTOR_SIZE;
    uint32_t inode_blocks = (DENYFS_MAX_INODES * DENYFS_INODE_SIZE + SECTOR_SIZE - 1)
                            / SECTOR_SIZE;
    uint32_t data_start = 1 + bitmap_blocks + inode_blocks;

    if (data_start >= total_blocks) return -1;  // volume too small

    // ------ Bitmap (all free initially, then mark metadata + root block) ------
    size_t bm_total = (size_t)bitmap_blocks * SECTOR_SIZE;
    uint8_t *bitmap = calloc(1, bm_total);
    if (!bitmap) return -1;

    // Mark metadata blocks as allocated
    for (uint32_t i = 0; i < data_start; i++)
        bitmap[i / 8] |= (uint8_t)(1 << (i % 8));

    // Allocate first data block for root dir
    uint32_t root_block = data_start;
    bitmap[root_block / 8] |= (uint8_t)(1 << (root_block % 8));

    // ------ Superblock ------
    denyfs_superblock_t sb;
    memset(&sb, 0, sizeof(sb));
    sb.magic        = DENYFS_SB_MAGIC;
    sb.block_size   = SECTOR_SIZE;
    sb.total_blocks = total_blocks;
    sb.inode_count  = DENYFS_MAX_INODES;
    sb.bitmap_start = 1;
    sb.bitmap_blocks = bitmap_blocks;
    sb.inode_start  = 1 + bitmap_blocks;
    sb.inode_blocks = inode_blocks;
    sb.data_start   = data_start;
    sb.free_blocks  = total_blocks - data_start - 1;
    sb.free_inodes  = DENYFS_MAX_INODES - 1;

    // Compute bitmap HMAC
    denyfs_compute_hmac(hmac_key, KEY_SIZE_HMAC, bitmap, bm_total, sb.bitmap_hmac);

    // ------ Inode table ------
    denyfs_inode_t inodes[DENYFS_MAX_INODES];
    memset(inodes, 0, sizeof(inodes));
    for (uint32_t i = 0; i < DENYFS_MAX_INODES; i++) {
        inodes[i].type = DENYFS_ITYPE_FREE;
        memset(inodes[i].direct, 0xFF, sizeof(inodes[i].direct));
    }

    // Root dir — inode 0
    inodes[0].type = DENYFS_ITYPE_DIR;
    inodes[0].size = 0;
    inodes[0].block_count = 1;
    memset(inodes[0].direct, 0xFF, sizeof(inodes[0].direct));
    inodes[0].direct[0] = root_block;
    inodes[0].mtime = (uint64_t)time(NULL);

    // ------ Write everything ------
    // Superblock (block 0)
    if (write_block_raw(fp, volume_key, start_offset, 0, (const uint8_t *)&sb) != 0)
        { free(bitmap); return -1; }

    // Bitmap blocks
    for (uint32_t i = 0; i < bitmap_blocks; i++) {
        if (write_block_raw(fp, volume_key, start_offset, 1 + i, bitmap + i * SECTOR_SIZE) != 0)
            { free(bitmap); return -1; }
    }

    // Inode table blocks
    for (uint32_t i = 0; i < inode_blocks; i++) {
        if (write_block_raw(fp, volume_key, start_offset, sb.inode_start + i,
                        ((const uint8_t *)inodes) + i * SECTOR_SIZE) != 0)
            { free(bitmap); return -1; }
    }

    // Root dir data block (all entries free)
    uint8_t root_data[SECTOR_SIZE];
    memset(root_data, 0, sizeof(root_data));
    denyfs_dirent_t *entries = (denyfs_dirent_t *)root_data;
    for (int i = 0; i < DENYFS_DIRENTS_PER_BLOCK; i++)
        entries[i].inode = DENYFS_INVALID_INO;
    if (write_block_raw(fp, volume_key, start_offset, root_block, root_data) != 0)
        { free(bitmap); return -1; }

    free(bitmap);
    return 0;
}

// ---------------------------------------------------------------------------
// Public: create container
// ---------------------------------------------------------------------------

int denyfs_container_create(const char *path, uint64_t size_mb,
                            const char *password, size_t pass_len) {
    uint64_t total_bytes = size_mb * 1024 * 1024;
    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    // CSPRNG fill
    size_t chunk_size = 65536;
    uint8_t *chunk = malloc(chunk_size);
    if (!chunk) { fclose(f); return -1; }

    uint64_t written = 0;
    while (written < total_bytes) {
        uint64_t rem = total_bytes - written;
        size_t to_write = (rem < chunk_size) ? (size_t)rem : chunk_size;
        randombytes_buf(chunk, to_write);
        if (fwrite(chunk, 1, to_write, f) != to_write)
            { free(chunk); fclose(f); return -1; }
        written += to_write;
    }
    free(chunk);

    // Generate keys
    uint8_t *salt       = denyfs_secure_alloc(SALT_SIZE);
    uint8_t *master_key = denyfs_secure_alloc(KEY_SIZE_GCM);
    uint8_t *header_key = denyfs_secure_alloc(KEY_SIZE_GCM);
    uint8_t *volume_key = denyfs_secure_alloc(KEY_SIZE_XTS);
    uint8_t *hmac_key   = denyfs_secure_alloc(KEY_SIZE_HMAC);
    if (!salt || !master_key || !header_key || !volume_key || !hmac_key) {
        if (salt) denyfs_secure_free(salt, SALT_SIZE);
        if (master_key) denyfs_secure_free(master_key, KEY_SIZE_GCM);
        if (header_key) denyfs_secure_free(header_key, KEY_SIZE_GCM);
        if (volume_key) denyfs_secure_free(volume_key, KEY_SIZE_XTS);
        if (hmac_key) denyfs_secure_free(hmac_key, KEY_SIZE_HMAC);
        fclose(f); return -1;
    }

    randombytes_buf(salt, SALT_SIZE);
    randombytes_buf(volume_key, KEY_SIZE_XTS);
    randombytes_buf(hmac_key, KEY_SIZE_HMAC);

    if (denyfs_derive_master_key(password, pass_len, salt, master_key) != 0)
        { fclose(f); goto cleanup_keys; }
    if (denyfs_derive_header_key(master_key, header_key) != 0)
        { fclose(f); goto cleanup_keys; }

    // Build header payload
    uint64_t volume_size = total_bytes / 2;
    denyfs_header_payload_t payload;
    memset(&payload, 0, sizeof(payload));
    payload.magic         = 0x44656e7946533031ULL;
    payload.volume_size   = volume_size;
    payload.bitmap_offset = SECTOR_SIZE;  // bitmap at block 1
    payload.bitmap_size   = ((volume_size / SECTOR_SIZE) + 7) / 8;
    memcpy(payload.volume_key, volume_key, KEY_SIZE_XTS);
    memcpy(payload.hmac_key, hmac_key, KEY_SIZE_HMAC);
    randombytes_buf(payload.reserved, sizeof(payload.reserved));

    // Encrypt header
    denyfs_header_disk_t disk_header;
    memset(&disk_header, 0, sizeof(disk_header));
    memcpy(disk_header.salt, salt, SALT_SIZE);
    if (denyfs_encrypt_header(&payload, header_key, &disk_header) != 0)
        { fclose(f); goto cleanup_keys; }

    // Write header at byte 0
    fseek(f, 0, SEEK_SET);
    if (fwrite(&disk_header, 1, sizeof(disk_header), f) != sizeof(disk_header))
        { fclose(f); goto cleanup_keys; }

    // Format filesystem inside the volume (starting at byte 4096)
    int fmt_res = format_volume(f, volume_key, hmac_key, volume_size, HEADER_SIZE);

    fclose(f);
    sodium_memzero(&payload, sizeof(payload));

cleanup_keys:
    denyfs_secure_free(salt, SALT_SIZE);
    denyfs_secure_free(master_key, KEY_SIZE_GCM);
    denyfs_secure_free(header_key, KEY_SIZE_GCM);
    denyfs_secure_free(volume_key, KEY_SIZE_XTS);
    denyfs_secure_free(hmac_key, KEY_SIZE_HMAC);
    return fmt_res;
}

// ---------------------------------------------------------------------------
// Public: create hidden volume
// ---------------------------------------------------------------------------

int denyfs_container_create_hidden(const char *path,
                                   const char *outer_password, size_t outer_pass_len,
                                   const char *hidden_password, size_t hidden_pass_len,
                                   uint64_t hidden_size_mb) {
    // Authenticate and open the outer volume to verify space
    denyfs_volume_t *vol = denyfs_vol_open(path, outer_password, outer_pass_len, NULL, 0, 0);
    if (!vol) return -EACCES;

    // Get total container size
    if (fseek(vol->fp, 0, SEEK_END) != 0) { denyfs_vol_close(vol); return -EIO; }
    long container_size = ftell(vol->fp);
    if (container_size < 0) { denyfs_vol_close(vol); return -EIO; }

    uint64_t hidden_size_bytes = hidden_size_mb * 1024 * 1024;
    uint64_t outer_end = vol->vol_start_offset + vol->volume_size;
    uint64_t hidden_header_offset = (uint64_t)container_size - DENYFS_HIDDEN_HEADER_OFFSET_FROM_EOF;

    if (outer_end + hidden_size_bytes > hidden_header_offset) {
        // No space remaining
        denyfs_vol_close(vol);
        return -ENOSPC;
    }

    uint64_t hidden_start_offset = hidden_header_offset - hidden_size_bytes;

    // Generate keys for the hidden volume
    uint8_t *salt       = denyfs_secure_alloc(SALT_SIZE);
    uint8_t *master_key = denyfs_secure_alloc(KEY_SIZE_GCM);
    uint8_t *header_key = denyfs_secure_alloc(KEY_SIZE_GCM);
    uint8_t *volume_key = denyfs_secure_alloc(KEY_SIZE_XTS);
    uint8_t *hmac_key   = denyfs_secure_alloc(KEY_SIZE_HMAC);
    if (!salt || !master_key || !header_key || !volume_key || !hmac_key) {
        if (salt) denyfs_secure_free(salt, SALT_SIZE);
        if (master_key) denyfs_secure_free(master_key, KEY_SIZE_GCM);
        if (header_key) denyfs_secure_free(header_key, KEY_SIZE_GCM);
        if (volume_key) denyfs_secure_free(volume_key, KEY_SIZE_XTS);
        if (hmac_key) denyfs_secure_free(hmac_key, KEY_SIZE_HMAC);
        denyfs_vol_close(vol); return -ENOMEM;
    }

    randombytes_buf(salt, SALT_SIZE);
    randombytes_buf(volume_key, KEY_SIZE_XTS);
    randombytes_buf(hmac_key, KEY_SIZE_HMAC);

    if (denyfs_derive_master_key(hidden_password, hidden_pass_len, salt, master_key) != 0 ||
        denyfs_derive_header_key(master_key, header_key) != 0) {
        denyfs_vol_close(vol);
        goto cleanup_keys;
    }

    // Build hidden header payload
    denyfs_header_payload_t payload;
    memset(&payload, 0, sizeof(payload));
    payload.magic         = 0x44656e7946533031ULL;
    payload.volume_size   = hidden_size_bytes;
    payload.bitmap_offset = SECTOR_SIZE;
    payload.bitmap_size   = ((hidden_size_bytes / SECTOR_SIZE) + 7) / 8;
    memcpy(payload.volume_key, volume_key, KEY_SIZE_XTS);
    memcpy(payload.hmac_key, hmac_key, KEY_SIZE_HMAC);
    randombytes_buf(payload.reserved, sizeof(payload.reserved));

    // Encrypt hidden header
    denyfs_header_disk_t disk_header;
    memset(&disk_header, 0, sizeof(disk_header));
    memcpy(disk_header.salt, salt, SALT_SIZE);
    if (denyfs_encrypt_header(&payload, header_key, &disk_header) != 0) {
        denyfs_vol_close(vol);
        goto cleanup_keys;
    }

    // Write hidden header at C - 32768
    if (fseek(vol->fp, (long)hidden_header_offset, SEEK_SET) != 0) {
        denyfs_vol_close(vol);
        goto cleanup_keys;
    }
    if (fwrite(&disk_header, 1, sizeof(disk_header), vol->fp) != sizeof(disk_header)) {
        denyfs_vol_close(vol);
        goto cleanup_keys;
    }

    // Format the hidden volume at its calculated start offset
    int fmt_res = format_volume(vol->fp, volume_key, hmac_key, hidden_size_bytes, hidden_start_offset);

    denyfs_vol_close(vol);
    sodium_memzero(&payload, sizeof(payload));

cleanup_keys:
    denyfs_secure_free(salt, SALT_SIZE);
    denyfs_secure_free(master_key, KEY_SIZE_GCM);
    denyfs_secure_free(header_key, KEY_SIZE_GCM);
    denyfs_secure_free(volume_key, KEY_SIZE_XTS);
    denyfs_secure_free(hmac_key, KEY_SIZE_HMAC);
    return (fmt_res == 0) ? 0 : -EIO;
}

// ---------------------------------------------------------------------------
// Public: open volume (Timing Indistinguishable + Outer-Mount Protection)
// ---------------------------------------------------------------------------

denyfs_volume_t *denyfs_vol_open(const char *path,
                                 const char *password, size_t pass_len,
                                 const char *hidden_password, size_t hidden_pass_len,
                                 int protect_hidden) {
    int fd = -1;
#ifdef O_NOATIME
    fd = open(path, O_RDWR | O_NOATIME);
    if (fd < 0 && errno == EPERM) {
        fd = open(path, O_RDWR);
    }
#else
    fd = open(path, O_RDWR);
#endif

    if (fd < 0) return NULL;
    FILE *fp = fdopen(fd, "r+b");
    if (!fp) { close(fd); return NULL; }

    // Get container size
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
    long container_size = ftell(fp);
    if (container_size < 0) { fclose(fp); return NULL; }

    // 1. Read outer header
    denyfs_header_disk_t outer_disk;
    if (fseek(fp, 0, SEEK_SET) != 0) { fclose(fp); return NULL; }
    if (fread(&outer_disk, 1, sizeof(outer_disk), fp) != sizeof(outer_disk)) {
        fclose(fp); return NULL;
    }

    // 2. Read hidden header
    denyfs_header_disk_t hidden_disk;
    uint64_t hidden_header_offset = (uint64_t)container_size - DENYFS_HIDDEN_HEADER_OFFSET_FROM_EOF;
    if (fseek(fp, (long)hidden_header_offset, SEEK_SET) != 0) { fclose(fp); return NULL; }
    if (fread(&hidden_disk, 1, sizeof(hidden_disk), fp) != sizeof(hidden_disk)) {
        fclose(fp); return NULL;
    }

    // -----------------------------------------------------------------------
    // STRICT TIMING INDISTINGUISHABILITY BOUNDARY:
    // We must perform KDF and decrypt operations on BOTH headers unconditionally.
    // -----------------------------------------------------------------------
    uint8_t *outer_master_key  = denyfs_secure_alloc(KEY_SIZE_GCM);
    uint8_t *outer_header_key  = denyfs_secure_alloc(KEY_SIZE_GCM);
    uint8_t *hidden_master_key = denyfs_secure_alloc(KEY_SIZE_GCM);
    uint8_t *hidden_header_key = denyfs_secure_alloc(KEY_SIZE_GCM);

    if (!outer_master_key || !outer_header_key || !hidden_master_key || !hidden_header_key) {
        if (outer_master_key) denyfs_secure_free(outer_master_key, KEY_SIZE_GCM);
        if (outer_header_key) denyfs_secure_free(outer_header_key, KEY_SIZE_GCM);
        if (hidden_master_key) denyfs_secure_free(hidden_master_key, KEY_SIZE_GCM);
        if (hidden_header_key) denyfs_secure_free(hidden_header_key, KEY_SIZE_GCM);
        fclose(fp); return NULL;
    }

    // Unconditional KDF 1 (Outer salt)
    int kdf_res_outer = denyfs_derive_master_key(password, pass_len, outer_disk.salt, outer_master_key);
    (void)kdf_res_outer;
    denyfs_derive_header_key(outer_master_key, outer_header_key);

    // Unconditional KDF 2 (Hidden salt)
    int kdf_res_hidden = denyfs_derive_master_key(password, pass_len, hidden_disk.salt, hidden_master_key);
    (void)kdf_res_hidden;
    denyfs_derive_header_key(hidden_master_key, hidden_header_key);

    // Unconditional Decrypt 1 (Outer payload)
    denyfs_header_payload_t outer_payload;
    memset(&outer_payload, 0, sizeof(outer_payload));
    int decrypt_res_outer = denyfs_decrypt_header(&outer_disk, outer_header_key, &outer_payload);

    // Unconditional Decrypt 2 (Hidden payload)
    denyfs_header_payload_t hidden_payload;
    memset(&hidden_payload, 0, sizeof(hidden_payload));
    int decrypt_res_hidden = denyfs_decrypt_header(&hidden_disk, hidden_header_key, &hidden_payload);

    // Securely check magic
    uint64_t expected_magic = 0x44656e7946533031ULL;
    int outer_magic_match  = (sodium_memcmp(&outer_payload.magic, &expected_magic, sizeof(uint64_t)) == 0);
    int hidden_magic_match = (sodium_memcmp(&hidden_payload.magic, &expected_magic, sizeof(uint64_t)) == 0);

    int outer_succeeded  = (decrypt_res_outer == 0 && outer_magic_match);
    int hidden_succeeded = (decrypt_res_hidden == 0 && hidden_magic_match);

    // Cleanup keys from stack/heap
    denyfs_secure_free(outer_master_key, KEY_SIZE_GCM);
    denyfs_secure_free(outer_header_key, KEY_SIZE_GCM);
    denyfs_secure_free(hidden_master_key, KEY_SIZE_GCM);
    denyfs_secure_free(hidden_header_key, KEY_SIZE_GCM);

    // Determine target volume to load
    denyfs_volume_t *vol = NULL;

    if (outer_succeeded) {
        vol = calloc(1, sizeof(*vol));
        if (vol) {
            vol->is_hidden = 0;
            vol->vol_start_offset = HEADER_SIZE;
            vol->volume_size = outer_payload.volume_size;
            vol->volume_key = denyfs_secure_alloc(KEY_SIZE_XTS);
            vol->hmac_key   = denyfs_secure_alloc(KEY_SIZE_HMAC);
            if (vol->volume_key && vol->hmac_key) {
                memcpy(vol->volume_key, outer_payload.volume_key, KEY_SIZE_XTS);
                memcpy(vol->hmac_key, outer_payload.hmac_key, KEY_SIZE_HMAC);
            } else {
                if (vol->volume_key) denyfs_secure_free(vol->volume_key, KEY_SIZE_XTS);
                if (vol->hmac_key) denyfs_secure_free(vol->hmac_key, KEY_SIZE_HMAC);
                free(vol); vol = NULL;
            }
        }
    } else if (hidden_succeeded) {
        vol = calloc(1, sizeof(*vol));
        if (vol) {
            vol->is_hidden = 1;
            vol->volume_size = hidden_payload.volume_size;
            vol->vol_start_offset = hidden_header_offset - hidden_payload.volume_size;
            vol->volume_key = denyfs_secure_alloc(KEY_SIZE_XTS);
            vol->hmac_key   = denyfs_secure_alloc(KEY_SIZE_HMAC);
            if (vol->volume_key && vol->hmac_key) {
                memcpy(vol->volume_key, hidden_payload.volume_key, KEY_SIZE_XTS);
                memcpy(vol->hmac_key, hidden_payload.hmac_key, KEY_SIZE_HMAC);
            } else {
                if (vol->volume_key) denyfs_secure_free(vol->volume_key, KEY_SIZE_XTS);
                if (vol->hmac_key) denyfs_secure_free(vol->hmac_key, KEY_SIZE_HMAC);
                free(vol); vol = NULL;
            }
        }
    }

    // Wipe payloads
    sodium_memzero(&outer_payload, sizeof(outer_payload));
    sodium_memzero(&hidden_payload, sizeof(hidden_payload));

    if (!vol) {
        fclose(fp);
        return NULL;
    }

    vol->fp = fp;

    // 3. Handle outer-mount protection if requested (protect_hidden == 1)
    if (protect_hidden && !vol->is_hidden && hidden_password != NULL) {
        // Run KDF for hidden master/header keys again using the provided hidden password
        uint8_t *prot_master = denyfs_secure_alloc(KEY_SIZE_GCM);
        uint8_t *prot_header = denyfs_secure_alloc(KEY_SIZE_GCM);
        
        if (prot_master && prot_header &&
            denyfs_derive_master_key(hidden_password, hidden_pass_len, hidden_disk.salt, prot_master) == 0 &&
            denyfs_derive_header_key(prot_master, prot_header) == 0) {
            
            denyfs_header_payload_t prot_payload;
            memset(&prot_payload, 0, sizeof(prot_payload));
            
            if (denyfs_decrypt_header(&hidden_disk, prot_header, &prot_payload) == 0 &&
                sodium_memcmp(&prot_payload.magic, &expected_magic, sizeof(uint64_t)) == 0) {
                
                vol->protect_hidden = 1;
                // Calculate protected block boundaries in absolute block scale
                uint64_t hidden_volume_start_byte = hidden_header_offset - prot_payload.volume_size;
                vol->protect_start_sector = hidden_volume_start_byte / SECTOR_SIZE;
                vol->protect_end_sector = (uint64_t)container_size / SECTOR_SIZE - 1;
            }
            sodium_memzero(&prot_payload, sizeof(prot_payload));
        }
        if (prot_master) denyfs_secure_free(prot_master, KEY_SIZE_GCM);
        if (prot_header) denyfs_secure_free(prot_header, KEY_SIZE_GCM);
    }

    // Load volume superblock (block 0)
    uint8_t sb_buf[SECTOR_SIZE];
    if (read_block(vol, 0, sb_buf) != 0) {
        denyfs_vol_close(vol);
        return NULL;
    }
    memcpy(&vol->sb, sb_buf, sizeof(vol->sb));

    if (vol->sb.magic != DENYFS_SB_MAGIC) {
        denyfs_vol_close(vol);
        return NULL;
    }

    // Read bitmap
    vol->bitmap_bytes = (size_t)vol->sb.bitmap_blocks * SECTOR_SIZE;
    vol->bitmap = calloc(1, vol->bitmap_bytes);
    if (!vol->bitmap) {
        denyfs_vol_close(vol);
        return NULL;
    }

    for (uint32_t i = 0; i < vol->sb.bitmap_blocks; i++) {
        if (read_block(vol, vol->sb.bitmap_start + i, vol->bitmap + i * SECTOR_SIZE) != 0) {
            denyfs_vol_close(vol);
            return NULL;
        }
    }

    // Verify bitmap HMAC
    uint8_t computed[DENYFS_HMAC_SIZE];
    denyfs_compute_hmac(vol->hmac_key, KEY_SIZE_HMAC, vol->bitmap, vol->bitmap_bytes, computed);
    if (sodium_memcmp(computed, vol->sb.bitmap_hmac, DENYFS_HMAC_SIZE) != 0) {
        denyfs_vol_close(vol);
        return NULL;
    }

    // Read inode table
    for (uint32_t i = 0; i < vol->sb.inode_blocks; i++) {
        if (read_block(vol, vol->sb.inode_start + i, ((uint8_t *)vol->inodes) + i * SECTOR_SIZE) != 0) {
            denyfs_vol_close(vol);
            return NULL;
        }
    }

    return vol;
}

// ---------------------------------------------------------------------------
// Public: flush
// ---------------------------------------------------------------------------

int denyfs_vol_flush(denyfs_volume_t *vol) {
    if (!vol || !vol->fp) return -1;

    // Recompute bitmap HMAC
    denyfs_compute_hmac(vol->hmac_key, KEY_SIZE_HMAC,
                        vol->bitmap, vol->bitmap_bytes, vol->sb.bitmap_hmac);

    // Write superblock
    if (write_block(vol, 0, (const uint8_t *)&vol->sb) != 0)
        return -1;

    // Write bitmap
    for (uint32_t i = 0; i < vol->sb.bitmap_blocks; i++) {
        if (write_block(vol, vol->sb.bitmap_start + i, vol->bitmap + i * SECTOR_SIZE) != 0)
            return -1;
    }

    // Write inode table
    for (uint32_t i = 0; i < vol->sb.inode_blocks; i++) {
        if (write_block(vol, vol->sb.inode_start + i, ((const uint8_t *)vol->inodes) + i * SECTOR_SIZE) != 0)
            return -1;
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Public: close
// ---------------------------------------------------------------------------

void denyfs_vol_close(denyfs_volume_t *vol) {
    if (!vol) return;

    if (vol->fp) {
        denyfs_vol_flush(vol);
        fclose(vol->fp);
        vol->fp = NULL;
    }

    if (vol->volume_key) denyfs_secure_free(vol->volume_key, KEY_SIZE_XTS);
    if (vol->hmac_key)   denyfs_secure_free(vol->hmac_key, KEY_SIZE_HMAC);
    if (vol->bitmap)     { sodium_memzero(vol->bitmap, vol->bitmap_bytes); free(vol->bitmap); }

    sodium_memzero(vol->inodes, sizeof(vol->inodes));
    sodium_memzero(&vol->sb, sizeof(vol->sb));
    free(vol);
}

// ---------------------------------------------------------------------------
// Public: lookup
// ---------------------------------------------------------------------------

int denyfs_vol_lookup(denyfs_volume_t *vol, const char *name, uint32_t *out_ino) {
    denyfs_inode_t *root = &vol->inodes[0];
    size_t name_len = strlen(name);

    for (uint32_t bi = 0; bi < DENYFS_DIRECT_BLOCKS; bi++) {
        if (root->direct[bi] == DENYFS_INVALID_BLOCK) continue;

        uint8_t block_data[SECTOR_SIZE];
        if (read_block(vol, root->direct[bi], block_data) != 0)
            return -EIO;

        denyfs_dirent_t *entries = (denyfs_dirent_t *)block_data;
        for (int i = 0; i < DENYFS_DIRENTS_PER_BLOCK; i++) {
            if (entries[i].inode != DENYFS_INVALID_INO &&
                entries[i].name_len == (uint8_t)name_len &&
                memcmp(entries[i].name, name, name_len) == 0) {
                if (out_ino) *out_ino = entries[i].inode;
                return 0;
            }
        }
    }
    return -ENOENT;
}

// ---------------------------------------------------------------------------
// Public: create
// ---------------------------------------------------------------------------

int denyfs_vol_create(denyfs_volume_t *vol, const char *name, uint32_t *out_ino) {
    // Check for duplicate
    uint32_t dummy;
    if (denyfs_vol_lookup(vol, name, &dummy) == 0) return -EEXIST;

    // Allocate inode
    int ino = alloc_inode(vol);
    if (ino < 0) return -ENOSPC;

    // Initialize inode
    denyfs_inode_t *inode = &vol->inodes[ino];
    inode->type = DENYFS_ITYPE_FILE;
    inode->size = 0;
    inode->block_count = 0;
    memset(inode->direct, 0xFF, sizeof(inode->direct));
    inode->mtime = (uint64_t)time(NULL);

    // Add directory entry
    int res = add_dirent(vol, name, (uint32_t)ino);
    if (res != 0) {
        // Roll back inode allocation
        inode->type = DENYFS_ITYPE_FREE;
        vol->sb.free_inodes++;
        return res;
    }

    if (out_ino) *out_ino = (uint32_t)ino;

    denyfs_vol_flush(vol);
    return 0;
}

// ---------------------------------------------------------------------------
// Public: unlink
// ---------------------------------------------------------------------------

int denyfs_vol_unlink(denyfs_volume_t *vol, const char *name) {
    uint32_t ino;
    if (denyfs_vol_lookup(vol, name, &ino) != 0) return -ENOENT;

    // Remove directory entry
    int res = remove_dirent(vol, name);
    if (res != 0) return res;

    // Free inode and its blocks
    free_inode(vol, ino);

    denyfs_vol_flush(vol);
    return 0;
}

// ---------------------------------------------------------------------------
// Public: read
// ---------------------------------------------------------------------------

int denyfs_vol_read(denyfs_volume_t *vol, uint32_t ino,
                    void *buf, size_t size, uint64_t offset) {
    if (ino >= DENYFS_MAX_INODES) return -EINVAL;
    denyfs_inode_t *inode = &vol->inodes[ino];
    if (inode->type != DENYFS_ITYPE_FILE) return -EISDIR;

    // Clamp read to file bounds
    if (offset >= inode->size) return 0;
    if (offset + size > inode->size) size = inode->size - (size_t)offset;
    if (size == 0) return 0;

    uint8_t *dst = (uint8_t *)buf;
    size_t bytes_read = 0;
    uint64_t pos = offset;

    while (bytes_read < size) {
        uint32_t blk_idx = (uint32_t)(pos / SECTOR_SIZE);
        uint32_t blk_off = (uint32_t)(pos % SECTOR_SIZE);
        size_t chunk = SECTOR_SIZE - blk_off;
        if (chunk > size - bytes_read) chunk = size - bytes_read;

        if (blk_idx >= DENYFS_DIRECT_BLOCKS) break;

        if (inode->direct[blk_idx] == DENYFS_INVALID_BLOCK) {
            memset(dst + bytes_read, 0, chunk);
        } else {
            uint8_t block_data[SECTOR_SIZE];
            if (read_block(vol, inode->direct[blk_idx], block_data) != 0)
                return -EIO;
            memcpy(dst + bytes_read, block_data + blk_off, chunk);
        }

        bytes_read += chunk;
        pos += chunk;
    }
    return (int)bytes_read;
}

// ---------------------------------------------------------------------------
// Public: write
// ---------------------------------------------------------------------------

int denyfs_vol_write(denyfs_volume_t *vol, uint32_t ino,
                     const void *buf, size_t size, uint64_t offset) {
    if (ino >= DENYFS_MAX_INODES) return -EINVAL;
    denyfs_inode_t *inode = &vol->inodes[ino];
    if (inode->type != DENYFS_ITYPE_FILE) return -EISDIR;

    size_t max_size = (size_t)DENYFS_DIRECT_BLOCKS * SECTOR_SIZE;
    if (offset + size > max_size) return -ENOSPC;

    const uint8_t *src = (const uint8_t *)buf;
    size_t bytes_written = 0;
    uint64_t pos = offset;

    while (bytes_written < size) {
        uint32_t blk_idx = (uint32_t)(pos / SECTOR_SIZE);
        uint32_t blk_off = (uint32_t)(pos % SECTOR_SIZE);
        size_t chunk = SECTOR_SIZE - blk_off;
        if (chunk > size - bytes_written) chunk = size - bytes_written;

        if (blk_idx >= DENYFS_DIRECT_BLOCKS) return -ENOSPC;

        // Ensure block is allocated
        if (inode->direct[blk_idx] == DENYFS_INVALID_BLOCK) {
            int blk = alloc_block(vol);
            if (blk < 0) return -ENOSPC;
            inode->direct[blk_idx] = (uint32_t)blk;
            inode->block_count++;

            // Zero-fill the new block
            uint8_t zeros[SECTOR_SIZE];
            memset(zeros, 0, sizeof(zeros));
            if (write_block(vol, (uint32_t)blk, zeros) != 0)
                return -EIO;
        }

        // Read-modify-write
        uint8_t block_data[SECTOR_SIZE];
        if (read_block(vol, inode->direct[blk_idx], block_data) != 0)
            return -EIO;

        memcpy(block_data + blk_off, src + bytes_written, chunk);

        int write_res = write_block(vol, inode->direct[blk_idx], block_data);
        if (write_res != 0)
            return write_res;

        bytes_written += chunk;
        pos += chunk;
    }

    // Update size if extended
    if (offset + size > inode->size)
        inode->size = (uint32_t)(offset + size);
    inode->mtime = (uint64_t)time(NULL);

    denyfs_vol_flush(vol);
    return (int)bytes_written;
}

// ---------------------------------------------------------------------------
// Public: truncate
// ---------------------------------------------------------------------------

int denyfs_vol_truncate(denyfs_volume_t *vol, uint32_t ino, uint32_t new_size) {
    if (ino >= DENYFS_MAX_INODES) return -EINVAL;
    denyfs_inode_t *inode = &vol->inodes[ino];
    if (inode->type != DENYFS_ITYPE_FILE) return -EISDIR;

    uint32_t max_size = DENYFS_DIRECT_BLOCKS * SECTOR_SIZE;
    if (new_size > max_size) return -ENOSPC;

    uint32_t old_blocks = (inode->size + SECTOR_SIZE - 1) / SECTOR_SIZE;
    uint32_t new_blocks = (new_size + SECTOR_SIZE - 1) / SECTOR_SIZE;

    if (new_size > inode->size) {
        // Extending — allocate new blocks
        for (uint32_t i = old_blocks; i < new_blocks; i++) {
            if (inode->direct[i] == DENYFS_INVALID_BLOCK) {
                int blk = alloc_block(vol);
                if (blk < 0) return -ENOSPC;
                inode->direct[i] = (uint32_t)blk;
                inode->block_count++;

                uint8_t zeros[SECTOR_SIZE];
                memset(zeros, 0, sizeof(zeros));
                if (write_block(vol, (uint32_t)blk, zeros) != 0)
                    return -EIO;
            }
        }
    } else if (new_size < inode->size) {
        // Shrinking — free excess blocks
        for (uint32_t i = new_blocks; i < old_blocks; i++) {
            if (inode->direct[i] != DENYFS_INVALID_BLOCK) {
                free_block(vol, inode->direct[i]);
                inode->direct[i] = DENYFS_INVALID_BLOCK;
                inode->block_count--;
            }
        }
    }

    inode->size = new_size;
    inode->mtime = (uint64_t)time(NULL);

    denyfs_vol_flush(vol);
    return 0;
}

// ---------------------------------------------------------------------------
// Public: readdir
// ---------------------------------------------------------------------------

int denyfs_vol_readdir(denyfs_volume_t *vol, denyfs_readdir_cb cb, void *userdata) {
    denyfs_inode_t *root = &vol->inodes[0];

    for (uint32_t bi = 0; bi < DENYFS_DIRECT_BLOCKS; bi++) {
        if (root->direct[bi] == DENYFS_INVALID_BLOCK) continue;

        uint8_t block_data[SECTOR_SIZE];
        if (read_block(vol, root->direct[bi], block_data) != 0)
            return -EIO;

        denyfs_dirent_t *entries = (denyfs_dirent_t *)block_data;
        for (int i = 0; i < DENYFS_DIRENTS_PER_BLOCK; i++) {
            if (entries[i].inode != DENYFS_INVALID_INO) {
                if (cb(entries[i].name, entries[i].inode, userdata) != 0)
                    return 0;  // callback requested stop
            }
        }
    }
    return 0;
}
