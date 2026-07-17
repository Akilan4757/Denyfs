#ifndef DENYFS_FS_H
#define DENYFS_FS_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "crypto.h"

// Filesystem constants
#define DENYFS_MAX_INODES       64
#define DENYFS_MAX_NAME_LEN     251   // field size; max filename = 250 chars + null
#define DENYFS_INODE_SIZE       128
#define DENYFS_DIRENT_SIZE      256
#define DENYFS_DIRECT_BLOCKS    24    // max file size = 24 * 4096 = 98304 bytes
#define DENYFS_DIRENTS_PER_BLOCK (SECTOR_SIZE / DENYFS_DIRENT_SIZE)  // 16
#define DENYFS_SB_MAGIC         0x44656e7946533032ULL  // 'DenyFS02'
#define DENYFS_HMAC_SIZE        32
#define DENYFS_INVALID_INO      0xFFFFFFFFU
#define DENYFS_INVALID_BLOCK    0xFFFFFFFFU

// Inode types
#define DENYFS_ITYPE_FREE       0
#define DENYFS_ITYPE_FILE       1
#define DENYFS_ITYPE_DIR        2

// ---------------------------------------------------------------------------
// On-disk structures (all packed, no compiler padding)
// ---------------------------------------------------------------------------

#pragma pack(push, 1)

// Superblock — occupies volume block 0
typedef struct {
    uint64_t magic;                       // DENYFS_SB_MAGIC
    uint32_t block_size;                  // SECTOR_SIZE (4096)
    uint32_t total_blocks;                // total blocks in the volume
    uint32_t inode_count;                 // DENYFS_MAX_INODES
    uint32_t bitmap_start;                // block index where bitmap starts
    uint32_t bitmap_blocks;               // number of blocks the bitmap occupies
    uint32_t inode_start;                 // block index where inode table starts
    uint32_t inode_blocks;                // number of blocks the inode table occupies
    uint32_t data_start;                  // block index of first data block
    uint32_t free_blocks;                 // count of unallocated data blocks
    uint32_t free_inodes;                 // count of free inodes
    uint8_t  bitmap_hmac[DENYFS_HMAC_SIZE]; // HMAC-SHA256 of the plaintext bitmap
    uint8_t  reserved[SECTOR_SIZE - 80];  // pad to exactly SECTOR_SIZE
} denyfs_superblock_t;

// Inode — 128 bytes each, DENYFS_MAX_INODES per volume
typedef struct {
    uint32_t type;                        // DENYFS_ITYPE_*
    uint32_t size;                        // file size in bytes
    uint32_t block_count;                 // allocated blocks
    uint32_t direct[DENYFS_DIRECT_BLOCKS]; // absolute block numbers (DENYFS_INVALID_BLOCK = unalloc)
    uint64_t mtime;                       // modification time (unix epoch)
    uint8_t  reserved[DENYFS_INODE_SIZE - 12 - DENYFS_DIRECT_BLOCKS * 4 - 8];
} denyfs_inode_t;

// Directory entry — 256 bytes each, 16 per block
typedef struct {
    uint32_t inode;                       // inode number (DENYFS_INVALID_INO = free)
    uint8_t  name_len;                    // length of name excluding null
    char     name[DENYFS_MAX_NAME_LEN];   // null-terminated filename
} denyfs_dirent_t;

#pragma pack(pop)

// Compile-time layout checks
_Static_assert(sizeof(denyfs_superblock_t) == SECTOR_SIZE,
               "Superblock must be exactly SECTOR_SIZE bytes");
_Static_assert(sizeof(denyfs_inode_t) == DENYFS_INODE_SIZE,
               "Inode must be exactly DENYFS_INODE_SIZE bytes");
_Static_assert(sizeof(denyfs_dirent_t) == DENYFS_DIRENT_SIZE,
               "Dirent must be exactly DENYFS_DIRENT_SIZE bytes");

#define DENYFS_HIDDEN_HEADER_OFFSET_FROM_EOF 32768

// ---------------------------------------------------------------------------
// In-memory volume state
// ---------------------------------------------------------------------------

typedef struct {
    FILE       *fp;                                // container file (open r+b)
    uint8_t    *volume_key;                        // sodium_malloc'd XTS key
    uint8_t    *hmac_key;                           // sodium_malloc'd HMAC key
    uint64_t    volume_size;                       // outer or hidden volume size in bytes
    denyfs_superblock_t sb;                        // in-memory superblock
    uint8_t    *bitmap;                            // in-memory allocation bitmap
    size_t      bitmap_bytes;                      // total bitmap buffer size
    denyfs_inode_t inodes[DENYFS_MAX_INODES];      // in-memory inode table
    uint64_t    vol_start_offset;                  // absolute byte offset to volume data region
    int         is_hidden;                         // 1 if this is a hidden volume mount
    int         protect_hidden;                    // 1 if outer-mount protection is active
    uint64_t    protect_start_sector;              // start sector of protected hidden volume
    uint64_t    protect_end_sector;                // end sector of protected hidden volume
} denyfs_volume_t;

// Readdir callback type
typedef int (*denyfs_readdir_cb)(const char *name, uint32_t ino, void *userdata);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// Create a new container file: CSPRNG fill, header, and formatted filesystem.
int denyfs_container_create(const char *path, uint64_t size_mb,
                            const char *password, size_t pass_len);

// Create a hidden volume in an existing container file.
int denyfs_container_create_hidden(const char *path,
                                   const char *outer_password, size_t outer_pass_len,
                                   const char *hidden_password, size_t hidden_pass_len,
                                   uint64_t hidden_size_mb);

// Open an existing container. Returns NULL on auth failure or corrupt metadata.
// Supports timing indistinguishability and outer-mount protection.
denyfs_volume_t *denyfs_vol_open(const char *path,
                                 const char *password, size_t pass_len,
                                 const char *hidden_password, size_t hidden_pass_len,
                                 int protect_hidden);

// Flush all in-memory metadata to disk (superblock, bitmap+HMAC, inode table).
int denyfs_vol_flush(denyfs_volume_t *vol);

// Flush and close volume, wipe keys, free struct.
void denyfs_vol_close(denyfs_volume_t *vol);

// Look up a filename in the root directory. Returns 0 on hit.
int denyfs_vol_lookup(denyfs_volume_t *vol, const char *name, uint32_t *out_ino);

// Create a new file in root directory. Returns 0 on success.
int denyfs_vol_create(denyfs_volume_t *vol, const char *name, uint32_t *out_ino);

// Unlink (delete) a file from root directory. Returns 0 on success.
int denyfs_vol_unlink(denyfs_volume_t *vol, const char *name);

// Read file data. Returns bytes read, or negative errno on error.
int denyfs_vol_read(denyfs_volume_t *vol, uint32_t ino,
                    void *buf, size_t size, uint64_t offset);

// Write file data. Returns bytes written, or negative errno on error.
int denyfs_vol_write(denyfs_volume_t *vol, uint32_t ino,
                     const void *buf, size_t size, uint64_t offset);

// Truncate (or extend) a file. Returns 0 on success.
int denyfs_vol_truncate(denyfs_volume_t *vol, uint32_t ino, uint32_t new_size);

// Iterate root directory entries, calling cb for each.
int denyfs_vol_readdir(denyfs_volume_t *vol, denyfs_readdir_cb cb, void *userdata);

#endif // DENYFS_FS_H
