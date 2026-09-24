#include "fs.h"
#include "crypto.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <sodium.h>

// ---------------------------------------------------------------------------
// Block-level I/O helpers (encrypt/decrypt + seek + read/write)
// ---------------------------------------------------------------------------

static int read_block(denyfs_volume_t *vol, uint32_t block_num, uint8_t *out) {
    if (!vol || !vol->fp || !out ||
        block_num >= vol->volume_size / SECTOR_SIZE) return -1;
    uint8_t cipher[SECTOR_SIZE];
    uint64_t offset_u64 = vol->vol_start_offset + (uint64_t)block_num * SECTOR_SIZE;
    if (offset_u64 > LONG_MAX) return -1;
    long offset = (long)offset_u64;
    if (fseek(vol->fp, offset, SEEK_SET) != 0) return -1;
    if (fread(cipher, 1, SECTOR_SIZE, vol->fp) != SECTOR_SIZE) return -1;
    return denyfs_crypt_sector(cipher, out, (uint64_t)block_num, vol->volume_key, 0);
}

static int write_block(denyfs_volume_t *vol, uint32_t block_num, const uint8_t *data) {
    if (!vol || !vol->fp || !data ||
        block_num >= vol->volume_size / SECTOR_SIZE) return -1;
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
    uint64_t offset_u64 = vol->vol_start_offset + (uint64_t)block_num * SECTOR_SIZE;
    if (offset_u64 > LONG_MAX) return -1;
    long offset = (long)offset_u64;
    if (fseek(vol->fp, offset, SEEK_SET) != 0) return -1;
    if (fwrite(cipher, 1, SECTOR_SIZE, vol->fp) != SECTOR_SIZE) return -1;
    return 0;
}

// Low-level helper for formatting (where no denyfs_volume_t exists yet)
static int write_block_raw(FILE *fp, const uint8_t *volume_key, uint64_t start_offset,
                           uint32_t block_num, const uint8_t *data) {
    uint8_t cipher[SECTOR_SIZE];
    if (denyfs_crypt_sector(data, cipher, (uint64_t)block_num, volume_key, 1) != 0)
        return -1;
    uint64_t offset_u64 = start_offset + (uint64_t)block_num * SECTOR_SIZE;
    if (offset_u64 > LONG_MAX) return -1;
    long offset = (long)offset_u64;
    if (fseek(fp, offset, SEEK_SET) != 0) return -1;
    if (fwrite(cipher, 1, SECTOR_SIZE, fp) != SECTOR_SIZE) return -1;
    if (fflush(fp) != 0) return -1;
    return 0;
}

static int valid_volume_range(uint64_t start, uint64_t size, uint64_t container_size) {
    return size != 0 && size % SECTOR_SIZE == 0 && start % SECTOR_SIZE == 0 && start <= container_size &&
           size <= container_size - start && start <= LONG_MAX &&
           size <= (uint64_t)LONG_MAX - start;
}

static int valid_dirent(const denyfs_dirent_t *entry) {
    if (!entry) return 0;
    if (entry->inode == DENYFS_INVALID_INO) return entry->name_len == 0;
    if (entry->inode == 0 || entry->inode >= DENYFS_MAX_INODES ||
        entry->name_len == 0 || entry->name_len >= DENYFS_MAX_NAME_LEN ||
        entry->name[entry->name_len] != '\0') return 0;
    for (uint32_t i = 0; i < entry->name_len; i++)
        if (entry->name[i] == '\0' || entry->name[i] == '/') return 0;
    return !((entry->name_len == 1 && entry->name[0] == '.') ||
             (entry->name_len == 2 && entry->name[0] == '.' && entry->name[1] == '.'));
}

static int validate_superblock(const denyfs_superblock_t *sb, uint64_t volume_size) {
    if (!sb || volume_size == 0 || volume_size % SECTOR_SIZE != 0) return -1;

    uint64_t expected_blocks = volume_size / SECTOR_SIZE;
    if (expected_blocks > UINT32_MAX || expected_blocks < 4 ||
        sb->magic != DENYFS_SB_MAGIC || sb->block_size != SECTOR_SIZE ||
        sb->total_blocks != expected_blocks || sb->inode_count != DENYFS_MAX_INODES ||
        sb->bitmap_start != 1 || sb->inode_blocks !=
            (DENYFS_MAX_INODES * DENYFS_INODE_SIZE + SECTOR_SIZE - 1) / SECTOR_SIZE)
        return -1;

    uint64_t bitmap_bytes = (expected_blocks + 7) / 8;
    uint64_t expected_bitmap_blocks = (bitmap_bytes + SECTOR_SIZE - 1) / SECTOR_SIZE;
    uint64_t expected_inode_start = 1 + expected_bitmap_blocks;
    uint64_t expected_data_start = expected_inode_start + sb->inode_blocks;
    if (expected_bitmap_blocks > UINT32_MAX ||
        sb->bitmap_blocks != expected_bitmap_blocks ||
        sb->inode_start != expected_inode_start ||
        sb->data_start != expected_data_start ||
        sb->data_start >= sb->total_blocks ||
        sb->free_blocks > sb->total_blocks - sb->data_start ||
        sb->free_inodes >= DENYFS_MAX_INODES)
        return -1;
    return 0;
}

static int claim_metadata_block(denyfs_volume_t *vol, uint8_t *claimed,
                                uint32_t block, uint32_t *claimed_count) {
    if (!vol || !vol->bitmap || !claimed || block < vol->sb.data_start ||
        block >= vol->sb.total_blocks || block / 8 >= vol->bitmap_bytes ||
        !(vol->bitmap[block / 8] & (1U << (block % 8))) ||
        (claimed[block / 8] & (1U << (block % 8))))
        return -1;
    claimed[block / 8] |= (uint8_t)(1U << (block % 8));
    (*claimed_count)++;
    return 0;
}

static int read_pointer_table(denyfs_volume_t *vol, uint32_t table_block,
                              uint32_t entries[DENYFS_POINTERS_PER_BLOCK]) {
    if (!vol || !vol->bitmap || table_block < vol->sb.data_start ||
        table_block >= vol->sb.total_blocks ||
        !(vol->bitmap[table_block / 8] & (1U << (table_block % 8))))
        return -1;
    return read_block(vol, table_block, (uint8_t *)entries);
}

static int validate_loaded_metadata(denyfs_volume_t *vol) {
    if (!vol || !vol->bitmap || vol->bitmap_bytes == 0) return -1;
    denyfs_inode_t *root = &vol->inodes[0];
    if (root->type != DENYFS_ITYPE_DIR || root->size != 0 ||
        root->block_count == 0 || root->block_count > DENYFS_DIRECT_BLOCKS ||
        root->indirect_block != DENYFS_INVALID_BLOCK ||
        root->double_indirect_block != DENYFS_INVALID_BLOCK)
        return -1;

    uint8_t *claimed = calloc(1, vol->bitmap_bytes);
    if (!claimed) return -1;
    uint32_t claimed_count = 0;
    uint32_t allocated_inodes = 0;
    for (uint32_t ino = 0; ino < DENYFS_MAX_INODES; ino++) {
        const denyfs_inode_t *inode = &vol->inodes[ino];
        if (inode->type == DENYFS_ITYPE_FREE) {
            if (ino == 0 || inode->size != 0 || inode->block_count != 0) goto invalid;
            for (uint32_t i = 0; i < DENYFS_DIRECT_BLOCKS; i++)
                if (inode->direct[i] != DENYFS_INVALID_BLOCK) goto invalid;
            if (inode->indirect_block != DENYFS_INVALID_BLOCK ||
                inode->double_indirect_block != DENYFS_INVALID_BLOCK) goto invalid;
            continue;
        }
        if (inode->type != (ino == 0 ? DENYFS_ITYPE_DIR : DENYFS_ITYPE_FILE) ||
            inode->size > DENYFS_MAX_FILE_SIZE ||
            inode->block_count > DENYFS_MAX_FILE_BLOCKS) goto invalid;
        allocated_inodes++;

        uint64_t file_blocks = (inode->size + SECTOR_SIZE - 1) / SECTOR_SIZE;
        uint32_t actual_file_blocks = 0;
        for (uint32_t i = 0; i < DENYFS_DIRECT_BLOCKS; i++) {
            uint32_t block = inode->direct[i];
            if (ino == 0) {
                if ((i < root->block_count) != (block != DENYFS_INVALID_BLOCK)) goto invalid;
            } else if (block != DENYFS_INVALID_BLOCK && i >= file_blocks) {
                goto invalid;
            }
            if (block != DENYFS_INVALID_BLOCK) {
                if (claim_metadata_block(vol, claimed, block, &claimed_count) != 0)
                    goto invalid;
                if (ino != 0) actual_file_blocks++;
            }
        }

        if (ino == 0) {
            if (inode->block_count != root->block_count) goto invalid;
            continue;
        }

        if (inode->indirect_block != DENYFS_INVALID_BLOCK) {
            uint32_t pointers[DENYFS_POINTERS_PER_BLOCK];
            if (claim_metadata_block(vol, claimed, inode->indirect_block,
                                     &claimed_count) != 0 ||
                read_pointer_table(vol, inode->indirect_block, pointers) != 0)
                goto invalid;
            uint32_t entries = 0;
            for (uint32_t i = 0; i < DENYFS_POINTERS_PER_BLOCK; i++) {
                uint32_t block = pointers[i];
                if (block == DENYFS_INVALID_BLOCK) continue;
                uint64_t logical = (uint64_t)DENYFS_DIRECT_BLOCKS + i;
                if (logical >= file_blocks ||
                    claim_metadata_block(vol, claimed, block, &claimed_count) != 0)
                    goto invalid;
                entries++;
                actual_file_blocks++;
            }
            if (entries == 0) goto invalid;
        }

        if (inode->double_indirect_block != DENYFS_INVALID_BLOCK) {
            uint32_t roots[DENYFS_POINTERS_PER_BLOCK];
            if (claim_metadata_block(vol, claimed, inode->double_indirect_block,
                                     &claimed_count) != 0 ||
                read_pointer_table(vol, inode->double_indirect_block, roots) != 0)
                goto invalid;
            uint32_t root_entries = 0;
            for (uint32_t outer = 0; outer < DENYFS_POINTERS_PER_BLOCK; outer++) {
                uint32_t child_block = roots[outer];
                if (child_block == DENYFS_INVALID_BLOCK) continue;
                uint64_t logical_start = (uint64_t)DENYFS_DIRECT_BLOCKS +
                    DENYFS_POINTERS_PER_BLOCK +
                    (uint64_t)outer * DENYFS_POINTERS_PER_BLOCK;
                if (logical_start >= file_blocks ||
                    claim_metadata_block(vol, claimed, child_block, &claimed_count) != 0)
                    goto invalid;
                uint32_t pointers[DENYFS_POINTERS_PER_BLOCK];
                if (read_pointer_table(vol, child_block, pointers) != 0) goto invalid;
                uint32_t child_entries = 0;
                for (uint32_t inner = 0; inner < DENYFS_POINTERS_PER_BLOCK; inner++) {
                    uint32_t block = pointers[inner];
                    if (block == DENYFS_INVALID_BLOCK) continue;
                    if (logical_start + inner >= file_blocks ||
                        claim_metadata_block(vol, claimed, block, &claimed_count) != 0)
                        goto invalid;
                    child_entries++;
                    actual_file_blocks++;
                }
                if (child_entries == 0) goto invalid;
                root_entries++;
            }
            if (root_entries == 0) goto invalid;
        }

        if (actual_file_blocks != inode->block_count) goto invalid;
    }

    if (allocated_inodes == 0 || vol->sb.free_inodes != DENYFS_MAX_INODES - allocated_inodes)
        goto invalid;

    for (uint32_t block = 0; block < vol->sb.data_start; block++)
        if (!(vol->bitmap[block / 8] & (1U << (block % 8)))) goto invalid;

    uint32_t allocated_data_blocks = 0;
    for (uint32_t block = vol->sb.data_start; block < vol->sb.total_blocks; block++)
        if (vol->bitmap[block / 8] & (1U << (block % 8))) allocated_data_blocks++;
    if (allocated_data_blocks != claimed_count ||
        vol->sb.free_blocks != vol->sb.total_blocks - vol->sb.data_start - allocated_data_blocks)
        goto invalid;

    uint8_t referenced[DENYFS_MAX_INODES] = {0};
    char names[DENYFS_MAX_INODES - 1][DENYFS_MAX_NAME_LEN];
    uint8_t name_lengths[DENYFS_MAX_INODES - 1];
    size_t name_count = 0;
    for (uint32_t bi = 0; bi < root->block_count; bi++) {
        uint8_t block_data[SECTOR_SIZE];
        if (read_block(vol, root->direct[bi], block_data) != 0) goto invalid;
        const denyfs_dirent_t *entries = (const denyfs_dirent_t *)block_data;
        for (uint32_t ei = 0; ei < DENYFS_DIRENTS_PER_BLOCK; ei++) {
            const denyfs_dirent_t *entry = &entries[ei];
            if (entry->inode == DENYFS_INVALID_INO) {
                if (!valid_dirent(entry)) goto invalid;
                continue;
            }
            if (!valid_dirent(entry) ||
                vol->inodes[entry->inode].type != DENYFS_ITYPE_FILE ||
                referenced[entry->inode] || name_count >= DENYFS_MAX_INODES - 1)
                goto invalid;
            for (size_t previous = 0; previous < name_count; previous++)
                if (name_lengths[previous] == entry->name_len &&
                    memcmp(names[previous], entry->name, entry->name_len) == 0) goto invalid;
            memcpy(names[name_count], entry->name, entry->name_len + 1);
            name_lengths[name_count++] = entry->name_len;
            referenced[entry->inode] = 1;
        }
    }
    for (uint32_t ino = 1; ino < DENYFS_MAX_INODES; ino++)
        if ((vol->inodes[ino].type == DENYFS_ITYPE_FILE) != (referenced[ino] != 0))
            goto invalid;
    free(claimed);
    return 0;

invalid:
    free(claimed);
    return -1;
}

// ---------------------------------------------------------------------------
// Bitmap helpers
// ---------------------------------------------------------------------------

static int alloc_block(denyfs_volume_t *vol) {
    for (uint32_t i = vol->sb.data_start; i < vol->sb.total_blocks; i++) {
        if (!(vol->bitmap[i / 8] & (1 << (i % 8)))) {
            vol->bitmap[i / 8] |= (uint8_t)(1 << (i % 8));
            vol->sb.free_blocks--;
            size_t bitmap_sector = (i / 8) / SECTOR_SIZE;
            if (bitmap_sector < vol->bitmap_dirty_count)
                vol->bitmap_dirty[bitmap_sector] = 1;
            return (int)i;
        }
    }
    return -1;
}

static void free_block(denyfs_volume_t *vol, uint32_t block_num) {
    if (block_num >= vol->sb.data_start && block_num < vol->sb.total_blocks) {
        uint8_t mask = (uint8_t)(1U << (block_num % 8));
        if (vol->bitmap[block_num / 8] & mask) {
            vol->bitmap[block_num / 8] &= (uint8_t)~mask;
            vol->sb.free_blocks++;
            size_t bitmap_sector = (block_num / 8) / SECTOR_SIZE;
            if (bitmap_sector < vol->bitmap_dirty_count)
                vol->bitmap_dirty[bitmap_sector] = 1;
        }
    }
}

static int allocate_pointer_table(denyfs_volume_t *vol, uint32_t *out_block) {
    int block = alloc_block(vol);
    if (block < 0) return -ENOSPC;
    uint32_t empty[DENYFS_POINTERS_PER_BLOCK];
    memset(empty, 0xFF, sizeof(empty));
    if (write_block(vol, (uint32_t)block, (const uint8_t *)empty) != 0) {
        free_block(vol, (uint32_t)block);
        return -EIO;
    }
    *out_block = (uint32_t)block;
    return 0;
}

static int allocate_zeroed_data_block(denyfs_volume_t *vol, uint32_t *out_block) {
    int block = alloc_block(vol);
    if (block < 0) return -ENOSPC;
    uint8_t zeros[SECTOR_SIZE] = {0};
    if (write_block(vol, (uint32_t)block, zeros) != 0) {
        free_block(vol, (uint32_t)block);
        return -EIO;
    }
    *out_block = (uint32_t)block;
    return 0;
}

static int get_file_data_block(denyfs_volume_t *vol, const denyfs_inode_t *inode,
                               uint64_t logical_block, uint32_t *out_block) {
    if (!vol || !inode || !out_block || logical_block >= DENYFS_MAX_FILE_BLOCKS)
        return -EINVAL;
    *out_block = DENYFS_INVALID_BLOCK;
    if (logical_block < DENYFS_DIRECT_BLOCKS) {
        *out_block = inode->direct[logical_block];
    } else {
        logical_block -= DENYFS_DIRECT_BLOCKS;
        uint32_t pointers[DENYFS_POINTERS_PER_BLOCK];
        if (logical_block < DENYFS_POINTERS_PER_BLOCK) {
            if (inode->indirect_block == DENYFS_INVALID_BLOCK) return 0;
            if (read_pointer_table(vol, inode->indirect_block, pointers) != 0) return -EIO;
            *out_block = pointers[logical_block];
        } else {
            logical_block -= DENYFS_POINTERS_PER_BLOCK;
            uint64_t outer = logical_block / DENYFS_POINTERS_PER_BLOCK;
            uint32_t inner = (uint32_t)(logical_block % DENYFS_POINTERS_PER_BLOCK);
            if (inode->double_indirect_block == DENYFS_INVALID_BLOCK) return 0;
            uint32_t roots[DENYFS_POINTERS_PER_BLOCK];
            if (read_pointer_table(vol, inode->double_indirect_block, roots) != 0)
                return -EIO;
            if (roots[outer] == DENYFS_INVALID_BLOCK) return 0;
            if (read_pointer_table(vol, roots[outer], pointers) != 0) return -EIO;
            *out_block = pointers[inner];
        }
    }
    if (*out_block != DENYFS_INVALID_BLOCK &&
        (*out_block < vol->sb.data_start || *out_block >= vol->sb.total_blocks ||
         !(vol->bitmap[*out_block / 8] & (1U << (*out_block % 8)))))
        return -EIO;
    return 0;
}

static int allocate_file_data_block(denyfs_volume_t *vol, denyfs_inode_t *inode,
                                    uint64_t logical_block, uint32_t *out_block) {
    uint32_t existing;
    int result = get_file_data_block(vol, inode, logical_block, &existing);
    if (result != 0) return result;
    if (existing != DENYFS_INVALID_BLOCK) {
        *out_block = existing;
        return 0;
    }

    uint32_t data_block;
    result = allocate_zeroed_data_block(vol, &data_block);
    if (result != 0) return result;

    if (logical_block < DENYFS_DIRECT_BLOCKS) {
        inode->direct[logical_block] = data_block;
    } else if ((logical_block -= DENYFS_DIRECT_BLOCKS) < DENYFS_POINTERS_PER_BLOCK) {
        int new_table = 0;
        uint32_t table_block = inode->indirect_block;
        if (table_block == DENYFS_INVALID_BLOCK) {
            result = allocate_pointer_table(vol, &table_block);
            if (result != 0) { free_block(vol, data_block); return result; }
            new_table = 1;
        }
        uint32_t pointers[DENYFS_POINTERS_PER_BLOCK];
        if (new_table) memset(pointers, 0xFF, sizeof(pointers));
        else if (read_pointer_table(vol, table_block, pointers) != 0) {
            free_block(vol, data_block);
            return -EIO;
        }
        pointers[logical_block] = data_block;
        if (write_block(vol, table_block, (const uint8_t *)pointers) != 0) {
            free_block(vol, data_block);
            if (new_table) free_block(vol, table_block);
            return -EIO;
        }
        if (new_table) inode->indirect_block = table_block;
    } else {
        logical_block -= DENYFS_POINTERS_PER_BLOCK;
        uint64_t outer = logical_block / DENYFS_POINTERS_PER_BLOCK;
        uint32_t inner = (uint32_t)(logical_block % DENYFS_POINTERS_PER_BLOCK);
        int new_root = 0, new_child = 0;
        uint32_t root_block = inode->double_indirect_block;
        if (root_block == DENYFS_INVALID_BLOCK) {
            result = allocate_pointer_table(vol, &root_block);
            if (result != 0) { free_block(vol, data_block); return result; }
            new_root = 1;
        }
        uint32_t roots[DENYFS_POINTERS_PER_BLOCK];
        if (new_root) memset(roots, 0xFF, sizeof(roots));
        else if (read_pointer_table(vol, root_block, roots) != 0) {
            free_block(vol, data_block);
            return -EIO;
        }

        uint32_t child_block = roots[outer];
        if (child_block == DENYFS_INVALID_BLOCK) {
            result = allocate_pointer_table(vol, &child_block);
            if (result != 0) {
                free_block(vol, data_block);
                if (new_root) free_block(vol, root_block);
                return result;
            }
            new_child = 1;
        }
        uint32_t pointers[DENYFS_POINTERS_PER_BLOCK];
        if (new_child) memset(pointers, 0xFF, sizeof(pointers));
        else if (read_pointer_table(vol, child_block, pointers) != 0) {
            free_block(vol, data_block);
            if (new_root) free_block(vol, root_block);
            return -EIO;
        }
        pointers[inner] = data_block;
        if (write_block(vol, child_block, (const uint8_t *)pointers) != 0) {
            free_block(vol, data_block);
            if (new_child) free_block(vol, child_block);
            if (new_root) free_block(vol, root_block);
            return -EIO;
        }
        if (new_child) {
            roots[outer] = child_block;
            if (write_block(vol, root_block, (const uint8_t *)roots) != 0) {
                free_block(vol, data_block);
                free_block(vol, child_block);
                if (new_root) free_block(vol, root_block);
                return -EIO;
            }
        }
        if (new_root) inode->double_indirect_block = root_block;
    }

    inode->block_count++;
    *out_block = data_block;
    return 0;
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
            if (!valid_dirent(&entries[i])) return -EIO;
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
            if (!valid_dirent(&entries[i])) return -EIO;
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

static int free_inode(denyfs_volume_t *vol, uint32_t ino) {
    denyfs_inode_t *inode = &vol->inodes[ino];

    // Free direct data blocks.
    for (uint32_t i = 0; i < DENYFS_DIRECT_BLOCKS; i++) {
        if (inode->direct[i] != DENYFS_INVALID_BLOCK) {
            free_block(vol, inode->direct[i]);
            inode->direct[i] = DENYFS_INVALID_BLOCK;
        }
    }

    // Free data blocks referenced by the single-indirect table, then the table.
    if (inode->indirect_block != DENYFS_INVALID_BLOCK) {
        uint32_t pointers[DENYFS_POINTERS_PER_BLOCK];
        if (read_pointer_table(vol, inode->indirect_block, pointers) != 0) return -EIO;
        for (uint32_t i = 0; i < DENYFS_POINTERS_PER_BLOCK; i++)
            if (pointers[i] != DENYFS_INVALID_BLOCK) free_block(vol, pointers[i]);
        free_block(vol, inode->indirect_block);
        inode->indirect_block = DENYFS_INVALID_BLOCK;
    }

    // Free double-indirect data and child tables, then the root pointer table.
    if (inode->double_indirect_block != DENYFS_INVALID_BLOCK) {
        uint32_t roots[DENYFS_POINTERS_PER_BLOCK];
        if (read_pointer_table(vol, inode->double_indirect_block, roots) != 0) return -EIO;
        for (uint32_t outer = 0; outer < DENYFS_POINTERS_PER_BLOCK; outer++) {
            if (roots[outer] == DENYFS_INVALID_BLOCK) continue;
            uint32_t pointers[DENYFS_POINTERS_PER_BLOCK];
            if (read_pointer_table(vol, roots[outer], pointers) != 0) return -EIO;
            for (uint32_t inner = 0; inner < DENYFS_POINTERS_PER_BLOCK; inner++)
                if (pointers[inner] != DENYFS_INVALID_BLOCK) free_block(vol, pointers[inner]);
            free_block(vol, roots[outer]);
        }
        free_block(vol, inode->double_indirect_block);
        inode->double_indirect_block = DENYFS_INVALID_BLOCK;
    }

    inode->type = DENYFS_ITYPE_FREE;
    inode->size = 0;
    inode->block_count = 0;
    inode->mtime = 0;
    vol->sb.free_inodes++;
    return 0;
}

// ---------------------------------------------------------------------------
// Format — write initial filesystem metadata into an already-open container
// ---------------------------------------------------------------------------

static int format_volume(FILE *fp, const uint8_t *volume_key,
                         const uint8_t *hmac_key, uint64_t volume_size,
                         uint64_t start_offset) {
    if (!fp || !volume_key || !hmac_key || volume_size == 0 ||
        volume_size % SECTOR_SIZE != 0 || start_offset > LONG_MAX ||
        volume_size > (uint64_t)LONG_MAX - start_offset ||
        volume_size / SECTOR_SIZE > UINT32_MAX - 8U) return -1;
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
    if (denyfs_compute_hmac(hmac_key, KEY_SIZE_HMAC, bitmap, bm_total, sb.bitmap_hmac) != 0) {
        free(bitmap);
        return -1;
    }

    // ------ Inode table ------
    denyfs_inode_t inodes[DENYFS_MAX_INODES];
    memset(inodes, 0, sizeof(inodes));
    for (uint32_t i = 0; i < DENYFS_MAX_INODES; i++) {
        inodes[i].type = DENYFS_ITYPE_FREE;
        memset(inodes[i].direct, 0xFF, sizeof(inodes[i].direct));
        inodes[i].indirect_block = DENYFS_INVALID_BLOCK;
        inodes[i].double_indirect_block = DENYFS_INVALID_BLOCK;
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
    if (!path || !password || pass_len == 0 || size_mb == 0 ||
        size_mb > UINT64_MAX / (1024 * 1024)) return -1;
    uint64_t total_bytes = size_mb * 1024 * 1024;
    if (total_bytes > (uint64_t)LONG_MAX || total_bytes < 1024 * 1024 ||
        total_bytes / 2 / SECTOR_SIZE > UINT32_MAX - 8U) return -1;
    int container_fd = open(path, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    if (container_fd < 0) return -1;
    FILE *f = fdopen(container_fd, "w+b");
    if (!f) { close(container_fd); unlink(path); return -1; }
    int fmt_res = -1;

    // CSPRNG fill
    size_t chunk_size = 65536;
    uint8_t *chunk = malloc(chunk_size);
    if (!chunk) { fclose(f); unlink(path); return -1; }

    uint64_t written = 0;
    while (written < total_bytes) {
        uint64_t rem = total_bytes - written;
        size_t to_write = (rem < chunk_size) ? (size_t)rem : chunk_size;
        randombytes_buf(chunk, to_write);
        if (fwrite(chunk, 1, to_write, f) != to_write)
            { free(chunk); fclose(f); unlink(path); return -1; }
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
        fclose(f); unlink(path); return -1;
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
    if (denyfs_encrypt_header(&payload, header_key, &disk_header) != 0) {
        sodium_memzero(&payload, sizeof(payload));
        fclose(f);
        goto cleanup_keys;
    }

    // Write header at byte 0
    if (fseek(f, 0, SEEK_SET) != 0) {
        sodium_memzero(&payload, sizeof(payload));
        fclose(f);
        goto cleanup_keys;
    }
    if (fwrite(&disk_header, 1, sizeof(disk_header), f) != sizeof(disk_header))
        { sodium_memzero(&payload, sizeof(payload)); fclose(f); goto cleanup_keys; }

    // Format filesystem inside the volume (starting at byte 4096)
    fmt_res = format_volume(f, volume_key, hmac_key, volume_size, HEADER_SIZE);

    fclose(f);
    sodium_memzero(&payload, sizeof(payload));

cleanup_keys:
    denyfs_secure_free(salt, SALT_SIZE);
    denyfs_secure_free(master_key, KEY_SIZE_GCM);
    denyfs_secure_free(header_key, KEY_SIZE_GCM);
    denyfs_secure_free(volume_key, KEY_SIZE_XTS);
    denyfs_secure_free(hmac_key, KEY_SIZE_HMAC);
    if (fmt_res != 0) unlink(path);
    return fmt_res;
}

// ---------------------------------------------------------------------------
// Public: create hidden volume
// ---------------------------------------------------------------------------

int denyfs_container_create_hidden(const char *path,
                                   const char *outer_password, size_t outer_pass_len,
                                   const char *hidden_password, size_t hidden_pass_len,
                                   uint64_t hidden_size_mb) {
    if (!path || !outer_password || !hidden_password || !outer_pass_len ||
        !hidden_pass_len || hidden_size_mb == 0 ||
        hidden_size_mb > UINT64_MAX / (1024 * 1024)) return -EINVAL;
    int fmt_res = -1;
    if (hidden_size_mb * (1024 * 1024) / SECTOR_SIZE > UINT32_MAX - 8U) return -EINVAL;
    if (outer_pass_len == hidden_pass_len &&
        sodium_memcmp(outer_password, hidden_password, outer_pass_len) == 0) return -EINVAL;
    // Authenticate and open the outer volume to verify space
    denyfs_volume_t *vol = denyfs_vol_open(path, outer_password, outer_pass_len, NULL, 0, 0);
    if (!vol) return -EACCES;

    // Get total container size
    if (fseek(vol->fp, 0, SEEK_END) != 0) { denyfs_vol_close(vol); return -EIO; }
    long container_size = ftell(vol->fp);
    if (container_size < (long)(DENYFS_HIDDEN_HEADER_OFFSET_FROM_EOF + HEADER_SIZE) ||
        container_size % SECTOR_SIZE != 0) {
        denyfs_vol_close(vol);
        return -EINVAL;
    }

    uint64_t hidden_size_bytes = hidden_size_mb * 1024 * 1024;
    uint64_t outer_end = vol->vol_start_offset + vol->volume_size;
    uint64_t hidden_header_offset = (uint64_t)container_size - DENYFS_HIDDEN_HEADER_OFFSET_FROM_EOF;

    if (hidden_size_bytes > hidden_header_offset ||
        outer_end > hidden_header_offset - hidden_size_bytes ||
        hidden_size_bytes % SECTOR_SIZE != 0) {
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
        sodium_memzero(&payload, sizeof(payload));
        denyfs_vol_close(vol);
        goto cleanup_keys;
    }

    // Write hidden header at C - 32768
    if (fseek(vol->fp, (long)hidden_header_offset, SEEK_SET) != 0) {
        sodium_memzero(&payload, sizeof(payload));
        denyfs_vol_close(vol);
        goto cleanup_keys;
    }
    if (fwrite(&disk_header, 1, sizeof(disk_header), vol->fp) != sizeof(disk_header)) {
        sodium_memzero(&payload, sizeof(payload));
        denyfs_vol_close(vol);
        goto cleanup_keys;
    }

    // Format the hidden volume at its calculated start offset
    fmt_res = format_volume(vol->fp, volume_key, hmac_key, hidden_size_bytes, hidden_start_offset);

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
    if (container_size < (long)(DENYFS_HIDDEN_HEADER_OFFSET_FROM_EOF + HEADER_SIZE) ||
        container_size % SECTOR_SIZE != 0) {
        fclose(fp);
        return NULL;
    }

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

    sodium_memzero(outer_master_key, KEY_SIZE_GCM);
    sodium_memzero(outer_header_key, KEY_SIZE_GCM);
    sodium_memzero(hidden_master_key, KEY_SIZE_GCM);
    sodium_memzero(hidden_header_key, KEY_SIZE_GCM);

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

    if (outer_succeeded && valid_volume_range(HEADER_SIZE, outer_payload.volume_size,
                                               hidden_header_offset)) {
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
    } else if (hidden_succeeded && hidden_payload.volume_size <= hidden_header_offset - HEADER_SIZE &&
               valid_volume_range(hidden_header_offset - hidden_payload.volume_size,
                                  hidden_payload.volume_size, hidden_header_offset)) {
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
    if (protect_hidden && !vol->is_hidden) {
        if (!hidden_password) {
            denyfs_vol_close(vol);
            return NULL;
        }
        // Run KDF for hidden master/header keys again using the provided hidden password
        uint8_t *prot_master = denyfs_secure_alloc(KEY_SIZE_GCM);
        uint8_t *prot_header = denyfs_secure_alloc(KEY_SIZE_GCM);
        
        if (prot_master && prot_header &&
            denyfs_derive_master_key(hidden_password, hidden_pass_len, hidden_disk.salt, prot_master) == 0 &&
            denyfs_derive_header_key(prot_master, prot_header) == 0) {
            
            denyfs_header_payload_t prot_payload;
            memset(&prot_payload, 0, sizeof(prot_payload));
            
            if (denyfs_decrypt_header(&hidden_disk, prot_header, &prot_payload) == 0 &&
                sodium_memcmp(&prot_payload.magic, &expected_magic, sizeof(uint64_t)) == 0 &&
                prot_payload.volume_size <= hidden_header_offset - HEADER_SIZE &&
                valid_volume_range(hidden_header_offset - prot_payload.volume_size,
                                   prot_payload.volume_size, hidden_header_offset)) {
                
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
        if (!vol->protect_hidden) {
            denyfs_vol_close(vol);
            return NULL;
        }
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
    if (validate_superblock(&vol->sb, vol->volume_size) != 0) {
        denyfs_vol_close(vol);
        return NULL;
    }

    vol->bitmap_bytes = (size_t)vol->sb.bitmap_blocks * SECTOR_SIZE;
    vol->bitmap = calloc(1, vol->bitmap_bytes);
    if (!vol->bitmap) {
        denyfs_vol_close(vol);
        return NULL;
    }
    vol->bitmap_dirty_count = vol->sb.bitmap_blocks;
    vol->bitmap_dirty = calloc(vol->bitmap_dirty_count, sizeof(*vol->bitmap_dirty));
    if (!vol->bitmap_dirty) {
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
    if (denyfs_compute_hmac(vol->hmac_key, KEY_SIZE_HMAC,
                            vol->bitmap, vol->bitmap_bytes, computed) != 0) {
        denyfs_vol_close(vol);
        return NULL;
    }
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

    if (validate_loaded_metadata(vol) != 0) {
        denyfs_vol_close(vol);
        return NULL;
    }

    return vol;
}

// ---------------------------------------------------------------------------
// Public: flush
// ---------------------------------------------------------------------------

int denyfs_vol_flush(denyfs_volume_t *vol) {
    if (!vol || !vol->fp || !vol->bitmap || !vol->bitmap_dirty) return -1;

    // Recompute bitmap HMAC
    if (denyfs_compute_hmac(vol->hmac_key, KEY_SIZE_HMAC,
                            vol->bitmap, vol->bitmap_bytes, vol->sb.bitmap_hmac) != 0)
        return -1;

    // Write superblock
    if (write_block(vol, 0, (const uint8_t *)&vol->sb) != 0)
        return -1;

    // Write bitmap
    for (uint32_t i = 0; i < vol->sb.bitmap_blocks; i++) {
        if (vol->bitmap_dirty[i] &&
            write_block(vol, vol->sb.bitmap_start + i,
                        vol->bitmap + i * SECTOR_SIZE) != 0)
            return -1;
    }

    // Write inode table
    for (uint32_t i = 0; i < vol->sb.inode_blocks; i++) {
        if (write_block(vol, vol->sb.inode_start + i, ((const uint8_t *)vol->inodes) + i * SECTOR_SIZE) != 0)
            return -1;
    }

    if (fflush(vol->fp) != 0) return -1;
    memset(vol->bitmap_dirty, 0, vol->bitmap_dirty_count);
    return 0;
}

// ---------------------------------------------------------------------------
// Public: close
// ---------------------------------------------------------------------------

void denyfs_vol_close(denyfs_volume_t *vol) {
    if (!vol) return;

    if (vol->fp) {
        fclose(vol->fp);
        vol->fp = NULL;
    }

    if (vol->volume_key) denyfs_secure_free(vol->volume_key, KEY_SIZE_XTS);
    if (vol->hmac_key)   denyfs_secure_free(vol->hmac_key, KEY_SIZE_HMAC);
    if (vol->bitmap)     { sodium_memzero(vol->bitmap, vol->bitmap_bytes); free(vol->bitmap); }
    if (vol->bitmap_dirty) { sodium_memzero(vol->bitmap_dirty, vol->bitmap_dirty_count); free(vol->bitmap_dirty); }

    sodium_memzero(vol->inodes, sizeof(vol->inodes));
    sodium_memzero(&vol->sb, sizeof(vol->sb));
    free(vol);
}

// ---------------------------------------------------------------------------
// Public: lookup
// ---------------------------------------------------------------------------

int denyfs_vol_lookup(denyfs_volume_t *vol, const char *name, uint32_t *out_ino) {
    if (!vol || !name || !name[0] || strlen(name) >= DENYFS_MAX_NAME_LEN) return -EINVAL;
    denyfs_inode_t *root = &vol->inodes[0];
    size_t name_len = strlen(name);

    for (uint32_t bi = 0; bi < DENYFS_DIRECT_BLOCKS; bi++) {
        if (root->direct[bi] == DENYFS_INVALID_BLOCK) continue;

        uint8_t block_data[SECTOR_SIZE];
        if (read_block(vol, root->direct[bi], block_data) != 0)
            return -EIO;

        denyfs_dirent_t *entries = (denyfs_dirent_t *)block_data;
        for (int i = 0; i < DENYFS_DIRENTS_PER_BLOCK; i++) {
            if (!valid_dirent(&entries[i])) return -EIO;
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
    if (!vol || !name || !name[0] || strlen(name) >= DENYFS_MAX_NAME_LEN ||
        strchr(name, '/') || strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        return -EINVAL;
    // Check for duplicate
    uint32_t dummy;
    int lookup_res = denyfs_vol_lookup(vol, name, &dummy);
    if (lookup_res == 0) return -EEXIST;
    if (lookup_res != -ENOENT) return lookup_res;

    // Allocate inode
    int ino = alloc_inode(vol);
    if (ino < 0) return -ENOSPC;

    // Initialize inode
    denyfs_inode_t *inode = &vol->inodes[ino];
    inode->type = DENYFS_ITYPE_FILE;
    inode->size = 0;
    inode->block_count = 0;
    memset(inode->direct, 0xFF, sizeof(inode->direct));
    inode->indirect_block = DENYFS_INVALID_BLOCK;
    inode->double_indirect_block = DENYFS_INVALID_BLOCK;
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

    return denyfs_vol_flush(vol) == 0 ? 0 : -EIO;
}

// ---------------------------------------------------------------------------
// Public: unlink
// ---------------------------------------------------------------------------

int denyfs_vol_unlink(denyfs_volume_t *vol, const char *name) {
    if (!vol || !name) return -EINVAL;
    uint32_t ino;
    if (denyfs_vol_lookup(vol, name, &ino) != 0) return -ENOENT;

    // Remove directory entry
    int res = remove_dirent(vol, name);
    if (res != 0) return res;

    // Free inode and its blocks
    if (free_inode(vol, ino) != 0) return -EIO;

    return denyfs_vol_flush(vol) == 0 ? 0 : -EIO;
}

// ---------------------------------------------------------------------------
// Public: read
// ---------------------------------------------------------------------------

int denyfs_vol_read(denyfs_volume_t *vol, uint32_t ino,
                    void *buf, size_t size, uint64_t offset) {
    if (!vol || (!buf && size != 0) || ino >= DENYFS_MAX_INODES) return -EINVAL;
    if (size > INT_MAX) return -EINVAL;
    denyfs_inode_t *inode = &vol->inodes[ino];
    if (inode->type != DENYFS_ITYPE_FILE) return -EISDIR;

    // Clamp read to file bounds
    if (offset >= inode->size) return 0;
    uint64_t available = (uint64_t)inode->size - offset;
    if (size > available) size = (size_t)available;
    if (size == 0) return 0;

    uint8_t *dst = (uint8_t *)buf;
    size_t bytes_read = 0;
    uint64_t pos = offset;

    while (bytes_read < size) {
        uint64_t blk_idx = pos / SECTOR_SIZE;
        uint32_t blk_off = (uint32_t)(pos % SECTOR_SIZE);
        size_t chunk = SECTOR_SIZE - blk_off;
        if (chunk > size - bytes_read) chunk = size - bytes_read;

        uint32_t physical_block;
        int map_result = get_file_data_block(vol, inode, blk_idx, &physical_block);
        if (map_result != 0) return map_result;
        if (physical_block == DENYFS_INVALID_BLOCK) {
            memset(dst + bytes_read, 0, chunk);
        } else {
            uint8_t block_data[SECTOR_SIZE];
            if (read_block(vol, physical_block, block_data) != 0)
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
    if (!vol || (!buf && size != 0) || ino >= DENYFS_MAX_INODES) return -EINVAL;
    if (size > INT_MAX) return -EINVAL;
    denyfs_inode_t *inode = &vol->inodes[ino];
    if (inode->type != DENYFS_ITYPE_FILE) return -EISDIR;

    if (offset > DENYFS_MAX_FILE_SIZE || size > DENYFS_MAX_FILE_SIZE - offset)
        return -ENOSPC;

    const uint8_t *src = (const uint8_t *)buf;
    size_t bytes_written = 0;
    uint64_t pos = offset;

    while (bytes_written < size) {
        uint64_t blk_idx = pos / SECTOR_SIZE;
        uint32_t blk_off = (uint32_t)(pos % SECTOR_SIZE);
        size_t chunk = SECTOR_SIZE - blk_off;
        if (chunk > size - bytes_written) chunk = size - bytes_written;

        uint32_t physical_block;
        int map_result = get_file_data_block(vol, inode, blk_idx, &physical_block);
        if (map_result != 0) return map_result;
        if (physical_block == DENYFS_INVALID_BLOCK) {
            map_result = allocate_file_data_block(vol, inode, blk_idx, &physical_block);
            if (map_result != 0) return map_result;
        }

        // Read-modify-write
        uint8_t block_data[SECTOR_SIZE];
        if (read_block(vol, physical_block, block_data) != 0)
            return -EIO;

        memcpy(block_data + blk_off, src + bytes_written, chunk);

        int write_res = write_block(vol, physical_block, block_data);
        if (write_res != 0)
            return write_res;

        bytes_written += chunk;
        pos += chunk;
    }

    // Update size if extended
    if (offset + size > inode->size)
        inode->size = offset + size;
    inode->mtime = (uint64_t)time(NULL);

    if (denyfs_vol_flush(vol) != 0) return -EIO;
    return (int)bytes_written;
}

// ---------------------------------------------------------------------------
// Public: truncate
// ---------------------------------------------------------------------------

static int truncate_file_blocks(denyfs_volume_t *vol, denyfs_inode_t *inode,
                                uint64_t new_block_count) {
    for (uint32_t i = 0; i < DENYFS_DIRECT_BLOCKS; i++) {
        if (i >= new_block_count && inode->direct[i] != DENYFS_INVALID_BLOCK) {
            free_block(vol, inode->direct[i]);
            inode->direct[i] = DENYFS_INVALID_BLOCK;
            inode->block_count--;
        }
    }

    if (inode->indirect_block != DENYFS_INVALID_BLOCK) {
        uint32_t pointers[DENYFS_POINTERS_PER_BLOCK];
        if (read_pointer_table(vol, inode->indirect_block, pointers) != 0) return -EIO;
        uint32_t remaining = 0;
        for (uint32_t i = 0; i < DENYFS_POINTERS_PER_BLOCK; i++) {
            uint64_t logical = (uint64_t)DENYFS_DIRECT_BLOCKS + i;
            if (logical >= new_block_count && pointers[i] != DENYFS_INVALID_BLOCK) {
                free_block(vol, pointers[i]);
                pointers[i] = DENYFS_INVALID_BLOCK;
                inode->block_count--;
            }
            if (pointers[i] != DENYFS_INVALID_BLOCK) remaining++;
        }
        if (remaining == 0) {
            free_block(vol, inode->indirect_block);
            inode->indirect_block = DENYFS_INVALID_BLOCK;
        } else if (write_block(vol, inode->indirect_block,
                               (const uint8_t *)pointers) != 0) {
            return -EIO;
        }
    }

    if (inode->double_indirect_block != DENYFS_INVALID_BLOCK) {
        uint32_t roots[DENYFS_POINTERS_PER_BLOCK];
        if (read_pointer_table(vol, inode->double_indirect_block, roots) != 0) return -EIO;
        uint32_t remaining_roots = 0;
        for (uint32_t outer = 0; outer < DENYFS_POINTERS_PER_BLOCK; outer++) {
            uint32_t child_block = roots[outer];
            if (child_block == DENYFS_INVALID_BLOCK) continue;
            uint64_t logical_start = (uint64_t)DENYFS_DIRECT_BLOCKS +
                DENYFS_POINTERS_PER_BLOCK +
                (uint64_t)outer * DENYFS_POINTERS_PER_BLOCK;
            uint32_t pointers[DENYFS_POINTERS_PER_BLOCK];
            if (read_pointer_table(vol, child_block, pointers) != 0) return -EIO;
            uint32_t remaining_child = 0;
            for (uint32_t inner = 0; inner < DENYFS_POINTERS_PER_BLOCK; inner++) {
                if (logical_start + inner >= new_block_count &&
                    pointers[inner] != DENYFS_INVALID_BLOCK) {
                    free_block(vol, pointers[inner]);
                    pointers[inner] = DENYFS_INVALID_BLOCK;
                    inode->block_count--;
                }
                if (pointers[inner] != DENYFS_INVALID_BLOCK) remaining_child++;
            }
            if (remaining_child == 0) {
                free_block(vol, child_block);
                roots[outer] = DENYFS_INVALID_BLOCK;
            } else {
                if (write_block(vol, child_block, (const uint8_t *)pointers) != 0)
                    return -EIO;
                remaining_roots++;
            }
        }
        if (remaining_roots == 0) {
            free_block(vol, inode->double_indirect_block);
            inode->double_indirect_block = DENYFS_INVALID_BLOCK;
        } else if (write_block(vol, inode->double_indirect_block,
                               (const uint8_t *)roots) != 0) {
            return -EIO;
        }
    }
    return 0;
}

int denyfs_vol_truncate(denyfs_volume_t *vol, uint32_t ino, uint64_t new_size) {
    if (!vol || ino >= DENYFS_MAX_INODES) return -EINVAL;
    denyfs_inode_t *inode = &vol->inodes[ino];
    if (inode->type != DENYFS_ITYPE_FILE) return -EISDIR;

    if (new_size > DENYFS_MAX_FILE_SIZE) return -ENOSPC;
    if (new_size == inode->size) return 0;

    if (new_size < inode->size) {
        if (new_size % SECTOR_SIZE != 0) {
            uint64_t tail_block = new_size / SECTOR_SIZE;
            uint32_t physical_block;
            int map_result = get_file_data_block(vol, inode, tail_block, &physical_block);
            if (map_result != 0) return map_result;
            if (physical_block != DENYFS_INVALID_BLOCK) {
                uint8_t block_data[SECTOR_SIZE];
                if (read_block(vol, physical_block, block_data) != 0) return -EIO;
                memset(block_data + (new_size % SECTOR_SIZE), 0,
                       SECTOR_SIZE - (new_size % SECTOR_SIZE));
                if (write_block(vol, physical_block, block_data) != 0) return -EIO;
            }
        }
        uint64_t new_blocks = (new_size + SECTOR_SIZE - 1) / SECTOR_SIZE;
        if (truncate_file_blocks(vol, inode, new_blocks) != 0) return -EIO;
    }

    inode->size = new_size;
    inode->mtime = (uint64_t)time(NULL);

    return denyfs_vol_flush(vol) == 0 ? 0 : -EIO;
}

// ---------------------------------------------------------------------------
// Public: readdir
// ---------------------------------------------------------------------------

int denyfs_vol_readdir(denyfs_volume_t *vol, denyfs_readdir_cb cb, void *userdata) {
    if (!vol || !cb) return -EINVAL;
    denyfs_inode_t *root = &vol->inodes[0];

    for (uint32_t bi = 0; bi < DENYFS_DIRECT_BLOCKS; bi++) {
        if (root->direct[bi] == DENYFS_INVALID_BLOCK) continue;

        uint8_t block_data[SECTOR_SIZE];
        if (read_block(vol, root->direct[bi], block_data) != 0)
            return -EIO;

        denyfs_dirent_t *entries = (denyfs_dirent_t *)block_data;
        for (int i = 0; i < DENYFS_DIRENTS_PER_BLOCK; i++) {
            if (!valid_dirent(&entries[i])) return -EIO;
            if (entries[i].inode != DENYFS_INVALID_INO) {
                if (cb(entries[i].name, entries[i].inode, userdata) != 0)
                    return 0;  // callback requested stop
            }
        }
    }
    return 0;
}
