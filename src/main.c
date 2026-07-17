#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/resource.h>
#include <sodium.h>
#include <errno.h>
#include "crypto.h"
#include "fs.h"
#include "fuse_ops.h"

// Helper to wipe and free secure buffer
void secure_cleanup_buffer(void *buf, size_t size) {
    if (buf) {
        denyfs_secure_free(buf, size);
    }
}

// Securely copy command line password and wipe the argv source
char *secure_dup_password(char *arg, size_t *out_len) {
    if (!arg) return NULL;
    size_t len = strlen(arg);
    char *sec_pass = denyfs_secure_alloc(len + 1);
    if (!sec_pass) {
        fprintf(stderr, "Error: secure memory allocation failed.\n");
        exit(1);
    }
    memcpy(sec_pass, arg, len);
    sec_pass[len] = '\0';
    
    // Wipe original command line arg
    sodium_memzero(arg, len);
    
    if (out_len) *out_len = len;
    return sec_pass;
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

int handle_create(const char *path, uint64_t size_mb, char *raw_pass, size_t pass_len) {
    printf("Creating container of size %llu MB at %s...\n",
           (unsigned long long)size_mb, path);

    clock_t start = clock();
    int res = denyfs_container_create(path, size_mb, raw_pass, pass_len);
    clock_t end = clock();
    double ms = (double)(end - start) * 1000.0 / CLOCKS_PER_SEC;

    if (res != 0) {
        fprintf(stderr, "Error: Container creation failed.\n");
        return 1;
    }

    printf("Container created and formatted (%.2f ms).\n", ms);
    return 0;
}

int handle_create_hidden(const char *path, char *outer_pass, size_t outer_pass_len,
                          char *hidden_pass, size_t hidden_pass_len, uint64_t hidden_size_mb) {
    printf("Creating hidden volume of size %llu MB inside %s...\n",
           (unsigned long long)hidden_size_mb, path);

    clock_t start = clock();
    int res = denyfs_container_create_hidden(path, outer_pass, outer_pass_len,
                                             hidden_pass, hidden_pass_len, hidden_size_mb);
    clock_t end = clock();
    double ms = (double)(end - start) * 1000.0 / CLOCKS_PER_SEC;

    if (res != 0) {
        if (res == -ENOSPC) {
            fprintf(stderr, "Error: Not enough free space inside container for hidden volume.\n");
        } else {
            fprintf(stderr, "Error: Hidden volume creation failed (code %d).\n", res);
        }
        return 1;
    }

    printf("Hidden volume successfully created and formatted (%.2f ms).\n", ms);
    return 0;
}

int handle_open(const char *path, char *raw_pass, size_t pass_len,
                char *hidden_pass, size_t hidden_pass_len, int protect_hidden) {
    clock_t start = clock();
    denyfs_volume_t *vol = denyfs_vol_open(path, raw_pass, pass_len,
                                           hidden_pass, hidden_pass_len, protect_hidden);
    clock_t end = clock();
    double ms = (double)(end - start) * 1000.0 / CLOCKS_PER_SEC;

    if (!vol) {
        fprintf(stderr, "Error: invalid password.\n");
        return 1;
    }

    printf("Container successfully authenticated (%.2f ms).\n", ms);
    printf("Volume type      : %s\n", vol->is_hidden ? "HIDDEN" : "OUTER");
    printf("Volume size      : %llu bytes\n", (unsigned long long)vol->volume_size);
    printf("Total blocks     : %u\n", vol->sb.total_blocks);
    printf("Free blocks      : %u\n", vol->sb.free_blocks);
    printf("Free inodes      : %u\n", vol->sb.free_inodes);
    printf("Data start block : %u\n", vol->sb.data_start);
    if (vol->protect_hidden) {
        printf("Protection active: YES (Blocks %llu to %llu locked)\n",
               (unsigned long long)vol->protect_start_sector,
               (unsigned long long)vol->protect_end_sector);
    } else {
        printf("Protection active: NO\n");
    }

    denyfs_vol_close(vol);
    return 0;
}

int handle_mount(const char *path, char *raw_pass, size_t pass_len,
                 char *hidden_pass, size_t hidden_pass_len, int protect_hidden,
                 const char *mount_point) {
    denyfs_volume_t *vol = denyfs_vol_open(path, raw_pass, pass_len,
                                           hidden_pass, hidden_pass_len, protect_hidden);
    if (!vol) {
        fprintf(stderr, "Error: invalid password.\n");
        return 1;
    }

    printf("Volume authenticated successfully (%s).\n", vol->is_hidden ? "HIDDEN" : "OUTER");
    
    // Print out-of-band deniability warnings
    printf("\n"
           "======================================================================\n"
           "⚠️  SECURITY NOTICE & DENIABILITY BANNER\n"
           "======================================================================\n"
           "1. File Indexers: Tracker, Baloo, etc., may scan the mount point. Exclude\n"
           "   the mount directory '%s' from your desktop search indexers.\n"
           "2. GVFS: The virtual filesystem daemon might create preview or thumbnail\n"
           "   caches of exposed files. Avoid opening folders in graphical managers.\n"
           "3. Logs: systemd-journald logs FUSE mounts/unmounts by default. Scrub or\n"
           "   rotate journal logs if timing deniability is critical.\n"
           "4. Container Metadata: Mount operations may alter atime/mtime on the host\n"
           "   file. If possible, mount using O_NOATIME or touch-preventing methods.\n"
           "======================================================================\n\n",
           mount_point);

    printf("Mounting at %s (Ctrl+C to unmount)...\n", mount_point);

    // FUSE main loop — blocks until unmount
    int ret = denyfs_fuse_run(vol, mount_point);
    // vol is freed by denyfs_fuse_destroy callback
    return ret;
}

// Phase 2: raw sector write
int handle_write_sector(const char *container_path, char *raw_pass, size_t pass_len,
                        uint64_t lba, const char *data_file) {
    denyfs_volume_t *vol = denyfs_vol_open(container_path, raw_pass, pass_len, NULL, 0, 0);
    if (!vol) {
        fprintf(stderr, "Error: invalid password.\n");
        return 1;
    }

    uint64_t max_lba = vol->volume_size / SECTOR_SIZE;
    if (lba >= max_lba) {
        fprintf(stderr, "Error: LBA %llu exceeds volume capacity (%llu sectors).\n",
                (unsigned long long)lba, (unsigned long long)max_lba);
        denyfs_vol_close(vol);
        return 1;
    }

    FILE *df = fopen(data_file, "rb");
    if (!df) { perror("Error opening data file"); denyfs_vol_close(vol); return 1; }

    uint8_t plain[SECTOR_SIZE];
    size_t nread = fread(plain, 1, SECTOR_SIZE, df);
    fclose(df);
    if (nread < SECTOR_SIZE) memset(plain + nread, 0, SECTOR_SIZE - nread);

    uint8_t cipher[SECTOR_SIZE];
    if (denyfs_crypt_sector(plain, cipher, lba, vol->volume_key, 1) != 0) {
        fprintf(stderr, "Error: Sector encryption failed.\n");
        sodium_memzero(plain, sizeof(plain));
        denyfs_vol_close(vol);
        return 1;
    }
    sodium_memzero(plain, sizeof(plain));

    uint64_t offset = vol->vol_start_offset + (lba * SECTOR_SIZE);
    fseek(vol->fp, (long)offset, SEEK_SET);
    if (fwrite(cipher, 1, SECTOR_SIZE, vol->fp) != SECTOR_SIZE) {
        perror("Error writing sector"); denyfs_vol_close(vol); return 1;
    }
    fflush(vol->fp);

    denyfs_vol_close(vol);
    printf("Sector %llu written successfully.\n", (unsigned long long)lba);
    return 0;
}

// Phase 2: raw sector read
int handle_read_sector(const char *container_path, char *raw_pass, size_t pass_len,
                       uint64_t lba, const char *out_file) {
    denyfs_volume_t *vol = denyfs_vol_open(container_path, raw_pass, pass_len, NULL, 0, 0);
    if (!vol) {
        fprintf(stderr, "Error: invalid password.\n");
        return 1;
    }

    uint64_t max_lba = vol->volume_size / SECTOR_SIZE;
    if (lba >= max_lba) {
        fprintf(stderr, "Error: LBA %llu exceeds volume capacity (%llu sectors).\n",
                (unsigned long long)lba, (unsigned long long)max_lba);
        denyfs_vol_close(vol);
        return 1;
    }

    uint64_t offset = vol->vol_start_offset + (lba * SECTOR_SIZE);
    fseek(vol->fp, (long)offset, SEEK_SET);

    uint8_t cipher[SECTOR_SIZE];
    if (fread(cipher, 1, SECTOR_SIZE, vol->fp) != SECTOR_SIZE) {
        fprintf(stderr, "Error: Failed to read sector.\n");
        denyfs_vol_close(vol);
        return 1;
    }

    uint8_t plain[SECTOR_SIZE];
    if (denyfs_crypt_sector(cipher, plain, lba, vol->volume_key, 0) != 0) {
        fprintf(stderr, "Error: Sector decryption failed.\n");
        denyfs_vol_close(vol);
        return 1;
    }

    FILE *of = fopen(out_file, "wb");
    if (!of) { perror("Error opening output file"); sodium_memzero(plain, sizeof(plain));
               denyfs_vol_close(vol); return 1; }
    fwrite(plain, 1, SECTOR_SIZE, of);
    fclose(of);

    sodium_memzero(plain, sizeof(plain));
    denyfs_vol_close(vol);
    printf("Sector %llu read successfully.\n", (unsigned long long)lba);
    return 0;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main(int argc, char **argv) {
    // Disable core dumps at process start
    struct rlimit lim;
    lim.rlim_cur = 0;
    lim.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &lim);

    if (denyfs_crypto_init() != 0) {
        fprintf(stderr, "Error: Cryptographic library initialization failed.\n");
        return 1;
    }

    if (argc < 2) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s create <path> --size <mb> --password <pass>\n", argv[0]);
        fprintf(stderr, "  %s create-hidden <path> --password <outer_pass> --hidden-password <hidden_pass> --size <mb>\n", argv[0]);
        fprintf(stderr, "  %s open <path> --password <pass> [--protect-hidden] [--hidden-password <hidden_pass>]\n", argv[0]);
        fprintf(stderr, "  %s mount <path> --password <pass> --mountpoint <dir> [--protect-hidden] [--hidden-password <hidden_pass>]\n", argv[0]);
        fprintf(stderr, "  %s write-sector <path> --password <pass> --lba <n> --data <file>\n", argv[0]);
        fprintf(stderr, "  %s read-sector <path> --password <pass> --lba <n> --output <file>\n", argv[0]);
        return 1;
    }

    const char *command = argv[1];

    if (strcmp(command, "create") == 0) {
        if (argc < 7) { fprintf(stderr, "Error: Missing arguments for 'create'.\n"); return 1; }
        const char *path = argv[2];
        uint64_t size_mb = 0;
        char *raw_pass = NULL;
        size_t pass_len = 0;

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--size") == 0 && i + 1 < argc)
                size_mb = strtoull(argv[i+1], NULL, 10);
            else if (strcmp(argv[i], "--password") == 0 && i + 1 < argc)
                raw_pass = secure_dup_password(argv[i+1], &pass_len);
        }
        if (size_mb == 0 || !raw_pass) {
            fprintf(stderr, "Error: Invalid size or missing password.\n");
            secure_cleanup_buffer(raw_pass, pass_len); return 1;
        }
        int ret = handle_create(path, size_mb, raw_pass, pass_len);
        secure_cleanup_buffer(raw_pass, pass_len);
        denyfs_crypto_cleanup();
        return ret;

    } else if (strcmp(command, "create-hidden") == 0) {
        if (argc < 9) { fprintf(stderr, "Error: Missing arguments for 'create-hidden'.\n"); return 1; }
        const char *path = argv[2];
        char *outer_pass = NULL;
        size_t outer_pass_len = 0;
        char *hidden_pass = NULL;
        size_t hidden_pass_len = 0;
        uint64_t size_mb = 0;

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--password") == 0 && i + 1 < argc)
                outer_pass = secure_dup_password(argv[i+1], &outer_pass_len);
            else if (strcmp(argv[i], "--hidden-password") == 0 && i + 1 < argc)
                hidden_pass = secure_dup_password(argv[i+1], &hidden_pass_len);
            else if (strcmp(argv[i], "--size") == 0 && i + 1 < argc)
                size_mb = strtoull(argv[i+1], NULL, 10);
        }
        if (!outer_pass || !hidden_pass || size_mb == 0) {
            fprintf(stderr, "Error: Missing size, outer password, or hidden password.\n");
            secure_cleanup_buffer(outer_pass, outer_pass_len);
            secure_cleanup_buffer(hidden_pass, hidden_pass_len);
            return 1;
        }
        int ret = handle_create_hidden(path, outer_pass, outer_pass_len,
                                       hidden_pass, hidden_pass_len, size_mb);
        secure_cleanup_buffer(outer_pass, outer_pass_len);
        secure_cleanup_buffer(hidden_pass, hidden_pass_len);
        denyfs_crypto_cleanup();
        return ret;

    } else if (strcmp(command, "open") == 0) {
        if (argc < 5) { fprintf(stderr, "Error: Missing arguments for 'open'.\n"); return 1; }
        const char *path = argv[2];
        char *raw_pass = NULL;
        size_t pass_len = 0;
        char *hidden_pass = NULL;
        size_t hidden_pass_len = 0;
        int protect_hidden = 0;

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--password") == 0 && i + 1 < argc) {
                raw_pass = secure_dup_password(argv[i+1], &pass_len); i++;
            } else if (strcmp(argv[i], "--hidden-password") == 0 && i + 1 < argc) {
                hidden_pass = secure_dup_password(argv[i+1], &hidden_pass_len); i++;
            } else if (strcmp(argv[i], "--protect-hidden") == 0) {
                protect_hidden = 1;
            }
        }
        if (!raw_pass) { fprintf(stderr, "Error: Missing password.\n"); return 1; }
        int ret = handle_open(path, raw_pass, pass_len, hidden_pass, hidden_pass_len, protect_hidden);
        secure_cleanup_buffer(raw_pass, pass_len);
        secure_cleanup_buffer(hidden_pass, hidden_pass_len);
        denyfs_crypto_cleanup();
        return ret;

    } else if (strcmp(command, "mount") == 0) {
        const char *path = argv[2];
        char *raw_pass = NULL;
        size_t pass_len = 0;
        char *hidden_pass = NULL;
        size_t hidden_pass_len = 0;
        int protect_hidden = 0;
        const char *mount_point = NULL;

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--password") == 0 && i + 1 < argc) {
                raw_pass = secure_dup_password(argv[i+1], &pass_len); i++;
            } else if (strcmp(argv[i], "--hidden-password") == 0 && i + 1 < argc) {
                hidden_pass = secure_dup_password(argv[i+1], &hidden_pass_len); i++;
            } else if (strcmp(argv[i], "--protect-hidden") == 0) {
                protect_hidden = 1;
            } else if (strcmp(argv[i], "--mountpoint") == 0 && i + 1 < argc) {
                mount_point = argv[i+1]; i++;
            }
        }
        if (!raw_pass || !mount_point) {
            fprintf(stderr, "Error: Missing arguments for 'mount'.\n");
            secure_cleanup_buffer(raw_pass, pass_len);
            secure_cleanup_buffer(hidden_pass, hidden_pass_len);
            return 1;
        }
        int ret = handle_mount(path, raw_pass, pass_len, hidden_pass, hidden_pass_len, protect_hidden, mount_point);
        secure_cleanup_buffer(raw_pass, pass_len);
        secure_cleanup_buffer(hidden_pass, hidden_pass_len);
        denyfs_crypto_cleanup();
        return ret;

    } else if (strcmp(command, "write-sector") == 0) {
        const char *path = argv[2];
        char *raw_pass = NULL;
        size_t pass_len = 0;
        uint64_t lba = 0;
        const char *data_file = NULL;
        int have_lba = 0;

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--password") == 0 && i + 1 < argc) {
                raw_pass = secure_dup_password(argv[i+1], &pass_len); i++;
            } else if (strcmp(argv[i], "--lba") == 0 && i + 1 < argc) {
                lba = strtoull(argv[i+1], NULL, 10); have_lba = 1; i++;
            } else if (strcmp(argv[i], "--data") == 0 && i + 1 < argc) {
                data_file = argv[i+1]; i++;
            }
        }
        if (!raw_pass || !have_lba || !data_file) {
            fprintf(stderr, "Error: Missing arguments for 'write-sector'.\n");
            secure_cleanup_buffer(raw_pass, pass_len); return 1;
        }
        int ret = handle_write_sector(path, raw_pass, pass_len, lba, data_file);
        secure_cleanup_buffer(raw_pass, pass_len);
        denyfs_crypto_cleanup();
        return ret;

    } else if (strcmp(command, "read-sector") == 0) {
        const char *path = argv[2];
        char *raw_pass = NULL;
        size_t pass_len = 0;
        uint64_t lba = 0;
        const char *out_file = NULL;
        int have_lba = 0;

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--password") == 0 && i + 1 < argc) {
                raw_pass = secure_dup_password(argv[i+1], &pass_len); i++;
            } else if (strcmp(argv[i], "--lba") == 0 && i + 1 < argc) {
                lba = strtoull(argv[i+1], NULL, 10); have_lba = 1; i++;
            } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
                out_file = argv[i+1]; i++;
            }
        }
        if (!raw_pass || !have_lba || !out_file) {
            fprintf(stderr, "Error: Missing arguments for 'read-sector'.\n");
            secure_cleanup_buffer(raw_pass, pass_len); return 1;
        }
        int ret = handle_read_sector(path, raw_pass, pass_len, lba, out_file);
        secure_cleanup_buffer(raw_pass, pass_len);
        denyfs_crypto_cleanup();
        return ret;

    } else {
        fprintf(stderr, "Error: Unknown command '%s'\n", command);
        return 1;
    }
}
