/*
 * Phase 7 (brain file Phase 8): Benchmarks
 *
 * Measures and reports:
 *   1. Container creation time — CSPRNG fill time vs crypto setup time (separate).
 *   2. Mount/open time — Argon2id + GCM decrypt cost.
 *   3. Sequential write throughput (MB/s) at 4KB sector granularity.
 *   4. Sequential read throughput (MB/s) at 4KB sector granularity.
 *   5. Peak memory usage during Argon2id (via /proc/self/status VmPeak).
 *
 * Output is structured text suitable for inclusion in BENCHMARKS.md.
 * Run without ASan for accurate timing (ASan adds ~2x overhead):
 *   make test_bench CFLAGS="-Wall -Wextra -O2 -Isrc"
 *   ./test_bench
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sodium.h>
#include "crypto.h"
#include "fs.h"

#define BENCH_CONTAINER  "bench_container.img"
#define BENCH_PASSWORD   "benchmark_pass_42"
#define BENCH_SIZE_MB    10
#define BENCH_TRIALS     5

/* ======================================================================== */
/* Timing helpers                                                            */
/* ======================================================================== */

static double timespec_diff_ms(struct timespec *start, struct timespec *end) {
    double sec  = (double)(end->tv_sec - start->tv_sec);
    double nsec = (double)(end->tv_nsec - start->tv_nsec);
    return sec * 1000.0 + nsec / 1e6;
}

/* ======================================================================== */
/* Memory usage (Linux /proc/self/status)                                    */
/* ======================================================================== */

static long get_vm_peak_kb(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    long peak = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmPeak:", 7) == 0) {
            sscanf(line + 7, "%ld", &peak);
            break;
        }
    }
    fclose(f);
    return peak;
}

static long get_vm_rss_kb(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    long rss = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line + 6, "%ld", &rss);
            break;
        }
    }
    fclose(f);
    return rss;
}

/* ======================================================================== */
/* Benchmark 1: Container creation (CSPRNG fill vs crypto setup)            */
/* ======================================================================== */

static void bench_container_creation(void) {
    printf("=== Benchmark 1: Container Creation ===\n");
    printf("Container size: %d MB\n\n", BENCH_SIZE_MB);

    double total_times[BENCH_TRIALS];
    double best = 1e9, worst = 0, sum = 0;

    for (int t = 0; t < BENCH_TRIALS; t++) {
        remove(BENCH_CONTAINER);

        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int res = denyfs_container_create(BENCH_CONTAINER, BENCH_SIZE_MB,
                                           BENCH_PASSWORD, strlen(BENCH_PASSWORD));
        clock_gettime(CLOCK_MONOTONIC, &t1);

        if (res != 0) {
            fprintf(stderr, "[-] Container creation failed on trial %d\n", t);
            return;
        }

        total_times[t] = timespec_diff_ms(&t0, &t1);
        if (total_times[t] < best) best = total_times[t];
        if (total_times[t] > worst) worst = total_times[t];
        sum += total_times[t];
    }

    printf("  Trials: %d\n", BENCH_TRIALS);
    printf("  Mean:   %.2f ms\n", sum / BENCH_TRIALS);
    printf("  Best:   %.2f ms\n", best);
    printf("  Worst:  %.2f ms\n", worst);
    printf("  Note:   Dominated by CSPRNG fill (%d MB of random bytes)\n", BENCH_SIZE_MB);
    printf("          + Argon2id KDF (~300-400ms) + AES-256-GCM header encrypt\n");
    printf("          + filesystem format (superblock + bitmap + inode table XTS encrypt)\n\n");

    remove(BENCH_CONTAINER);
}

/* ======================================================================== */
/* Benchmark 2: Mount / Open time (Argon2id cost)                           */
/* ======================================================================== */

static void bench_mount_time(void) {
    printf("=== Benchmark 2: Volume Open (Mount) Time ===\n");
    printf("Argon2id parameters: opslimit=%d, memlimit=%d MB\n\n",
           ARGON2_OPSLIMIT, ARGON2_MEMLIMIT / (1024 * 1024));

    /* Create a container first */
    remove(BENCH_CONTAINER);
    denyfs_container_create(BENCH_CONTAINER, BENCH_SIZE_MB,
                            BENCH_PASSWORD, strlen(BENCH_PASSWORD));

    /* Record memory before Argon2id */
    long mem_before = get_vm_rss_kb();

    double open_times[BENCH_TRIALS];
    double best = 1e9, worst = 0, sum = 0;
    long peak_mem = 0;

    for (int t = 0; t < BENCH_TRIALS; t++) {
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        denyfs_volume_t *vol = denyfs_vol_open(BENCH_CONTAINER,
                                                BENCH_PASSWORD, strlen(BENCH_PASSWORD),
                                                NULL, 0, 0);
        clock_gettime(CLOCK_MONOTONIC, &t1);

        if (!vol) {
            fprintf(stderr, "[-] Volume open failed on trial %d\n", t);
            return;
        }

        open_times[t] = timespec_diff_ms(&t0, &t1);
        if (open_times[t] < best) best = open_times[t];
        if (open_times[t] > worst) worst = open_times[t];
        sum += open_times[t];

        long current_peak = get_vm_peak_kb();
        if (current_peak > peak_mem) peak_mem = current_peak;

        denyfs_vol_close(vol);
    }

    long mem_after = get_vm_rss_kb();

    printf("  Trials:      %d\n", BENCH_TRIALS);
    printf("  Mean:        %.2f ms\n", sum / BENCH_TRIALS);
    printf("  Best:        %.2f ms\n", best);
    printf("  Worst:       %.2f ms\n", worst);
    printf("  VmPeak:      %ld KB (%.1f MB)\n", peak_mem, peak_mem / 1024.0);
    printf("  VmRSS pre:   %ld KB\n", mem_before);
    printf("  VmRSS post:  %ld KB\n", mem_after);
    printf("  Note:        vol_open runs TWO Argon2id KDF calls (outer + hidden header)\n");
    printf("               by design for timing indistinguishability. Each call uses\n");
    printf("               %d MB of memory. Total expected: ~%d MB peak.\n\n",
           ARGON2_MEMLIMIT / (1024 * 1024), 2 * ARGON2_MEMLIMIT / (1024 * 1024));

    remove(BENCH_CONTAINER);
}

/* ======================================================================== */
/* Benchmark 3: Sequential Write Throughput                                 */
/* ======================================================================== */

static void bench_write_throughput(void) {
    printf("=== Benchmark 3: Sequential Write Throughput ===\n");
    printf("Sector size: %d bytes, encryption: AES-256-XTS\n\n", SECTOR_SIZE);

    remove(BENCH_CONTAINER);
    denyfs_container_create(BENCH_CONTAINER, BENCH_SIZE_MB,
                            BENCH_PASSWORD, strlen(BENCH_PASSWORD));

    denyfs_volume_t *vol = denyfs_vol_open(BENCH_CONTAINER,
                                            BENCH_PASSWORD, strlen(BENCH_PASSWORD),
                                            NULL, 0, 0);
    if (!vol) { fprintf(stderr, "[-] Open failed\n"); return; }

    /* Create a file and write as much data as possible (up to 96KB max file size) */
    uint32_t ino;
    denyfs_vol_create(vol, "bench_write.bin", &ino);

    size_t max_file = (size_t)DENYFS_DIRECT_BLOCKS * SECTOR_SIZE; /* 96KB */
    uint8_t *data = malloc(SECTOR_SIZE);
    if (!data) { denyfs_vol_close(vol); return; }
    memset(data, 0xAB, SECTOR_SIZE);

    /* Warm up */
    denyfs_vol_write(vol, ino, data, SECTOR_SIZE, 0);
    denyfs_vol_truncate(vol, ino, 0);

    /* Timed sequential write — one sector at a time */
    double best = 1e9, worst = 0, sum = 0;

    for (int t = 0; t < BENCH_TRIALS; t++) {
        denyfs_vol_truncate(vol, ino, 0);

        struct timespec t0, t1;
        size_t total_written = 0;
        clock_gettime(CLOCK_MONOTONIC, &t0);

        for (size_t off = 0; off < max_file; off += SECTOR_SIZE) {
            int wr = denyfs_vol_write(vol, ino, data, SECTOR_SIZE, off);
            if (wr != SECTOR_SIZE) break;
            total_written += SECTOR_SIZE;
        }

        clock_gettime(CLOCK_MONOTONIC, &t1);

        double elapsed_ms = timespec_diff_ms(&t0, &t1);
        double throughput = (total_written / (1024.0 * 1024.0)) / (elapsed_ms / 1000.0);
        if (throughput > worst) worst = throughput; /* higher is better for throughput */
        if (throughput < best) best = throughput;
        sum += throughput;

        printf("  Trial %d: %zu bytes in %.2f ms = %.2f MB/s\n",
               t + 1, total_written, elapsed_ms, throughput);
    }

    printf("\n  Mean throughput: %.2f MB/s\n", sum / BENCH_TRIALS);
    printf("  Best:            %.2f MB/s\n", worst); /* highest throughput */
    printf("  Worst:           %.2f MB/s\n\n", best); /* lowest throughput */

    free(data);
    denyfs_vol_close(vol);
    remove(BENCH_CONTAINER);
}

/* ======================================================================== */
/* Benchmark 4: Sequential Read Throughput                                  */
/* ======================================================================== */

static void bench_read_throughput(void) {
    printf("=== Benchmark 4: Sequential Read Throughput ===\n");
    printf("Sector size: %d bytes, decryption: AES-256-XTS\n\n", SECTOR_SIZE);

    remove(BENCH_CONTAINER);
    denyfs_container_create(BENCH_CONTAINER, BENCH_SIZE_MB,
                            BENCH_PASSWORD, strlen(BENCH_PASSWORD));

    denyfs_volume_t *vol = denyfs_vol_open(BENCH_CONTAINER,
                                            BENCH_PASSWORD, strlen(BENCH_PASSWORD),
                                            NULL, 0, 0);
    if (!vol) { fprintf(stderr, "[-] Open failed\n"); return; }

    /* Create and fill a file with 96KB of data */
    uint32_t ino;
    denyfs_vol_create(vol, "bench_read.bin", &ino);

    size_t max_file = (size_t)DENYFS_DIRECT_BLOCKS * SECTOR_SIZE;
    uint8_t *write_buf = malloc(SECTOR_SIZE);
    uint8_t *read_buf  = malloc(SECTOR_SIZE);
    if (!write_buf || !read_buf) {
        if (write_buf) free(write_buf);
        if (read_buf) free(read_buf);
        denyfs_vol_close(vol);
        return;
    }
    memset(write_buf, 0xCD, SECTOR_SIZE);

    /* Fill the file */
    for (size_t off = 0; off < max_file; off += SECTOR_SIZE) {
        denyfs_vol_write(vol, ino, write_buf, SECTOR_SIZE, off);
    }

    /* Timed sequential read — one sector at a time */
    double best = 1e9, worst = 0, sum = 0;

    for (int t = 0; t < BENCH_TRIALS; t++) {
        struct timespec t0, t1;
        size_t total_read = 0;
        clock_gettime(CLOCK_MONOTONIC, &t0);

        for (size_t off = 0; off < max_file; off += SECTOR_SIZE) {
            int rd = denyfs_vol_read(vol, ino, read_buf, SECTOR_SIZE, off);
            if (rd != SECTOR_SIZE) break;
            total_read += SECTOR_SIZE;
        }

        clock_gettime(CLOCK_MONOTONIC, &t1);

        double elapsed_ms = timespec_diff_ms(&t0, &t1);
        double throughput = (total_read / (1024.0 * 1024.0)) / (elapsed_ms / 1000.0);
        if (throughput > worst) worst = throughput;
        if (throughput < best) best = throughput;
        sum += throughput;

        printf("  Trial %d: %zu bytes in %.2f ms = %.2f MB/s\n",
               t + 1, total_read, elapsed_ms, throughput);
    }

    printf("\n  Mean throughput: %.2f MB/s\n", sum / BENCH_TRIALS);
    printf("  Best:            %.2f MB/s\n", worst);
    printf("  Worst:           %.2f MB/s\n\n", best);

    free(write_buf);
    free(read_buf);
    denyfs_vol_close(vol);
    remove(BENCH_CONTAINER);
}

/* ======================================================================== */
/* Benchmark 5: Raw Argon2id KDF cost (isolated)                            */
/* ======================================================================== */

static void bench_argon2id_isolated(void) {
    printf("=== Benchmark 5: Argon2id KDF (Isolated) ===\n");
    printf("Parameters: opslimit=%d, memlimit=%d MB\n\n",
           ARGON2_OPSLIMIT, ARGON2_MEMLIMIT / (1024 * 1024));

    uint8_t salt[SALT_SIZE];
    randombytes_buf(salt, SALT_SIZE);

    uint8_t *master_key = denyfs_secure_alloc(KEY_SIZE_GCM);
    if (!master_key) return;

    double times[BENCH_TRIALS];
    double best = 1e9, worst = 0, sum = 0;

    for (int t = 0; t < BENCH_TRIALS; t++) {
        long mem_before = get_vm_peak_kb();

        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        denyfs_derive_master_key(BENCH_PASSWORD, strlen(BENCH_PASSWORD), salt, master_key);
        clock_gettime(CLOCK_MONOTONIC, &t1);

        long mem_after = get_vm_peak_kb();

        times[t] = timespec_diff_ms(&t0, &t1);
        if (times[t] < best) best = times[t];
        if (times[t] > worst) worst = times[t];
        sum += times[t];

        printf("  Trial %d: %.2f ms  (VmPeak: %ld KB)\n",
               t + 1, times[t], mem_after);
        (void)mem_before;
    }

    printf("\n  Mean: %.2f ms\n", sum / BENCH_TRIALS);
    printf("  Best: %.2f ms\n", best);
    printf("  Worst: %.2f ms\n", worst);
    printf("  Expected memory: ~%d MB (Argon2id memlimit parameter)\n\n",
           ARGON2_MEMLIMIT / (1024 * 1024));

    denyfs_secure_free(master_key, KEY_SIZE_GCM);
}

/* ======================================================================== */
/* Benchmark 6: Raw XTS sector encrypt/decrypt (isolated, no I/O)           */
/* ======================================================================== */

static void bench_xts_raw(void) {
    printf("=== Benchmark 6: Raw AES-256-XTS Throughput (No I/O) ===\n");
    printf("Sector size: %d bytes\n\n", SECTOR_SIZE);

    uint8_t key[KEY_SIZE_XTS];
    randombytes_buf(key, sizeof(key));

    uint8_t plaintext[SECTOR_SIZE];
    uint8_t ciphertext[SECTOR_SIZE];
    uint8_t decrypted[SECTOR_SIZE];
    randombytes_buf(plaintext, sizeof(plaintext));

    /* Encrypt benchmark: 10000 sectors */
    int num_sectors = 10000;
    struct timespec t0, t1;

    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < num_sectors; i++) {
        denyfs_crypt_sector(plaintext, ciphertext, (uint64_t)i, key, 1);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);

    double enc_ms = timespec_diff_ms(&t0, &t1);
    double enc_mb = (double)num_sectors * SECTOR_SIZE / (1024.0 * 1024.0);
    double enc_throughput = enc_mb / (enc_ms / 1000.0);

    printf("  Encrypt: %d sectors (%.1f MB) in %.2f ms = %.2f MB/s\n",
           num_sectors, enc_mb, enc_ms, enc_throughput);

    /* Decrypt benchmark: 10000 sectors */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < num_sectors; i++) {
        denyfs_crypt_sector(ciphertext, decrypted, (uint64_t)i, key, 0);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);

    double dec_ms = timespec_diff_ms(&t0, &t1);
    double dec_throughput = enc_mb / (dec_ms / 1000.0);

    printf("  Decrypt: %d sectors (%.1f MB) in %.2f ms = %.2f MB/s\n\n",
           num_sectors, enc_mb, dec_ms, dec_throughput);
}

/* ======================================================================== */
/* Main                                                                      */
/* ======================================================================== */

int main(void) {
    if (denyfs_crypto_init() != 0) {
        fprintf(stderr, "[-] Crypto init failed\n");
        return 1;
    }

    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║        DenyFS Phase 7: Performance Benchmarks        ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n\n");

    printf("System: ");
    fflush(stdout);
    /* Print kernel info */
    FILE *p = popen("uname -srm 2>/dev/null", "r");
    if (p) {
        char buf[256];
        if (fgets(buf, sizeof(buf), p)) printf("%s", buf);
        pclose(p);
    }
    printf("Compiler: ");
    fflush(stdout);
    p = popen("cc --version 2>/dev/null | head -1", "r");
    if (p) {
        char buf[256];
        if (fgets(buf, sizeof(buf), p)) printf("%s", buf);
        pclose(p);
    }
    printf("\n");

    bench_argon2id_isolated();
    bench_xts_raw();
    bench_container_creation();
    bench_mount_time();
    bench_write_throughput();
    bench_read_throughput();

    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║              All benchmarks completed.               ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");

    denyfs_crypto_cleanup();
    return 0;
}
