#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <math.h>
#include <sodium.h>
#include "crypto.h"
#include "fs.h"

#define TIMING_TRIALS 50
#define CONTAINER_SIZE_MB 6

// Helper to get monotonic time in microseconds
static uint64_t get_time_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

int main(void) {
    if (denyfs_crypto_init() != 0) {
        fprintf(stderr, "[-] Crypto library init failed.\n");
        return 1;
    }

    printf("[*] Running Phase 4 Timing Indistinguishability Tests...\n");

    const char *img_outer_only = "timing_outer_only.img";
    const char *img_both = "timing_both.img";
    const char *outer_pass = "outer_pass_123456";
    const char *hidden_pass = "hidden_pass_123456";
    const char *wrong_pass = "wrong_password_attempt";

    // 1. Create container 1: outer only
    printf("[*] Creating outer-only container...\n");
    int res = denyfs_container_create(img_outer_only, CONTAINER_SIZE_MB, outer_pass, strlen(outer_pass));
    assert(res == 0);

    // 2. Create container 2: both outer and hidden
    printf("[*] Creating container with both outer and hidden volumes...\n");
    res = denyfs_container_create(img_both, CONTAINER_SIZE_MB, outer_pass, strlen(outer_pass));
    assert(res == 0);
    res = denyfs_container_create_hidden(img_both, outer_pass, strlen(outer_pass), hidden_pass, strlen(hidden_pass), 2);
    assert(res == 0);

    uint64_t times_outer_only[TIMING_TRIALS];
    uint64_t times_both[TIMING_TRIALS];

    // Warm-up iteration to ensure code is page-cached
    denyfs_volume_t *vol_warmup = denyfs_vol_open(img_outer_only, wrong_pass, strlen(wrong_pass), NULL, 0, 0);
    if (vol_warmup) denyfs_vol_close(vol_warmup);

    // 3. Measure outer-only timing
    printf("[*] Measuring timing on outer-only container (wrong password)...\n");
    for (int i = 0; i < TIMING_TRIALS; i++) {
        uint64_t start = get_time_us();
        denyfs_volume_t *vol = denyfs_vol_open(img_outer_only, wrong_pass, strlen(wrong_pass), NULL, 0, 0);
        uint64_t end = get_time_us();
        
        // Assert that decryption failed
        assert(vol == NULL);
        times_outer_only[i] = end - start;
    }

    // 4. Measure both timing
    printf("[*] Measuring timing on container with hidden volume (wrong password)...\n");
    for (int i = 0; i < TIMING_TRIALS; i++) {
        uint64_t start = get_time_us();
        denyfs_volume_t *vol = denyfs_vol_open(img_both, wrong_pass, strlen(wrong_pass), NULL, 0, 0);
        uint64_t end = get_time_us();
        
        // Assert that decryption failed
        assert(vol == NULL);
        times_both[i] = end - start;
    }

    // 5. Calculate statistics
    double sum_outer_only = 0, sum_both = 0;
    for (int i = 0; i < TIMING_TRIALS; i++) {
        sum_outer_only += (double)times_outer_only[i];
        sum_both += (double)times_both[i];
    }
    double mean_outer_only = sum_outer_only / TIMING_TRIALS;
    double mean_both = sum_both / TIMING_TRIALS;

    double sq_sum_outer_only = 0, sq_sum_both = 0;
    for (int i = 0; i < TIMING_TRIALS; i++) {
        sq_sum_outer_only += ((double)times_outer_only[i] - mean_outer_only) * ((double)times_outer_only[i] - mean_outer_only);
        sq_sum_both += ((double)times_both[i] - mean_both) * ((double)times_both[i] - mean_both);
    }
    double stddev_outer_only = sqrt(sq_sum_outer_only / TIMING_TRIALS);
    double stddev_both = sqrt(sq_sum_both / TIMING_TRIALS);

    printf("\n--- TIMING STATISTICS ---\n");
    printf("Outer-only container (mean): %.2f ms (stddev: %.2f ms)\n", mean_outer_only / 1000.0, stddev_outer_only / 1000.0);
    printf("Container with hidden (mean): %.2f ms (stddev: %.2f ms)\n", mean_both / 1000.0, stddev_both / 1000.0);

    double diff_ms = fabs(mean_outer_only - mean_both) / 1000.0;
    printf("Absolute difference in mean: %.4f ms\n", diff_ms);

    // Assert timing difference is negligible (e.g., < 15ms)
    // KDF itself takes ~250ms per run, running 2 KDFs takes ~500ms.
    // The timing difference between the presence/absence of a hidden volume should be less than 15ms.
    assert(diff_ms < 15.0);
    printf("[+] Timing side-channel verification PASSED. Timing difference is within limits.\n");

    // Cleanup
    remove(img_outer_only);
    remove(img_both);

    denyfs_crypto_cleanup();
    return 0;
}
