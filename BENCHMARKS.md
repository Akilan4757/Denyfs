# DenyFS — Performance Benchmarks

Phase 7 deliverable. All measurements taken on the system described below with the `test_bench` binary compiled at `-O2` without AddressSanitizer (ASan adds ~2× overhead and distorts timing).

---

## Test Environment

| Parameter | Value |
|---|---|
| Kernel | Linux 6.6.114.1-microsoft-standard-WSL2 x86_64 |
| Compiler | gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0 |
| Optimization | `-O2` |
| libsodium | System package (Ubuntu 26.04) |
| OpenSSL | System package (Ubuntu 26.04) |
| Container size | 10 MB |
| Sector size | 4096 bytes |
| Trials per benchmark | 5 |

---

## 1. Argon2id KDF (Isolated)

**Parameters:** `opslimit = 4`, `memlimit = 64 MB`, algorithm = Argon2id 1.3

| Metric | Value |
|---|---|
| Mean | 200.87 ms |
| Best | 185.73 ms |
| Worst | 231.61 ms |
| VmPeak | 75,856 KB (~74.1 MB) |

**Analysis:** VmPeak of ~74 MB is consistent with the configured 64 MB Argon2id memlimit plus process overhead (~10 MB baseline). The ~200ms per KDF call is the intentional cost of memory-hard key derivation — this is the memory-hardness working as designed, not a performance bug.

---

## 2. Raw AES-256-XTS Throughput (No I/O)

Pure cryptographic throughput without filesystem or disk I/O overhead.

| Operation | Sectors | Data | Time | Throughput |
|---|---|---|---|---|
| Encrypt | 10,000 | 39.1 MB | 19.45 ms | **2,007.85 MB/s** |
| Decrypt | 10,000 | 39.1 MB | 16.26 ms | **2,402.03 MB/s** |

**Analysis:** AES-NI hardware acceleration delivers multi-GB/s throughput. XTS is not the bottleneck in any DenyFS operation — I/O and KDF dominate.

---

## 3. Container Creation

**Container size:** 10 MB

| Metric | Value |
|---|---|
| Mean | 464.93 ms |
| Best | 437.99 ms |
| Worst | 479.32 ms |

**Breakdown (approximate):**
- CSPRNG fill (10 MB of `randombytes_buf`): ~180–200 ms
- Argon2id KDF: ~200 ms
- AES-256-GCM header encrypt: < 1 ms
- Filesystem format (superblock + bitmap + inode table XTS encrypt): < 5 ms
- Disk I/O (write 10 MB): ~60–80 ms

**Analysis:** Creation time scales linearly with container size due to the CSPRNG fill requirement. A 100 MB container would take ~4–5 seconds. The CSPRNG fill is a security requirement (all non-file bytes must be indistinguishable from random), not an optimization target.

---

## 4. Volume Open (Mount) Time

**Argon2id parameters:** `opslimit = 4`, `memlimit = 64 MB`

| Metric | Value |
|---|---|
| Mean | 403.34 ms |
| Best | 394.18 ms |
| Worst | 421.14 ms |
| VmPeak | 76,352 KB (~74.6 MB) |
| VmRSS (pre-mount) | 7,368 KB |
| VmRSS (post-close) | 7,388 KB |

**Analysis:** `vol_open` runs **two** Argon2id KDF calls unconditionally (one for the outer header salt, one for the hidden header salt) as part of the timing indistinguishability mechanism from Phase 4. This doubles the KDF cost (~200ms × 2 = ~400ms) but is non-negotiable — it prevents an observer from determining whether a hidden volume exists by timing the open operation.

VmPeak of ~74.6 MB indicates libsodium reuses its internal Argon2id buffer across the two sequential calls rather than allocating twice. VmRSS returns to baseline after close, confirming no key material leaks into long-lived allocations.

---

## 5. Sequential Write Throughput (Encrypted, with I/O)

**Operation:** Write 96 KB (24 × 4096-byte sectors) to a single file, one sector at a time.

| Metric | Value |
|---|---|
| Mean | 1.81 MB/s |
| Best | 1.84 MB/s |
| Worst | 1.75 MB/s |

**Analysis:** Write throughput is dominated by the read-modify-write cycle per sector (read encrypted block → decrypt → modify → encrypt → write → flush) and `fflush()` after each block write. Each write involves:
1. XTS decrypt of the existing block (~0.002 ms)
2. Memcpy of new data
3. XTS encrypt of the modified block (~0.002 ms)
4. `fwrite` + `fflush` to disk (~2 ms per sector on WSL2)

The `fflush()` per write is a durability/correctness choice — data is committed after each operation. Batch-flushing would increase throughput significantly but risks data loss on crash.

---

## 6. Sequential Read Throughput (Encrypted, with I/O)

**Operation:** Read 96 KB (24 × 4096-byte sectors) from a single file, one sector at a time.

| Metric | Value |
|---|---|
| Mean | 13.09 MB/s |
| Best | 14.22 MB/s |
| Worst | 12.50 MB/s |

**Analysis:** Read throughput is ~7× faster than write because reads don't require `fflush()` or the read-modify-write cycle. Each read involves:
1. `fseek` + `fread` of one encrypted sector
2. XTS decrypt (~0.002 ms)
3. Memcpy to caller buffer

OS page cache effects are visible — sequential reads benefit from readahead.

---

## Summary Table

| Operation | Value | Bottleneck |
|---|---|---|
| Argon2id KDF (single) | ~201 ms | Memory-hard by design |
| Volume open (2× KDF) | ~403 ms | Timing indistinguishability |
| Container create (10 MB) | ~465 ms | CSPRNG fill + KDF |
| Raw XTS encrypt | 2,008 MB/s | Not a bottleneck |
| Raw XTS decrypt | 2,402 MB/s | Not a bottleneck |
| Sequential write (w/ I/O) | 1.81 MB/s | fflush per sector |
| Sequential read (w/ I/O) | 13.09 MB/s | Disk I/O + XTS |
| Peak memory (Argon2id) | ~74.6 MB | Configured: 64 MB + overhead |

---

## Reproducing These Results

```bash
# Build without ASan for accurate timing
make test_bench
# Or explicitly:
cc -Wall -Wextra -O2 -Isrc src/crypto.c src/fs.c tests/test_bench.c -o test_bench -lsodium -lcrypto

# Run
./test_bench
```

Results will vary based on CPU (AES-NI support), disk subsystem (SSD vs HDD, native vs WSL2), and available memory.
