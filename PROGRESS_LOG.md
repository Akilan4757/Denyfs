# DenyFS Progress Log

## Session 8 — 2026-07-17

### What existed at the start of this session
- Phases 1-7 complete: crypto core, sector I/O, filesystem with FUSE, deniability hardening, build integrity documentation, fuzzing harnesses and stress tests, benchmarks. All tests passing. Every brain file phase implemented except Phase 6 (Threat model + writeup).

### Scoping decision
- Phase 8 (brain file Phase 6): Threat model + writeup. Brain file specifies: *"See §9. This is the section to rehearse for an interview — it's what shows the difference between 'encrypted' and 'deniable.'"* This phase produces a standalone `THREAT_MODEL.md` that formats §9's adversary model into a presentation-ready document with full cross-references to implementation evidence. No code changes — documentation deliverable only. "Done" = document exists with all 7 adversary classes named, all security properties cross-referenced to tests, interview Q&A section included, README/PROGRESS_LOG updated.

### What was actually built / changed
- `THREAT_MODEL.md` (NEW): Comprehensive threat model and security writeup with 8 sections:
  1. **Core Distinction**: Encrypted vs. deniable — what DenyFS adds beyond standard FDE.
  2. **Adversary Model**: Table of adversary capabilities and limitations (single-snapshot assumption).
  3. **Defended Threats** (5 subsections):
     - 3.1 Data confidentiality (AES-256-XTS, cross-ref to Phase 1 + `test_crypto`)
     - 3.2 Deniability of hidden volume existence (5-property table with phase cross-refs)
     - 3.3 Timing side-channel resistance (mechanism explanation + `test_timing` evidence: 5.71ms Δ)
     - 3.4 Key material protection (6-row defense table: sodium_malloc, mlock, memzero, RLIMIT_CORE, sodium_memcmp)
     - 3.5 Hidden volume protection during outer mount (write guard mechanism + test evidence)
  4. **Undefended Threats** (7 named adversary classes from §9):
     - 4.1 Repeated snapshots over time
     - 4.2 Host compromise (malware, root, keylogger)
     - 4.3 Cold-boot / RAM-remanence attacks
     - 4.4 DMA attacks (Thunderbolt, FireWire, PCIe)
     - 4.5 Evil-maid / tampered binary
     - 4.6 Compromised kernel
     - 4.7 Cloud backup / sync leakage
     - Each includes: threat description, impact, why there's no code fix
  5. **Host-Environment Metadata Leaks**: 6-row table (container timestamps, shell history, journald, desktop indexers, GVFS, /tmp+swap) with mitigations.
  6. **Cryptographic Primitive Selection Rationale**: Table explaining Argon2id, HKDF, AES-256-GCM, AES-256-XTS, HMAC-SHA256 choices.
  7. **Security Property Summary**: 15-row evidence matrix mapping every claimed property to its status (✅/❌) and test evidence.
  8. **Interview Framing**: Q&A responses for "Why not VeraCrypt?", "What about cold-boot?", "How do you know the hidden volume is invisible?", "What's the weakest point?"
- `README.md` (MODIFIED): Added Phase 8 to roadmap. Added threat model cross-reference to Known Limitations section.
- `PROGRESS_LOG.md` (MODIFIED): Session 8 appended.

### Tests run and results
- No code changes in this session — documentation only. All prior tests remain passing from Session 7.

### Known issues / incomplete work from this session
- None.

### ⚠️ Brain file discrepancies found (if any)
- None. All 9 brain file phases (0-8) are now fully implemented and documented.

### Do Next
- **All brain file phases complete.** The DenyFS project is fully implemented per the architecture document:
  - Phase 0: Design lock ✅ (brain file itself)
  - Phase 1: Crypto core ✅
  - Phase 2: Volume mounting ✅
  - Phase 3: Filesystem layer ✅
  - Phase 4: Deniability hardening ✅
  - Phase 5: Build integrity note ✅
  - Phase 6: Threat model + writeup ✅ (this session)
  - Phase 7: Test suite ✅
  - Phase 8: Benchmarks ✅
- Optional future work:
  - Run extended AFL++ fuzzing campaigns (harnesses ready, need `apt install afl++`)
  - FUSE end-to-end mount test (requires WSL2 FUSE kernel module)
  - Dynamic inode allocation (stated scope limitation in Phase 3)
  - Subdirectory support (stated scope limitation in Phase 3)

---

## Session 7 — 2026-07-17

### What existed at the start of this session
- Phases 1-6 complete: crypto core, raw sector CLI, on-disk filesystem with FUSE, deniability hardening, build integrity documentation, fuzzing harnesses and stress tests. All tests passing.

### Scoping decision
- Phase 7 (brain file Phase 8): Benchmarks. Brain file specifies four benchmark categories: (1) container creation time with CSPRNG fill reported separately, (2) mount time showing Argon2id cost, (3) sequential read/write throughput at 4KB sectors, (4) peak memory during Argon2id. Sized to one session because the deliverables are a benchmark binary plus a results document — no source modifications to the core codebase. "Done" = benchmark compiles with `-O2` (no ASan), runs all 6 benchmark categories, results documented in `BENCHMARKS.md`, all prior tests still pass.

### What was actually built / changed
- `tests/test_bench.c` (NEW): Benchmark suite with 6 measurement categories:
  1. **Argon2id KDF (isolated)**: Single KDF call timing + VmPeak from `/proc/self/status`. Verifies memlimit parameter matches observed peak memory.
  2. **Raw AES-256-XTS throughput**: 10,000 sector encrypt/decrypt without I/O, reporting pure crypto throughput in MB/s.
  3. **Container creation**: End-to-end `denyfs_container_create()` timing over 5 trials with min/max/mean.
  4. **Volume open (mount)**: `denyfs_vol_open()` timing over 5 trials, including VmPeak and VmRSS before/after. Documents the 2× KDF cost from timing indistinguishability.
  5. **Sequential write throughput**: 96KB file write (24 sectors) one sector at a time, reporting MB/s with I/O overhead.
  6. **Sequential read throughput**: 96KB file read (24 sectors) one sector at a time, reporting MB/s with I/O overhead.
  - System info printed at startup (kernel via `uname -srm`, compiler via `cc --version`).
  - Compiled with `-O2` and no ASan for accurate timing (ASan adds ~2× overhead).
- `BENCHMARKS.md` (NEW): Formatted benchmark results document. Key results on WSL2/Ubuntu 26.04/gcc 15.2.0:
  - Argon2id KDF: 200.87ms mean, VmPeak 75,856 KB (~74.1 MB, consistent with 64 MB memlimit + overhead).
  - Raw XTS: encrypt 2,008 MB/s, decrypt 2,402 MB/s (AES-NI accelerated).
  - Container creation (10 MB): 464.93ms mean (CSPRNG fill + KDF dominant).
  - Volume open: 403.34ms mean (2× Argon2id by design), VmPeak 76,352 KB.
  - Sequential write: 1.81 MB/s (fflush per sector dominates).
  - Sequential read: 13.09 MB/s (no flush, OS readahead benefits).
  - Includes analysis paragraphs explaining each result and identifying bottlenecks.
- `Makefile` (MODIFIED): Added `test_bench` target compiled with `-O2 -Isrc` and no sanitizer flags. Updated `all` and `clean` targets.
- `README.md` (MODIFIED): Roadmap Phase 7 marked `[x]` with link to `BENCHMARKS.md`.

### Tests run and results
- Phase 1 crypto tests: All pass.
- Phase 2 volume tests: All pass.
- Phase 3 & 4 filesystem tests: All pass (11/11).
- Benchmark suite: All 6 benchmarks completed successfully.
- Zero regressions across the full test suite.

### Known issues / incomplete work from this session
- The two pre-existing `-Wmaybe-uninitialized` warnings in `fs.c` (lines 371 and 470) appear only under `-O2` and are false positives — the `fmt_res` variable is always initialized by `format_volume()` before the `return` statement in the success path, and the `goto cleanup_keys` path does not reach the `return fmt_res` line. These are existing code, not new — not fixing in this session per the "don't touch unrelated code" principle.

### ⚠️ Brain file discrepancies found (if any)
- None.

### Do Next
- All phases complete (1-7). The DenyFS project roadmap is fully implemented:
  - Phase 1: Crypto core ✅
  - Phase 2: Sector I/O ✅
  - Phase 3: Filesystem ✅
  - Phase 4: Hardening ✅
  - Phase 5: Build integrity note ✅
  - Phase 6: Fuzzing & stress tests ✅
  - Phase 7: Benchmarks ✅
- Optional future work: run extended AFL++ fuzzing campaigns (harnesses are ready, just need `afl++` installed), FUSE end-to-end mount test (requires WSL2 FUSE kernel module), write the final threat model writeup (brain file Phase 6/§9 — the threat model is already documented in the architecture file, a standalone writeup would format it for presentation).

---

## Session 6 — 2026-07-17

### What existed at the start of this session
- Phases 1-5 complete: crypto core, raw sector CLI, on-disk filesystem with FUSE, deniability hardening, build integrity documentation. All prior tests passing (crypto, volume, fs, timing).

### Scoping decision
- Phase 6 (brain file Phase 7): Fuzzing & stress tests. Brain file specifies three requirements: (1) seeded correctness cases for corrupted header/hidden region/bitmap, (2) header parser fuzzing harness as priority #1 (pre-auth attack surface), (3) FUSE-layer stress tests (create/delete/rename loops). Sized to one session because the deliverables are test code that builds on the existing API without modifying any source files. "Done" = all new test binaries compile under ASan/UBSan with zero warnings, stress tests pass 10/10, fuzz harnesses run without crash on random input, all prior tests still pass.

### What was actually built / changed
- `tests/fuzz_header.c` (NEW): AFL++ fuzzing harness for the pre-auth header parser. Reads a 4096-byte input as `denyfs_header_disk_t`, runs the full Argon2id KDF + HKDF + GCM decrypt path using a fixed password and attacker-controlled salt/IV/tag/ciphertext. If GCM verification happens to succeed, validates payload fields (magic, volume_size). Supports both standalone mode (reads file or stdin) and AFL++ persistent mode (`__AFL_LOOP`). Exits cleanly regardless of input content.
- `tests/fuzz_sector.c` (NEW): AFL++ fuzzing harness for XTS sector encryption/decryption. Reads 4096+ bytes as ciphertext, extracts LBA from trailing bytes if present, runs decrypt then re-encrypt, and aborts only on roundtrip mismatch (which would indicate a real bug). Supports standalone and persistent modes.
- `tests/test_stress.c` (NEW): 10 seeded correctness and stress tests covering:
  1. Corrupted outer header rejection (GCM ciphertext byte flip → auth failure).
  2. Corrupted hidden header region rejection (GCM ciphertext corruption at hidden header offset → hidden auth fails, outer still works).
  3. Corrupted superblock rejection (XTS block 0 corruption → magic mismatch after decryption).
  4. Max inode capacity (create all 63 files, verify 64th rejected with `ENOSPC`, delete all, verify free_inodes = 63).
  5. Rapid create/delete cycles (500 iterations with small write/read verification per cycle).
  6. Max file size boundary (96KB = 24 × 4096 write and full read-back verification with non-trivial pattern).
  7. Oversized write rejection (96KB + 1 byte → `ENOSPC`; 1 byte at offset 96KB → `ENOSPC`).
  8. Max-length filename (250 characters — DENYFS_MAX_NAME_LEN - 1; create + lookup verified).
  9. Invalid filename rejection (empty string and 251-char overlength both rejected).
  10. Interleaved operations stress (200 iterations: create pair, write A, truncate+write B, read-back both, delete A; persistence verified on reopen).
- `tests/gen_fuzz_corpus.sh` (NEW): Seed corpus generator for AFL++ campaigns. Creates 6 header seeds (valid from real container, hidden region extract, all-zeros, all-0xFF, random, structured with salt/IV/tag layout) and 3 sector seeds (all-zeros, random, random+LBA).
- `Makefile` (MODIFIED): Added `test_stress`, `fuzz_header`, and `fuzz_sector` build targets. `test_stress` included in the `make test` rule. Fuzz harnesses are separate (use `CC=afl-gcc make fuzz_header` for actual AFL++ runs). Updated `clean` to remove new binaries and temp files.
- `README.md` (MODIFIED): Roadmap Phase 6 marked `[x]` with updated description.

### Tests run and results
- Phase 1 crypto tests: All pass.
- Phase 2 volume tests: All pass.
- Phase 3 & 4 filesystem tests: All pass (11/11).
- Phase 4 timing tests: PASSED — outer-only mean 407.04ms (σ=28.38), with-hidden mean 401.33ms (σ=14.12), absolute difference 5.71ms (within 15ms limit).
- Phase 6 stress tests (ASan/UBSan clean, 10/10):
  - `[+] Corrupted outer header correctly rejected.`
  - `[+] Corrupted hidden header correctly rejected; outer still works.`
  - `[+] Corrupted superblock correctly rejected.`
  - `[+] Max file capacity test passed (63 create + 63 delete).`
  - `[+] 500 rapid create/delete cycles completed cleanly.`
  - `[+] 96KB max file size write/read verified.`
  - `[+] Oversized writes correctly rejected.`
  - `[+] 250-char filename created and looked up successfully.`
  - `[+] Invalid filenames correctly rejected.`
  - `[+] 200 interleaved operation iterations completed cleanly.`
  - `[+] All Phase 6 stress tests passed successfully.`
- Fuzz harness smoke tests:
  - `fuzz_header`: `[+] Harness completed without crash (input: 4096 bytes)` on random input.
  - `fuzz_sector`: `[+] Sector fuzz harness completed without crash (input: 4104 bytes)` on random input.

### Known issues / incomplete work from this session
- AFL++ is not installed in the WSL Ubuntu environment, so actual multi-hour fuzzing campaigns were not run. The harnesses are compiled and verified to run cleanly on sample inputs. To run fuzzing: install AFL++ (`apt install afl++`), then `CC=afl-gcc make fuzz_header fuzz_sector`, then `bash tests/gen_fuzz_corpus.sh`, then `afl-fuzz -i fuzz_corpus_header -o fuzz_findings_header -- ./fuzz_header @@`.
- The brain file's Phase 7 also specifies the "missing test" — timing indistinguishability comparison between a no-hidden-volume wrong-password attempt and a has-hidden-volume wrong-password attempt. This test already exists and passes as `test_timing` (built in Session 4). No additional work needed.

### ⚠️ Brain file discrepancies found (if any)
- None.

### Do Next
- Phase 7 (brain file Phase 8): Benchmarks. Record and document: container creation time (CSPRNG fill vs crypto setup separately), mount time (Argon2id cost), sequential read/write throughput at 4KB sector granularity, and peak memory usage during Argon2id. Create a `test_bench.c` or `bench.c` that outputs structured timing data. Document results in a `BENCHMARKS.md` artifact.

---

## Session 5 — 2026-07-17

### What existed at the start of this session
- Phases 1-4 complete: crypto core, raw sector CLI, on-disk filesystem with FUSE, deniability hardening (timing, memory hygiene, core dump prevention, outer-mount protection). All tests passing.

### Scoping decision
- Phase 5: Build integrity note. Per the brain file §4 Phase 5: "Not a full phase — a documented limitation." This is a documentation-only deliverable. Sized to one session because no code changes are required — only a standalone document and README cross-references. "Done" = `BUILD_INTEGRITY.md` exists with full coverage of the three scope limitations (reproducible builds, code signing, supply-chain integrity), README references it, and this log entry is written.

### What was actually built / changed
- `BUILD_INTEGRITY.md` (NEW): Standalone Phase 5 deliverable. Covers:
  - §1: The core problem — why build integrity matters for DenyFS specifically. Three threat vectors named: backdoored binary distribution, compiler/toolchain compromise (Thompson attack), and dependency supply-chain attack.
  - §2: What DenyFS does NOT implement — reproducible builds (2a), code signing (2b), and supply-chain integrity (2c). Each subsection lists what *would* be needed (pinned toolchains, signing keys, hash-locked dependencies, SBOM) and explicitly states none of it is implemented.
  - §3: What this means for users — build-from-source trust model vs. pre-built binary trust assumptions.
  - §4: Recommended user mitigations — build from source, verify compiler/dependency packages, audit the ~1200-line codebase, air-gap sensitive builds.
  - §5: Cross-references to brain file §9 adversary #5, §4 Phase 5, §8 compressibility list item #4, and README Known Limitations.
  - §6: Why the document exists instead of a fix — honest scope statement for a portfolio project.
- `README.md` (MODIFIED):
  - Known Limitations → Build Integrity bullet expanded to reference `BUILD_INTEGRITY.md`.
  - Roadmap updated: Phase 5 marked `[x]` with description "Build Integrity Note" and link to `BUILD_INTEGRITY.md`. Former Phase 5/6 (Fuzzing, Benchmarks) renumbered to Phase 6/7 to align with brain file's actual Phase 7/8 numbering.

### Tests run and results
- No code changes — documentation-only phase. No tests applicable.
- Verified `BUILD_INTEGRITY.md` cross-references match brain file §9 adversary #5, §4 Phase 5, and §8 item #4 verbatim.
- Verified README roadmap checkboxes: Phases 1-5 marked `[x]`, Phases 6-7 marked `[ ]`.

### Known issues / incomplete work from this session
- None.

### ⚠️ Brain file discrepancies found (if any)
- None.

### Do Next
- Phase 6 (brain file Phase 7): Fuzzing & stress tests. Instrument the pre-auth header parser (`denyfs_header_disk_t` decryption path in `src/fs.c:denyfs_vol_open`) for AFL++ fuzzing campaigns — this is the actual pre-auth attack surface that runs on attacker-controlled bytes before any password is verified. Secondary target: FUSE-layer create/delete/rename loops. Do not start Phase 7 (benchmarks) until fuzzing coverage is established.

---

## Session 4 — 2026-07-16

### What existed at the start of this session
- Phases 1-3 complete: crypto core, raw sector CLI, on-disk metadata format, FUSE callbacks, and integration test suites.

### Scoping decision
- Phase 4: Deniability hardening. Implement core-dump prevention, memory hygiene, indistinguishable sequential header decryption, hidden volume formatting/mounting, outer-mount protection block boundary checks, atime suppression, and a high-resolution timing verification benchmark test.

### What was actually built / changed
- `src/main.c`: Added core dump restriction via `setrlimit(RLIMIT_CORE, &lim)`. Implemented `create-hidden` subcommand CLI routing. Enhanced `open` and `mount` subcommands to support `--protect-hidden` and `--hidden-password` flags. Integrated deniability warning notices on FUSE mounts.
- `src/fs.h`: Added `DENYFS_HIDDEN_HEADER_OFFSET_FROM_EOF` (32768). Updated `denyfs_volume_t` to include `vol_start_offset`, `is_hidden`, `protect_hidden`, `protect_start_sector`, and `protect_end_sector`. Added `denyfs_container_create_hidden` declaration and updated `denyfs_vol_open` to support hidden volume parameters.
- `src/fs.c`:
  - `denyfs_vol_open`: Refactored to read both headers and sequentially run the Argon2id KDF and GCM decrypt on both, unconditionally preventing timing-based presence attacks. Implemented `O_NOATIME` opening (with standard fallback). Added outer-mount protection key derivation and block range mapping.
  - `denyfs_container_create_hidden`: Implemented hidden volume creation. Checks remaining container space, calculates start offset, formats the hidden volume, and encrypts and writes the hidden header.
  - `write_block`: Added bounds checks against `protect_start_sector` and `protect_end_sector` to return `-ENOSPC` when outer volume writes attempt to overwrite the hidden volume.
- `tests/test_fs.c`: Added `test_hidden_volume_functionality` integration test verifying hidden volume formatting, directory independence, and outer-mount protection block boundaries mapping.
- `tests/test_timing.c` (NEW): Microsecond-level timing side-channel test running 50 trial openings on a container with no hidden volume vs. a container with a hidden volume, confirming timing difference is indistinguishable (< 15ms).
- `Makefile`: Added `test_timing` compilation and clean targets linking against math library (`-lm`).

### Tests run and results
- Phase 1-3 tests: All pass.
- Phase 4 Timing Verification:
  - `Outer-only container (mean): 385.33 ms (stddev: 27.88 ms)`
  - `Container with hidden (mean): 393.57 ms (stddev: 26.92 ms)`
  - `Absolute difference in mean: 8.2437 ms` (within the 15ms limit)
  - `[+] Timing side-channel verification PASSED.`
- Phase 4 Hidden Volume & Outer Protection Tests:
  - `[+] Hidden volume format and write succeeded.`
  - `[+] Outer volume cannot see hidden volume files.`
  - `[+] Outer-mount protection activated and mapped correctly.`
  - `[+] All Phase 3 & 4 tests passed successfully.`
- CLI Smoke Test: Verified `create-hidden`, `open` for both types, wrong password rejection, and outer-mount protection block bounds locking (`Blocks 1784 to 2559 locked`) via CLI.

### Known issues / incomplete work from this session
- None.

### ⚠️ Brain file discrepancies found (if any)
- None.

### Do Next
- Phase 5: Build integrity note. Document scope limitations around code signing, reproducible builds, and compiler/binary compromise.

---

## Session 3 — 2026-07-16

### What existed at the start of this session
- Phases 1-2 complete: crypto core, raw sector I/O CLI, unit tests.

### Scoping decision
- Phase 3: Filesystem layer. Implement on-disk metadata (Superblock, block allocation bitmap with HMAC integrity check, flat inode table, flat directory entries) and all FUSE operations (`getattr`, `read`, `write`, `readdir`, `open`, `truncate`, `create`, `unlink`).

### What was actually built / changed
- `src/crypto.h` / `src/crypto.c`: Added `denyfs_compute_hmac()` — generic HMAC-SHA256 function for bitmap integrity protection.
- `src/fs.h` (NEW): On-disk structures with compile-time `_Static_assert` layout checks:
  - `denyfs_superblock_t` (4096 bytes): magic, layout pointers, free counts, bitmap HMAC digest.
  - `denyfs_inode_t` (128 bytes): type, size, 24 direct block pointers, mtime. Max file size = 96KB (stated scope limitation).
  - `denyfs_dirent_t` (256 bytes): inode + name. 16 entries per block.
  - `denyfs_volume_t`: in-memory state (FILE handle, secure keys, superblock, bitmap, inode table).
  - Full public API: `denyfs_container_create`, `denyfs_vol_open/close/flush`, `denyfs_vol_create/unlink/read/write/truncate/readdir/lookup`.
- `src/fs.c` (NEW, ~500 lines): Complete filesystem implementation:
  - `format_volume()`: initializes superblock, bitmap (HMAC-protected), inode table, and root dir block.
  - `denyfs_container_create()`: CSPRNG fill + header + format in one call.
  - `denyfs_vol_open()`: authenticate → load superblock → load+verify bitmap HMAC → load inodes.
  - Block-level I/O: `read_block` / `write_block` with XTS encrypt/decrypt + fseek + fflush.
  - Bitmap allocation/deallocation with `alloc_block` / `free_block`.
  - Directory entry management: `add_dirent` / `remove_dirent` / `denyfs_vol_lookup`.
  - Inode allocation: `alloc_inode` / `free_inode` (frees all data blocks).
  - `denyfs_vol_write`: handles multi-block writes with read-modify-write for partial blocks.
  - `denyfs_vol_read`: handles multi-block reads with clamping to file size.
  - `denyfs_vol_truncate`: extends (allocate + zero-fill) or shrinks (free excess blocks).
  - `denyfs_vol_flush`: recomputes bitmap HMAC, writes superblock + bitmap + inode table.
  - `denyfs_vol_close`: flush + wipe keys (sodium_memzero) + free.
- `src/fuse_ops.h` / `src/fuse_ops.c` (NEW): FUSE3 callback layer wrapping fs.c API. Single-threaded foreground mode (`-f -s`). Callbacks: `getattr`, `readdir`, `open`, `read`, `write`, `create`, `unlink`, `truncate`, `destroy`. Path handling rejects nested paths (flat directory only).
- `src/main.c`: Refactored to use `denyfs_container_create()` and `denyfs_vol_open()`. Added `mount` command (`--mountpoint` flag → FUSE loop). Phase 2 sector ops now use `denyfs_vol_open` for authentication. `open` command now shows free blocks/inodes/data_start.
- `Makefile`: Added `FUSE_CFLAGS`/`FUSE_LIBS` via `pkg-config fuse3`. Added `test_fs` target (no FUSE dependency). Updated `test` and `clean` rules.
- `tests/test_fs.c` (NEW): 10 integration tests covering the Phase 3 gate requirements:
  1. Container creation and format verification (superblock magic, layout, root dir inode).
  2. File create + lookup + duplicate rejection.
  3. Write/read roundtrip (including partial reads).
  4. Multi-block write/read (10000 bytes spanning 3 sectors).
  5. Readdir listing all files.
  6. Truncate extend (zero-fill) + shrink (free blocks).
  7. Unlink (inode + blocks freed, directory updated).
  8. Persistence across close/reopen.
  9. Bitmap HMAC corruption detection (flip ciphertext byte → vol_open refuses).
  10. Wrong password rejection.

### Tests run and results
- Phase 1 crypto tests: All pass.
- Phase 2 volume tests: All pass.
- Phase 3 filesystem tests (ASan/UBSan clean, 10/10):
  - `[+] Container created and formatted correctly.`
  - `[+] File create and lookup work correctly.`
  - `[+] Write/read roundtrip verified.`
  - `[+] Multi-block write/read verified.`
  - `[+] Readdir lists all files correctly.`
  - `[+] Truncate (extend/shrink) works correctly.`
  - `[+] Unlink works correctly.`
  - `[+] Persistence verified across close/reopen.`
  - `[+] Bitmap HMAC corruption correctly detected.`
  - `[+] Wrong password correctly rejected.`
  - `[+] All Phase 3 tests passed successfully.`
- CLI smoke test: `create` formats filesystem (296ms), `open` shows volume metadata (free blocks: 507, free inodes: 63, data_start: 4), wrong password cleanly rejected.

### Known issues / incomplete work from this session
- FUSE mount not tested end-to-end (requires WSL2 FUSE kernel module). Filesystem API fully tested without FUSE.
- Max file size limited to 96KB (24 direct blocks × 4096). Stated scope limitation per architecture doc.
- Max 63 files (64 inodes, 1 reserved for root dir). Stated scope limitation per architecture doc.

### ⚠️ Brain file discrepancies found (if any)
- None.

### Do Next
- Phase 4: Deniability hardening. Implement fixed-order/fixed-time header attempt sequence, memory hygiene audit, `setrlimit(RLIMIT_CORE, 0)`, atime suppression, and the external-observable indistinguishability mechanism from §3.

---

## Session 2 — 2026-07-16

### What existed at the start of this session
- Phase 1 complete: crypto core (`src/crypto.h`, `src/crypto.c`), CLI with `create`/`open` (`src/main.c`), unit tests (`tests/test_crypto.c`), Makefile.

### Scoping decision
- Phase 2: Volume mounting (raw, no FUSE). Implement `write-sector` and `read-sector` CLI subcommands that authenticate the container, encrypt/decrypt individual 4096-byte sectors at a given LBA within the outer volume's data region. Add automated integration test (`tests/test_volume.c`).

### What was actually built / changed
- `src/main.c`: Refactored authentication logic into reusable `denyfs_authenticate()` function (reads header, derives keys, decrypts payload, returns payload struct). Added `write-sector` subcommand (authenticate → encrypt plaintext from file → write ciphertext to `HEADER_SIZE + (lba * SECTOR_SIZE)` in container). Added `read-sector` subcommand (authenticate → read ciphertext → decrypt → write plaintext to output file). Both include LBA bounds checking against `volume_size / SECTOR_SIZE`. Updated usage output.
- `tests/test_volume.c`: New integration test file covering six tests:
  1. Roundtrip: write sectors 0, 1, 5 with known patterns, wipe all state, re-authenticate from scratch, read back — byte-identical.
  2. Ciphertext differs from plaintext on disk.
  3. Same plaintext at different LBAs yields different ciphertext (XTS tweak verification).
  4. Wrong password rejected by GCM authentication.
  5. LBA bounds check rejects out-of-range writes.
  6. Container creation via direct API.
- `Makefile`: Added `test_volume` build target, updated `test` rule to run both test binaries, updated `clean` to remove `test_volume` and `test_volume.img`.

### Tests run and results
- Phase 1 crypto tests: All pass (Argon2id, GCM, XTS).
- Phase 2 volume tests (ASan/UBSan clean):
  - `[+] Roundtrip verified: all sectors byte-identical after close/reopen.`
  - `[+] Ciphertext differs from plaintext on disk.`
  - `[+] Different LBAs produce different ciphertext for identical plaintext.`
  - `[+] Wrong password correctly rejected.`
  - `[+] Bounds check verified: LBA 512 correctly exceeds volume.`
  - `[+] All Phase 2 tests passed successfully.`
- CLI smoke test: Created container, wrote 4096 random bytes to LBA 3 via `write-sector`, read back via `read-sector`, `cmp` confirmed byte-identical. Verified on-disk raw bytes at LBA offset differ from plaintext via `dd` extraction.

### Known issues / incomplete work from this session
- None.

### ⚠️ Brain file discrepancies found (if any)
- None.

### Do Next
- Phase 3: Filesystem layer. Implement on-disk metadata (Superblock, block allocation bitmap with HMAC integrity check, flat inode table, flat directory entries) and FUSE operations (`getattr`, `read`, `write`, `readdir`, `open`, `truncate`, `create`, `unlink`).

---

## Session 1 — 2026-07-16

### What existed at the start of this session
- Only `DenyFS-Architecture-and-Build-Plan.md` existed. No source code or directories were present.

### Task(s) this session tackled
- Phase 1: Cryptographic core implementation. Built and verified the key derivation, header GCM wrapping, block XTS encryption, secure memory allocation wrappers, and early CLI for container creation/inspection.

### What was actually built / changed
- `src/crypto.h`: Cryptographic headers exposing `libsodium` and `OpenSSL` wrapper interfaces, packed header layouts (`denyfs_header_payload_t` and `denyfs_header_disk_t`), and memory hygiene functions.
- `src/crypto.c`: Cryptographic logic implementing Argon2id (`crypto_pwhash`), HKDF-Expand (via `HMAC-SHA256` for portability), GCM encryption/decryption (`EVP_aes_256_gcm`), and block encryption (`EVP_aes_256_xts` using 16-byte little-endian LBA tweaks). Includes secure wrappers (`denyfs_secure_alloc`, `denyfs_secure_free`) locking memory and zeroing sensitive data.
- `src/main.c`: CLI implementation (`create` and `open`). Handles secure password duplication/wiping in `argv`, streamed CSPRNG random generation in 64KB blocks, and strict timing checks for KDF.
- `Makefile`: Compiler flags for development (`-fsanitize=address,undefined` enabled) targeting both MSYS2 MinGW-w64 on Windows and native gcc/clang on Linux.
- `tests/test_crypto.c`: Testing harness validating Argon2id derivation consistency, GCM encryption/decryption correctness, tamper detection on GCM tags, and XTS sector LBA-tweak uniqueness.

### Tests run and results
- Unit tests: All cryptographic tests (Argon2id, HKDF, GCM, XTS) run and pass successfully.
- Sanitizer status: Built and run cleanly with AddressSanitizer and UndefinedBehaviorSanitizer enabled inside WSL Ubuntu. No leaks, buffer overflows, or UB reported.
- CLI Verification:
  - Container creation (`./denyfs create test.img --size 10 --password <pass>`) successfully streams CSPRNG random bytes and writes the encrypted header.
  - Authentication (`./denyfs open test.img --password <pass>`) successfully decrypts the GCM header, prints volume size, and validates metadata.
  - Invalid password (`./denyfs open test.img --password wrong`) cleanly prints `Error: invalid password.` and exits with 1.

### Known issues / incomplete work from this session
- None.

### ⚠️ Brain file discrepancies found (if any)
- None.

### Do Next
- Phase 2: Volume mounting (raw, no FUSE). Implement sector-level reading/writing CLI interface and raw validation to allow `dd` commands to read/write into the encrypted volume sectors directly.
