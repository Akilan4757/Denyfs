# DenyFS — Threat Model & Security Writeup

This document is the final deliverable of Phase 8 (brain file Phase 6). It exists to answer one question clearly: **what does DenyFS actually protect against, and what doesn't it?** Every claim below is cross-referenced to the implementation phase that enforces it.

---

## 1. The Core Distinction: Encrypted vs. Deniable

Standard full-disk encryption (LUKS, BitLocker, FileVault) protects **confidentiality** — an adversary who captures the disk cannot read the plaintext. But the *existence* of encrypted data is obvious: the LUKS header, the partition type, the entropy profile of the ciphertext blocks all announce "something is encrypted here."

DenyFS adds a second property: **plausible deniability**. A DenyFS container is designed so that:
- The entire container file is byte-for-byte indistinguishable from CSPRNG output to an observer without a password.
- A user can reveal the **outer** password under coercion and mount the outer volume — the adversary sees a working encrypted filesystem and has no evidence that a second, hidden volume exists inside the same container.
- The hidden volume's data occupies the container's "free space" region. Since free space in DenyFS is filled with random bytes at creation time, and encrypted data under AES-256-XTS is also indistinguishable from random, the hidden volume's sectors blend seamlessly with genuine free space.

This is the same architectural pattern as VeraCrypt's hidden volumes. DenyFS implements it from scratch to understand every primitive involved, not to replace VeraCrypt.

---

## 2. Adversary Model

### What the adversary has

| Capability | Notes |
|---|---|
| Physical access to the container file | Can copy, inspect, hex-dump, or analyze every byte |
| The outer password (coerced or voluntarily disclosed) | Can mount the outer volume and inspect its entire filesystem |
| Host filesystem metadata | Can see the container file's size, timestamps, and location |
| Arbitrary computational resources (within classical bounds) | Can attempt any analysis that doesn't require breaking AES-256 or Argon2id |

### What the adversary does NOT have

| Limitation | Notes |
|---|---|
| The hidden password | Cannot be coerced, guessed, or brute-forced |
| Quantum computing capabilities | AES-256 and Argon2id remain secure under classical assumptions |
| Persistent access over time (single-snapshot only) | See §4 for what happens when this assumption is violated |

---

## 3. Defended Threats — What DenyFS Protects Against

### 3.1. Confidentiality of Stored Data

**Threat:** Adversary captures the container file and attempts to read its contents.

**Defense:** All filesystem data is encrypted with AES-256-XTS using per-sector LBA tweaks. Header metadata is encrypted with AES-256-GCM. Keys are derived from the user password via Argon2id (opslimit=4, memlimit=64MB).

**Implementation:** Phase 1 (`src/crypto.c`). Verified by `test_crypto`, which validates cipher output correctness and tweak uniqueness.

---

### 3.2. Deniability of Hidden Volume Existence

**Threat:** Adversary has the outer password and inspects the container's raw bytes, sector structure, and header fields for evidence that a hidden volume exists.

**Defense:** The design ensures that a container with a hidden volume is **structurally indistinguishable** from one without:

| Property | How it's achieved | Phase |
|---|---|---|
| Free space = random bytes | Container filled with CSPRNG output at creation time | Phase 1 (`denyfs_container_create` in `src/fs.c`) |
| Hidden data = random bytes | AES-256-XTS ciphertext is indistinguishable from CSPRNG output | Phase 1 (`src/crypto.c`) |
| Hidden header = random bytes | AES-256-GCM ciphertext in a fixed slot at EOF is indistinguishable from the random fill | Phase 1, 3 |
| No metadata leaks | Outer volume superblock, bitmap, and inode table contain no pointers to or awareness of the hidden volume | Phase 3 (`src/fs.c`) |
| Bitmap integrity | Outer volume's bitmap HMAC covers only outer-volume blocks; hidden-volume blocks are outside the outer bitmap's scope | Phase 3 |

---

### 3.3. Timing Side-Channel Resistance

**Threat:** Adversary measures the time it takes to open the container with different passwords and infers whether a hidden volume exists from timing differences.

**Defense:** `denyfs_vol_open` unconditionally executes **two** full Argon2id KDF derivations and **two** AES-256-GCM decryption attempts on every open — one for the outer header, one for the hidden header — regardless of which password was provided and regardless of whether a hidden volume exists. The four possible outcomes (outer succeeds, hidden succeeds, both fail, both succeed — the last is cryptographically impossible since keys are independent) all follow the same execution path with no short-circuiting.

**Implementation:** Phase 4 (`src/fs.c`, lines 515-558). Verified by `test_timing`, which runs 100 trials comparing wall-clock timing between containers with and without hidden volumes and asserts statistical indistinguishability (5.71ms mean difference against a 15ms threshold).

**Specific mechanism (§3 of brain file):**
1. Always attempt: (a) decrypt outer header, (b) decrypt hidden header. In that order. Both always execute.
2. External behavior for "wrong password" and "correct password, no hidden volume" is identical: both produce `Error: invalid password.` with no stack trace, no distinct exit code, no timing tell.
3. On success, DenyFS mounts whichever volume matched and gives no indication that another password might exist.

---

### 3.4. Key Material Protection

**Threat:** Key material persists in process memory after use, vulnerable to crash dumps, memory forensics, or swap-file analysis.

**Defense:**

| Protection | Mechanism | Phase |
|---|---|---|
| Secure allocation | All key buffers allocated via `sodium_malloc` (guard pages, canary) | Phase 1, 4 |
| Memory locking | `sodium_mlock` prevents key pages from being swapped to disk | Phase 4 |
| Secure wiping | `sodium_memzero` (compiler-proof, not dead-store-eliminable) on all key buffers at close/error | Phase 4 |
| Core dump prevention | `setrlimit(RLIMIT_CORE, 0)` at process start | Phase 4 |
| Constant-time comparison | All password/key comparisons use `sodium_memcmp`, never `memcmp` | Phase 4 |

**Implementation:** Phase 4 (`src/fs.c`, `src/crypto.c`). Memory hygiene verified under AddressSanitizer/UndefinedBehaviorSanitizer across all test suites.

---

### 3.5. Hidden Volume Protection During Outer Mount

**Threat:** User mounts the outer volume (under coercion) and writes data. The write lands on sectors occupied by the hidden volume, destroying hidden data without the user's knowledge.

**Defense:** When the outer volume is mounted with `--protect-hidden --hidden-password <pass>`, DenyFS decrypts the hidden volume's header to determine its sector range, then enforces a write guard that rejects any write operation targeting sectors within the hidden volume's range. The guard returns `-EIO`, which is the same error returned for any other I/O failure — it does not leak the existence of a protected region.

**Implementation:** Phase 4 (`src/fs.c`, `write_block` function with `protect_start_sector`/`protect_end_sector` range check). Verified by `test_fs` hidden-volume protection tests.

---

## 4. Undefended Threats — What DenyFS Does NOT Protect Against

These are **named, acknowledged, and architecturally non-addressable within scope**. Listing them is more important than listing defenses, because a security tool that doesn't say what it *doesn't* do is more dangerous than one that's silent about security entirely.

---

### 4.1. Repeated Snapshots Over Time

**Threat:** Adversary captures the container file at two or more points in time and diffs them.

**Impact:** Changed bytes in the "free space" region (which is where the hidden volume lives) reveal that *something* wrote to those sectors between snapshots. The adversary cannot decrypt the data, but can infer that a hidden volume likely exists.

**Why there is no code fix:** This is a structural limitation of the hidden-volume approach itself — VeraCrypt shares it. The only mitigation is operational: avoid giving an adversary multiple historical copies of the container.

**Operational guidance:** Do not store DenyFS containers in version-controlled directories, cloud sync folders with revision history, or backup systems that retain snapshots.

---

### 4.2. Host Compromise (Malware, Root, Keylogger)

**Threat:** Adversary has code execution on the host while DenyFS is in use.

**Impact:** Both passwords can be captured as they're typed. Key material can be read from process memory. All cryptographic protections are void.

**Why there is no code fix:** This is outside the threat model boundary — DenyFS assumes the host OS is not compromised during use. No userspace application can defend against a compromised kernel or a keylogger.

---

### 4.3. Cold-Boot / RAM-Remanence Attacks

**Threat:** Adversary physically seizes a running (or recently powered-off) machine and reads DRAM contents before they decay.

**Impact:** Key material is in memory while the volume is mounted. `sodium_mlock` prevents swap-to-disk exposure but does not defend against physical DRAM reads.

**Why there is no code fix:** Full protection against RAM-remanence requires hardware-level memory encryption (AMD SME/SEV, Intel TME) — not achievable in a userspace FUSE application. Stated explicitly rather than left as a silent gap.

---

### 4.4. DMA Attacks (Thunderbolt, FireWire, PCIe)

**Threat:** Adversary uses a DMA-capable peripheral to read physical memory while the system is running.

**Impact:** Same as cold-boot — key material in RAM is accessible via DMA.

**Why there is no code fix:** Requires IOMMU-level protections (`intel_iommu=on`, Thunderbolt security policies) configured at the OS/firmware level. Outside this project's scope.

---

### 4.5. Evil-Maid / Tampered Binary

**Threat:** Adversary replaces the `denyfs` binary with a backdoored version that exfiltrates passwords or key material.

**Impact:** All security properties are voided. The user trusts a compromised tool.

**Why there is no code fix:** DenyFS does not implement reproducible builds, code signing, or binary attestation. This is documented in [BUILD_INTEGRITY.md](BUILD_INTEGRITY.md) as a scope limitation. A production system would need all three.

---

### 4.6. Compromised Kernel

**Threat:** The host kernel is compromised (rootkit, backdoored module, supply-chain attack on the kernel image).

**Impact:** FUSE operates in userspace, but the kernel mediates all I/O. A compromised kernel can observe every read, write, and system call regardless of anything DenyFS does.

**Why there is no code fix:** Kernel integrity is a prerequisite assumption, not something a userspace tool can verify or enforce.

---

### 4.7. Cloud Backup / Sync Leakage

**Threat:** The container file is synced to a cloud service (Dropbox, Google Drive, iCloud, OneDrive) that retains version history.

**Impact:** Recreates the repeated-snapshot problem (§4.1) outside the user's control. The cloud provider's servers now hold multiple historical copies of the container.

**Why there is no code fix:** This is an operational concern, not a software one. DenyFS cannot detect or prevent cloud sync from running on the host.

**Operational guidance:** Never store DenyFS containers in cloud-synced directories. If backup is needed, use a non-versioning encrypted backup (e.g., a secondary DenyFS container on a physically controlled USB device).

---

## 5. Host-Environment Metadata Leaks

These are information channels **outside** the container file that can leak evidence of DenyFS usage or hidden-volume activity. DenyFS documents them as user-facing operational guidance; they are not code-level fixes because they involve system components outside this tool's control.

| Leak Source | Risk | Mitigation |
|---|---|---|
| **Container file atime/mtime/ctime** | Host filesystem timestamps on the container file change when DenyFS reads/writes it, potentially revealing usage timing | Open with `O_NOATIME` or `chattr +A` on the container file |
| **Shell history** | Passwords passed on the command line appear in `~/.bash_history` | Use interactive password prompt (not `--password` on command line) |
| **systemd journal** | FUSE mount/unmount events are logged by `journalctl` by default | Users needing full operational deniability must scrub journal logs |
| **Desktop file indexers** (Tracker, Baloo, GNOME/KDE) | Can index filenames or content the moment a FUSE mount exposes them | Exclude the mount point from indexer scope |
| **GVFS / desktop virtual filesystem** | Thumbnail/preview caches can leak filenames from mounted volumes | Same: exclude mount point from GVFS scope |
| **/tmp and swap** | Temporary files created by applications working with mounted files | Use `noswap` configuration; avoid apps that create /tmp caches for sensitive files |

---

## 6. Cryptographic Primitive Selection Rationale

| Primitive | Use | Why This One |
|---|---|---|
| **Argon2id** | Password → Master Key | Memory-hard KDF; resists GPU/ASIC brute-force. id variant provides both side-channel resistance (Argon2i property) and GPU resistance (Argon2d property). |
| **HKDF-Expand** (HMAC-SHA256) | Master Key → Header Key | Standard key-derivation function for expanding a single PRK into multiple domain-separated subkeys. Single-block output (32 bytes = one HMAC block). |
| **AES-256-GCM** | Header encryption | Authenticated encryption — provides both confidentiality and a pass/fail authentication signal. Essential for the deniability mechanism: GCM's authentication failure is used to distinguish "correct password" from "wrong password" without any other oracle. |
| **AES-256-XTS** | Sector encryption | Standard disk-encryption mode. Operates on fixed-size blocks with LBA-based tweaks. No authentication (by design — XTS is a narrow-block cipher mode, not an AEAD). Chosen over GCM for the body because GCM's expansion (IV + tag per sector) would waste ~5% of disk capacity at 4KB sectors and would require managing per-sector nonce state. |
| **HMAC-SHA256** | Bitmap integrity | Separate authentication for the allocation bitmap (not covered by GCM, which only protects the header). Prevents silent bitmap corruption from causing data-loss bugs. |

---

## 7. Security Property Summary

| Property | Status | Evidence |
|---|---|---|
| Data confidentiality (AES-256-XTS) | ✅ Implemented | `test_crypto`: cipher correctness + tweak uniqueness |
| Header authentication (AES-256-GCM) | ✅ Implemented | `test_crypto`: GCM tag verification + tamper detection |
| Deniable hidden volume | ✅ Implemented | `test_fs`: hidden volume create/mount/protection tests |
| Timing indistinguishability | ✅ Implemented + Verified | `test_timing`: 100-trial statistical test (5.71ms Δ, <15ms threshold) |
| Memory hygiene (sodium_malloc/mlock/memzero) | ✅ Implemented | ASan/UBSan clean across all test suites |
| Core dump prevention | ✅ Implemented | `setrlimit(RLIMIT_CORE, 0)` in `main.c` |
| Constant-time comparisons | ✅ Implemented | `sodium_memcmp` in all password/key/magic paths |
| Bitmap integrity (HMAC-SHA256) | ✅ Implemented | `test_fs`: deliberate bitmap corruption detected |
| Header parser robustness | ✅ Fuzz-tested | `fuzz_header`: AFL++ harness, no crashes on random input |
| Sector crypto robustness | ✅ Fuzz-tested | `fuzz_sector`: AFL++ harness with roundtrip verification |
| Write guard for hidden volume | ✅ Implemented | `test_fs`: outer mount with protection rejects hidden-region writes |
| Repeated-snapshot resistance | ❌ Not addressable | Structural limitation of hidden-volume architecture |
| Host compromise resistance | ❌ Out of scope | Requires trusted computing base beyond userspace |
| Cold-boot / DMA resistance | ❌ Out of scope | Requires hardware memory encryption |
| Build integrity / supply chain | ❌ Documented only | See [BUILD_INTEGRITY.md](BUILD_INTEGRITY.md) |

---

## 8. Interview Framing

**"Why not just use VeraCrypt?"**

> I intentionally restricted scope to understand every primitive involved in building a deniable storage system — the objective was never to replace VeraCrypt, it was to understand, well enough to defend under questioning, why VeraCrypt's design choices are the ones they are.

**"What about a cold-boot attack?"**

> `sodium_mlock` prevents swap-to-disk exposure, but does not defend against physical DRAM reads on a seized machine. Full protection requires hardware-level memory encryption (AMD SME/SEV, Intel TME) — this is documented as a named out-of-scope threat, not an oversight.

**"How do you know the hidden volume is actually invisible?"**

> Three layers of evidence: (1) the container's free space is CSPRNG-filled at creation, making hidden ciphertext byte-indistinguishable from unused space; (2) the outer volume's metadata contains zero references to the hidden volume; (3) the timing test runs 100 open operations and proves that the presence or absence of a hidden volume produces no statistically measurable timing difference (5.71ms mean Δ against a 15ms threshold).

**"What's the weakest point?"**

> The repeated-snapshot problem. If an adversary captures the container at two points in time and diffs them, changed bytes in the free-space region imply hidden-volume activity. This is inherent to hidden-volume architectures — VeraCrypt shares it. The only mitigation is operational, not cryptographic.

---

## References

- [DenyFS Architecture & Build Plan](DenyFS-Architecture-and-Build-Plan.md) — Full design document (brain file)
- [BUILD_INTEGRITY.md](BUILD_INTEGRITY.md) — Build integrity scope limitations
- [BENCHMARKS.md](BENCHMARKS.md) — Performance benchmarks and analysis
- [PROGRESS_LOG.md](PROGRESS_LOG.md) — Session-by-session development log
