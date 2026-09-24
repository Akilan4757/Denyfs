# DenyFS — Threat Model & Security Writeup

This document is the threat-model deliverable from the architecture plan. It answers one question clearly: **what does DenyFS attempt to protect against, and what does it not protect against?** Claims below describe the current implementation and its limits.

---

## 1. The Core Distinction: Encrypted vs. Deniable

Standard full-disk encryption (LUKS, BitLocker, FileVault) protects **confidentiality** — an adversary who captures the disk cannot read the plaintext. But the *existence* of encrypted data is obvious: the LUKS header, the partition type, the entropy profile of the ciphertext blocks all announce "something is encrypted here."

DenyFS aims for a second property: **plausible deniability**. In a single snapshot, the container is designed so that:
- The container bytes look random to an observer without a password, assuming the cryptographic design holds.
- A user can reveal the **outer** password under coercion and mount the outer volume. The outer filesystem does not describe a hidden volume, but that does not prove that hidden data is absent.
- The hidden volume's data occupies the container's unused region. Since that region starts filled with random bytes and hidden data uses AES-256-XTS, both are intended to look random-like in a single snapshot.

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
| Quantum computing capabilities | This prototype's analysis assumes classical attackers; it makes no quantum-security assessment. |
| Persistent access over time (single-snapshot only) | See §4 for what happens when this assumption is violated |

---

## 3. Defended Threats — What DenyFS Protects Against

### 3.1. Confidentiality of Stored Data

**Threat:** Adversary captures the container file and attempts to read its contents.

**Defense:** Filesystem blocks are encrypted with AES-256-XTS using per-sector LBA tweaks. Header metadata is encrypted and authenticated with AES-256-GCM. Argon2id (opslimit=4, memlimit=64MB) derives a master key from the password; HKDF derives a header key, and the authenticated header payload contains randomly generated volume and bitmap-HMAC keys.

**Implementation:** Phase 1 (`src/crypto.c`). Verified by `test_crypto`, which validates cipher output correctness and tweak uniqueness.

---

### 3.2. Deniability of Hidden Volume Existence

**Threat:** Adversary has the outer password and inspects the container's raw bytes, sector structure, and header fields for evidence that a hidden volume exists.

**Design:** A hidden volume is intended to be difficult to distinguish from random unused space in a single snapshot. These mechanisms support that goal, but do not establish universal indistinguishability:

| Property | How it's achieved | Phase |
|---|---|---|
| Free space = random bytes | Container filled using libsodium's system-backed CSPRNG at creation time | `denyfs_container_create` in `src/fs.c` |
| Hidden data = random-looking ciphertext | AES-256-XTS encrypts hidden filesystem blocks | `src/crypto.c` |
| Hidden header = random-looking bytes | AES-256-GCM header with random salt and IV in a fixed slot | `src/fs.c`, `src/crypto.c` |
| Outer metadata independence | Outer filesystem metadata does not describe hidden-volume blocks | `src/fs.c` |
| Bitmap integrity | HMAC authenticates the allocation bitmap, not all filesystem metadata | `src/fs.c`, `src/crypto.c` |

---

### 3.3. Timing Work-Shape Measure

**Threat:** Adversary measures the time it takes to open the container with different passwords and infers whether a hidden volume exists from timing differences.

**Mechanism:** `denyfs_vol_open` attempts **two** Argon2id derivations and **two** AES-256-GCM decryptions on every open — one for each header slot — without stopping after the first success. A failed-password open therefore uses the same number of cryptographic attempts whether the hidden header contains a valid volume or random fill. This gives equal cryptographic work shape; it is not a fixed-time guarantee.

**Implementation/evidence:** `test_timing.c` compares failed-password opens for an outer-only container and a container with a hidden volume over 50 trials per case. It fails if the absolute mean difference exceeds 15 ms. This coarse threshold is a regression check for one environment, not statistical proof and not evidence about successful opens.

**Specific mechanism (§3 of brain file):**
1. Always attempt: (a) decrypt outer header, (b) decrypt hidden header. In that order. Both always execute.
2. When both candidate headers fail authentication, the CLI reports `Error: invalid password.` without stating which header attempt failed. A correct outer password succeeds and opens the outer filesystem whether or not a hidden volume exists.
3. On success, DenyFS mounts whichever volume matched and gives no indication that another password might exist.

---

### 3.4. Key Material Protection

**Threat:** Key material persists in process memory after use, vulnerable to crash dumps, memory forensics, or swap-file analysis.

**Defense:**

| Protection | Mechanism | Phase |
|---|---|---|
| Secure allocation | Key buffers use `sodium_malloc` (guard pages; locking is attempted by libsodium where supported) | `src/crypto.c` |
| Memory locking | DenyFS does not separately check or enforce lock success | `src/crypto.c` |
| Secure wiping | `sodium_memzero` (compiler-proof, not dead-store-eliminable) on all key buffers at close/error | Phase 4 |
| Core dump prevention | The CLI requests `RLIMIT_CORE = 0` and warns if the request fails | `src/main.c` |
| Secret comparison | `sodium_memcmp` is used for HMAC and key-equality checks; filenames use ordinary comparison | `src/crypto.c`, `src/fs.c` |

**Implementation:** `src/fs.c`, `src/crypto.c`, and `src/main.c`. Sanitizers can find memory errors, but do not prove correct memory clearing or protect secrets from a privileged observer.

---

### 3.5. Hidden Volume Protection During Outer Mount

**Threat:** User mounts the outer volume (under coercion) and writes data. The write lands on sectors occupied by the hidden volume, destroying hidden data without the user's knowledge.

**Defense:** With `--protect-hidden`, DenyFS prompts for the hidden password (or reads it from `--hidden-password-fd`), authenticates the hidden header, and rejects outer writes targeting the protected range. If the hidden password fails, the mount is refused. The guard returns `-ENOSPC`; this can reveal that an attempted write hit an unavailable range, so it is not a general-purpose concealment mechanism.

**Implementation:** `src/fs.c`, `write_block` and the `protect_start_sector`/`protect_end_sector` range check. The outer volume's own block limit also constrains ordinary filesystem writes.

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

**Impact:** Key material is in memory while the volume is mounted. The secure allocator attempts memory locking where supported, but DenyFS does not verify success and cannot defend against physical DRAM reads.

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
| **Container file timestamps** | Reads may update atime and writes update modification metadata, depending on host filesystem behavior | DenyFS requests `O_NOATIME` where available and falls back if permission is denied; host behavior still matters |
| **Shell history / process list** | Command-line passwords can leak through shell history and process metadata | This CLI does not accept plaintext password flags; use the interactive prompt or carefully controlled file descriptors |
| **systemd journal** | FUSE mount/unmount events are logged by `journalctl` by default | Users needing full operational deniability must scrub journal logs |
| **Desktop file indexers** (Tracker, Baloo, GNOME/KDE) | Can index filenames or content the moment a FUSE mount exposes them | Exclude the mount point from indexer scope |
| **GVFS / desktop virtual filesystem** | Thumbnail/preview caches can leak filenames from mounted volumes | Same: exclude mount point from GVFS scope |
| **/tmp and swap** | Temporary files created by applications working with mounted files | Use `noswap` configuration; avoid apps that create /tmp caches for sensitive files |

---

## 6. Cryptographic Primitive Selection Rationale

| Primitive | Use | Why This One |
|---|---|---|
| **Argon2id** | Password → Master Key | Memory-hard password KDF; raises the cost of password guessing. Weak passwords remain guessable. |
| **HKDF-Expand** (HMAC-SHA256) | Master Key → Header Key | Standard key-derivation function for expanding a single PRK into multiple domain-separated subkeys. Single-block output (32 bytes = one HMAC block). |
| **AES-256-GCM** | Header encryption | Authenticates the encrypted header payload and reports whether a candidate key is correct. |
| **AES-256-XTS** | Sector encryption | Disk-encryption mode with a logical-block tweak. It does not authenticate ciphertext. |
| **HMAC-SHA256** | Bitmap integrity | Authenticates the plaintext allocation bitmap using the random key carried in the encrypted header. It does not authenticate the superblock, inode table, directory blocks, or file data. |

---

## 7. Security Property Summary

| Property | Status | Evidence |
|---|---|---|
| Data confidentiality (AES-256-XTS) | ✅ Implemented | `test_crypto`: cipher correctness + tweak uniqueness |
| Header authentication (AES-256-GCM) | ✅ Implemented | `test_crypto`: GCM tag verification + tamper detection |
| Hidden-volume design | Implemented, not proven | `test_fs` exercises create/open/isolation; one-snapshot deniability is a design goal |
| Failed-open work shape | Implemented; timing evidence is limited | `test_timing`: 50 wrong-password trials per container type and a 15 ms threshold |
| Memory handling | Partially implemented | Secure allocator and wiping are used; lock and core-limit success are not checked |
| Secret comparisons | Implemented where needed | `sodium_memcmp` for magic/HMAC/key-equality checks; filesystem names are not secret |
| Bitmap integrity | Implemented | `test_fs` source includes deliberate bitmap corruption case |
| Metadata bounds validation | Implemented | Superblock layout, direct/indirect block maps, inode references, bitmap allocation, and directory entries checked on open |
| Header/sector fuzzing | Harness source exists; AFL++ campaign not established | Harnesses cover GCM/XTS paths, not the complete `denyfs_vol_open` parser |
| FUSE integration | Live smoke test passed | `make test-fuse` exercises normal file operations and a 4 GiB sparse-file write/read; it is not exhaustive FUSE fuzzing |
| Write guard for hidden volume | Implemented when explicitly enabled | `write_block` rejects writes to the protected range; `--protect-hidden` requires a valid hidden password |
| Repeated-snapshot resistance | ❌ Not addressable | Structural limitation of hidden-volume architecture |
| Host compromise resistance | ❌ Out of scope | Requires trusted computing base beyond userspace |
| Cold-boot / DMA resistance | ❌ Out of scope | Requires hardware memory encryption |
| Build integrity / supply chain | ❌ Documented only | See [BUILD_INTEGRITY.md](BUILD_INTEGRITY.md) |

---

## 8. Interview Framing

**"Why not just use VeraCrypt?"**

> I intentionally restricted scope to understand every primitive involved in building a deniable storage system — the objective was never to replace VeraCrypt, it was to understand, well enough to defend under questioning, why VeraCrypt's design choices are the ones they are.

**"What about a cold-boot attack?"**

> DenyFS uses libsodium's secure allocator, which attempts memory locking where supported, but the application does not check that locking succeeded. This does not defend against physical DRAM reads on a seized machine.

**"How do you know the hidden volume is actually invisible?"**

> The implementation fills unused space with random bytes, stores the hidden header in a fixed random-looking slot, and keeps hidden blocks out of outer metadata. Its timing test compares 50 failed-password opens per container type. These are limited design and regression checks; they do not prove that the hidden volume is invisible.

**"What's the weakest point?"**

> The repeated-snapshot problem. If an adversary captures the container at two points in time and diffs them, changed bytes in the free-space region imply hidden-volume activity. This is inherent to hidden-volume architectures — VeraCrypt shares it. The only mitigation is operational, not cryptographic.

---

## 9. Appendix: Data-Block Authentication vs. Plausible Deniability Tradeoff

DenyFS omits cryptographic authentication for file data, inode records, and directory blocks, using AES-256-XTS for those sectors. The bitmap alone has a separate HMAC. This is a security tradeoff: XTS preserves fixed-size random-looking blocks but does not detect tampering. It is not a general rule that authenticated storage is incompatible with deniability.

### The Cryptographic Dilemma
To authenticate a sector, a cryptographic tag (e.g., 16 bytes for GCM) must be stored. There are only two ways to store this tag:
1. **Inline / Adjacent to the Sector:** This expands the sector size (e.g., 4096 bytes of plaintext becomes 4112 bytes of ciphertext). A host disk sector is strictly 512 or 4096 bytes; block expansion cannot be easily mapped to physical sectors without leaking layout structure.
2. **In an Out-of-Band Tag Database:** A dedicated allocation map or table holds the authentication tags for all sectors. 

Whether tags reveal a hidden volume depends on their placement and protection. A visible tag table that covers hidden sectors could create a clue, while another authenticated layout might avoid that leak. DenyFS does not implement authenticated data blocks or analyze alternative formats in depth.

### The DenyFS Resolution
By using **AES-256-XTS**, DenyFS gets:
- **No Block Expansion:** Ciphertext size exactly matches plaintext size (4096 bytes).
- **Random-looking ciphertext:** XTS emits fixed-size ciphertext with no per-block tag or nonce in this format. This supports the design goal but is not a formal proof of indistinguishability for the whole container.

The allocation bitmap is authenticated with an HMAC-SHA256 digest stored in the encrypted superblock. The HMAC key is carried in the GCM-protected header payload. Other filesystem metadata and file data do not have cryptographic authentication.

This is DenyFS's chosen tradeoff, with a corresponding risk: changed file data can silently decrypt to changed plaintext, and some metadata corruption may not be detected cryptographically.

---

## References

- [DenyFS Architecture & Build Plan](DenyFS-Architecture-and-Build-Plan.md) — Full design document (brain file)
- [BUILD_INTEGRITY.md](BUILD_INTEGRITY.md) — Build integrity scope limitations
- [BENCHMARKS.md](BENCHMARKS.md) — Performance benchmarks and analysis
- [PROGRESS_LOG.md](PROGRESS_LOG.md) — Session-by-session development log
