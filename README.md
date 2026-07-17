<p align="center">
  <img src="https://img.shields.io/badge/DenyFS-Deniable_Encrypted_Filesystem-8B5CF6?style=for-the-badge&labelColor=1a1a2e" alt="DenyFS" />
</p>

<h1 align="center">🔐 DenyFS</h1>

<p align="center">
  <strong>A deniable encrypted container filesystem with plausible deniability, built from scratch in C.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-C11-00599C?style=flat-square&logo=c&logoColor=white" />
  <img src="https://img.shields.io/badge/Crypto-AES--256--XTS_%7C_GCM_%7C_Argon2id-FF6B6B?style=flat-square" />
  <img src="https://img.shields.io/badge/FUSE-libfuse3-4CAF50?style=flat-square" />
  <img src="https://img.shields.io/badge/Platform-Linux_%7C_WSL2-FFA726?style=flat-square&logo=linux&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" />
  <a href="https://github.com/Akilan4757/Denyfs/actions/workflows/ci.yml"><img src="https://github.com/Akilan4757/Denyfs/actions/workflows/ci.yml/badge.svg" alt="CI Status" /></a>
  <img src="https://img.shields.io/badge/ASan%2FUBSan-Clean-00C853?style=flat-square" />
</p>

<p align="center">
  <a href="#-what-is-denyfs">What is DenyFS?</a> •
  <a href="#-the-problem">The Problem</a> •
  <a href="#%EF%B8%8F-architecture">Architecture</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-security-model">Security Model</a> •
  <a href="#-benchmarks">Benchmarks</a> •
  <a href="#-project-structure">Project Structure</a> •
  <a href="#-testing">Testing</a> •
  <a href="#-threat-model">Threat Model</a>
</p>

---

## 📖 What is DenyFS?

**DenyFS** is a **deniable encrypted container filesystem** — a single file that contains one or two encrypted volumes, where the existence of the second (hidden) volume is **cryptographically undetectable**, even if the attacker has the first password.

Unlike standard encrypted volumes (LUKS, BitLocker, FileVault), DenyFS doesn't just protect **what** you stored — it protects the fact that **a second set of data exists at all**.

> **🎯 Project Goal:** Understand every cryptographic primitive involved in building a deniable storage system — not to replace VeraCrypt, but to understand why VeraCrypt's design choices are the ones they are, well enough to defend under questioning.

---

## 🔍 The Problem

### Standard Encryption ≠ Deniability

| Scenario | Standard FDE | DenyFS |
|:---|:---:|:---:|
| Attacker captures your disk | ❌ Can't read data | ❌ Can't read data |
| Attacker coerces your password | ✅ Sees everything | ⚠️ Sees **outer volume only** |
| Attacker knows encrypted data exists | ✅ LUKS header is visible | ❌ Entire file looks random |
| Attacker suspects a hidden volume | N/A | ❌ **No evidence it exists** |

<details>
<summary><strong>📘 How does plausible deniability work?</strong></summary>

<br/>

The key insight is that **AES ciphertext is indistinguishable from random noise**.

1. **At creation**, DenyFS fills the entire container with cryptographically secure random bytes (CSPRNG).
2. **The outer volume** writes encrypted data into the first portion of the container.
3. **The hidden volume** (if created) writes encrypted data into the container's "free space" region.
4. Since both encrypted data and unused space are **byte-for-byte indistinguishable from random**, there is no way to determine whether the free space contains a hidden volume or is genuinely unused.

When coerced, you reveal the outer password. The adversary sees a working filesystem. They **cannot prove** that additional encrypted data exists in the remaining space.

</details>

---

## 🏗️ Architecture

### Container Layout

```
┌─────────────────────────────────────────────────────────────────────┐
│                        DenyFS Container File                         │
├──────────┬──────────────────────────────────┬────────────────────────┤
│  Header  │         Outer Volume             │   Free / Hidden Space  │
│  (4 KB)  │  (Superblock + Bitmap + Inodes   │   (CSPRNG-filled or    │
│  AES-GCM │   + Data Blocks, AES-256-XTS)    │    Hidden Volume)      │
├──────────┴──────────────────────────────────┴────────────────────────┤
│                                                    ┌──────────────┐ │
│                                                    │Hidden Header │ │
│                                                    │  (4 KB, GCM) │ │
│                                                    └──────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Hierarchy

```
Password ──── Argon2id(salt, opslimit=4, memlimit=64MB) ────► Master Key
                                                                  │
                        ┌─────────────────────────────────────────┼──────────────────┐
                        ▼                                         ▼                  ▼
                  Header Key                               Volume Key          HMAC Key
                  (AES-256-GCM)                            (AES-256-XTS)       (HMAC-SHA256)
                  Wraps header                             Encrypts all        Authenticates
                  payload containing                       file data with      allocation
                  volume key + HMAC key                    per-sector LBA      bitmap
                                                           tweaks
```

### Timing Indistinguishability Mechanism

```
                    ┌──────────────────────────────────────────────┐
                    │            denyfs_vol_open()                 │
                    ├──────────────────────────────────────────────┤
                    │                                              │
                    │  ┌─────────────────────────────────────┐     │
                    │  │  ALWAYS: KDF #1 (outer salt)        │     │
                    │  │  ALWAYS: Decrypt outer header (GCM) │     │
                    │  └─────────────────────────────────────┘     │
                    │                                              │
                    │  ┌─────────────────────────────────────┐     │
                    │  │  ALWAYS: KDF #2 (hidden salt)       │     │
                    │  │  ALWAYS: Decrypt hidden header (GCM)│     │
                    │  └─────────────────────────────────────┘     │
                    │                                              │
                    │  Check which (if any) succeeded...           │
                    │  Mount matched volume OR return generic      │
                    │  "Error: invalid password."                  │
                    │                                              │
                    │  ⏱️ Same execution path regardless of       │
                    │     which password was given or whether      │
                    │     a hidden volume exists.                  │
                    └──────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

```bash
# Ubuntu / Debian
sudo apt install build-essential libsodium-dev libssl-dev libfuse3-dev pkg-config

# Arch Linux
sudo pacman -S base-devel libsodium openssl fuse3

# macOS (Homebrew) — FUSE mount not supported, tests still run
brew install libsodium openssl macfuse
```

### Build

```bash
git clone https://github.com/Akilan4757/Denyfs.git
cd Denyfs
make all        # builds everything: denyfs binary + all tests + fuzz harnesses
make test       # runs full test suite (crypto, volume, fs, timing, stress)
```

### Run

```bash
# Create a 10MB encrypted container (prompts securely for password)
./denyfs create vault.img --size 10

# Mount it via FUSE (prompts securely for password)
mkdir -p /tmp/vault
./denyfs mount vault.img --mountpoint /tmp/vault

# Use it like a normal filesystem
echo "classified data" > /tmp/vault/secret.txt
ls /tmp/vault

# Unmount
fusermount -u /tmp/vault
```

---

## 📋 Usage

### 1️⃣ Create a Container

Creates an encrypted container filled with CSPRNG random bytes and formats the outer volume (prompts securely for password):

```bash
./denyfs create <container> --size <MB>
```

```bash
# Example: create a 50MB container (interactive)
./denyfs create secure.img --size 50

# Scripted example: read password from file descriptor 3
./denyfs create secure.img --size 50 --password-fd 3
```

### 2️⃣ Create a Hidden Volume

Formats a hidden volume inside the container's free space (prompts securely for outer and hidden passwords):

```bash
./denyfs create-hidden <container> --size <MB>
```

```bash
# Example: create a 10MB hidden volume inside a 50MB container (interactive)
./denyfs create-hidden secure.img --size 10

# Scripted example: read outer password from fd 3, hidden password from fd 4
./denyfs create-hidden secure.img --size 10 --password-fd 3 --hidden-password-fd 4
```

### 3️⃣ Mount a Volume (FUSE)

DenyFS automatically detects which volume the password unlocks:

```bash
# Mount outer or hidden volume (prompts securely for password)
./denyfs mount secure.img --mountpoint /tmp/mount
```

### 4️⃣ Mount with Hidden Volume Protection

When mounting the outer volume under coercion, protect the hidden volume from accidental overwrites:

```bash
# Mount outer volume with hidden protection (prompts for outer and hidden passwords)
./denyfs mount secure.img --protect-hidden --mountpoint /tmp/outer
```

> ⚠️ **Without `--protect-hidden`**, writing large files to the outer volume may silently overwrite hidden volume sectors — the outer volume has no knowledge of the hidden volume by design.

### 5️⃣ Authenticate (No Mount)

Verify a password without mounting:

```bash
# Authenticate (prompts securely for password)
./denyfs open secure.img
# Output: Volume opened successfully. Size: 41943040 bytes, Hidden: no
```

---

## 🛡️ Security Model

### What DenyFS Protects

| Property | Mechanism | Evidence |
|:---|:---|:---|
| **Data Confidentiality** | AES-256-XTS per-sector encryption with LBA tweaks | `test_crypto` — cipher correctness + tweak uniqueness |
| **Header Authentication** | AES-256-GCM authenticated encryption | `test_crypto` — tag verification + tamper detection |
| **Hidden Volume Deniability** | CSPRNG fill + XTS ciphertext indistinguishable from random | `test_fs` — hidden volume tests |
| **Timing Side-Channel** | Unconditional 2× KDF + 2× GCM on every open | `test_timing` — 100-trial statistical test (Δ = 5.71ms) |
| **Key Material Safety** | `sodium_malloc` / `mlock` / `memzero` + core dump disabled | ASan/UBSan clean across all suites |
| **Hidden Volume Write Guard** | Sector-range rejection returns generic `-EIO` | `test_fs` — protection boundary tests |
| **Bitmap Integrity** | HMAC-SHA256 over allocation bitmap | `test_fs` — deliberate corruption detected |

### What DenyFS Does NOT Protect Against

| Threat | Why | Mitigation |
|:---|:---|:---|
| **Repeated snapshots** | Diff reveals changed sectors in hidden region | Operational: don't give adversary multiple copies |
| **Host compromise** | Keylogger captures both passwords | Out of scope: requires trusted computing base |
| **Cold-boot / DMA** | Key material readable from physical RAM | Requires hardware memory encryption |
| **Evil-maid attack** | Tampered binary exfiltrates passwords | No code signing or reproducible builds (documented) |
| **Cloud sync** | Version history recreates snapshot problem | Never store in synced directories |

> 📄 **Full analysis:** [THREAT_MODEL.md](THREAT_MODEL.md) — 7 named adversary classes with detailed impact assessments

---

## ⚡ Benchmarks

Measured on Linux 6.6 (WSL2), gcc 15.2.0, `-O2`, AES-NI enabled:

| Operation | Result | Bottleneck |
|:---|---:|:---|
| Argon2id KDF (single call) | **201 ms** | Memory-hard by design (64 MB) |
| Volume open (2× KDF) | **403 ms** | Timing indistinguishability |
| Container create (10 MB) | **465 ms** | CSPRNG fill dominates |
| AES-256-XTS encrypt | **2,008 MB/s** | AES-NI accelerated |
| AES-256-XTS decrypt | **2,402 MB/s** | AES-NI accelerated |
| Sequential write (with I/O) | **1.81 MB/s** | `fflush` per sector (durability) |
| Sequential read (with I/O) | **13.09 MB/s** | Disk I/O + XTS |
| Peak memory (Argon2id) | **74.6 MB** | 64 MB configured + overhead |

> 📄 **Full results:** [BENCHMARKS.md](BENCHMARKS.md) — 6 benchmark categories with analysis

---

## 📁 Project Structure

```
DenyFS/
├── src/
│   ├── crypto.c          # Argon2id KDF, HKDF, AES-256-GCM, AES-256-XTS, HMAC-SHA256
│   ├── crypto.h          # Crypto constants and function declarations
│   ├── fs.c              # Filesystem layer: container create, vol open/close, file ops
│   ├── fs.h              # Filesystem types: superblock, inodes, volume struct
│   ├── fuse_ops.c        # FUSE3 callback implementations (getattr, read, write, etc.)
│   ├── fuse_ops.h        # FUSE operation declarations
│   └── main.c            # CLI entry point: create, open, mount, create-hidden
│
├── tests/
│   ├── test_crypto.c     # Phase 1: KDF, HKDF, GCM, XTS correctness
│   ├── test_volume.c     # Phase 2: Sector-level encrypt/decrypt roundtrip
│   ├── test_fs.c         # Phase 3-4: Full filesystem + hidden volume tests
│   ├── test_timing.c     # Phase 4: Timing indistinguishability (100 trials)
│   ├── test_stress.c     # Phase 6: 10 corruption/capacity/boundary stress tests
│   ├── test_bench.c      # Phase 7: Performance benchmarks (6 categories)
│   ├── fuzz_header.c     # AFL++ harness: pre-auth header parser fuzzing
│   ├── fuzz_sector.c     # AFL++ harness: XTS sector crypto fuzzing
│   └── gen_fuzz_corpus.sh# Seed corpus generator for AFL++ campaigns
│
├── Makefile              # Build system (ASan/UBSan for tests, -O2 for benchmarks)
├── README.md             # This file
├── THREAT_MODEL.md       # Adversary model, defended/undefended threats, interview Q&A
├── BENCHMARKS.md         # Performance measurements and analysis
├── BUILD_INTEGRITY.md    # Scope limitations: code signing, reproducible builds
├── PROGRESS_LOG.md       # Session-by-session development log (8 sessions)
└── DenyFS-Architecture-and-Build-Plan.md  # Design document (brain file)
```

**Source Stats:** `~2,200 lines` of C (4 source files + CLI), `~2,600 lines` of tests (7 test files + fuzz harnesses), `~1,100 lines` of documentation (5 markdown files).

---

## 🧪 Testing

### Run All Tests

```bash
make test
```

This executes all 5 test suites sequentially under **AddressSanitizer** and **UndefinedBehaviorSanitizer**:

| Suite | What it tests | Tests |
|:---|:---|---:|
| `test_crypto` | KDF, HKDF, GCM encrypt/decrypt, XTS sector crypto | 3 |
| `test_volume` | Sector roundtrip, cipher uniqueness, wrong password, bounds | 5 |
| `test_fs` | Create, lookup, read, write, readdir, truncate, unlink, persistence, hidden volume | 11 |
| `test_timing` | Timing indistinguishability over 100 Argon2id trials | 1 |
| `test_stress` | Corruption, capacity limits, rapid cycles, boundary cases | 10 |
| **Total** | | **30** |

### Run Benchmarks

```bash
make test_bench    # compiled at -O2 without ASan for accurate timing
./test_bench
```

### Run AFL++ Fuzzing

```bash
# Install AFL++
sudo apt install afl++

# Build with AFL++ instrumentation
CC=afl-gcc make fuzz_header fuzz_sector

# Generate seed corpus
bash tests/gen_fuzz_corpus.sh

# Fuzz the header parser (pre-auth attack surface)
afl-fuzz -i fuzz_corpus_header -o fuzz_findings_header -- ./fuzz_header @@

# Fuzz the sector crypto
afl-fuzz -i fuzz_corpus_sector -o fuzz_findings_sector -- ./fuzz_sector @@
```

---

## 🔬 How It Works — Deep Dive

<details>
<summary><strong>1. Container Creation</strong></summary>

```
1. Generate 10 MB of CSPRNG random bytes → write to file
   (This is why free space is indistinguishable from encrypted data)

2. Generate random salt (16 bytes)
3. Argon2id(password, salt) → Master Key (32 bytes)
4. HKDF-Expand(Master Key, "DenyFS Header Key V1") → Header Key (32 bytes)
5. Generate Volume Key (64 bytes for XTS) + HMAC Key (32 bytes)

6. Encrypt header payload (magic + keys + metadata) with AES-256-GCM
   → Produces: salt | IV | tag | ciphertext (written at byte 0)

7. Format filesystem:
   - Superblock (block 0): magic, block size, inode count, bitmap pointer
   - Allocation bitmap (blocks 1-N): one bit per data block
   - Inode table (blocks N+1-M): 64 fixed inodes
   - Data blocks (blocks M+1-end): file content storage

8. Encrypt each metadata/data block with AES-256-XTS(Volume Key, LBA)
```

</details>

<details>
<summary><strong>2. Volume Open (The Deniability Mechanism)</strong></summary>

```
Given: password P, container file C

1. Read outer header (bytes 0-4095)
2. Read hidden header (bytes EOF-32768 to EOF-32768+4095)

3. UNCONDITIONALLY (no short-circuit):
   a. KDF #1: Argon2id(P, outer_salt) → outer_master → outer_header_key
   b. KDF #2: Argon2id(P, hidden_salt) → hidden_master → hidden_header_key

4. UNCONDITIONALLY:
   a. AES-GCM decrypt outer header → check magic
   b. AES-GCM decrypt hidden header → check magic

5. If outer magic matches → mount outer volume
   If hidden magic matches → mount hidden volume
   If neither matches → "Error: invalid password."

Steps 3-4 ALWAYS execute both paths regardless of outcome.
This makes "wrong password" and "right password, no hidden volume"
timing-identical (verified: Δ = 5.71ms over 100 trials).
```

</details>

<details>
<summary><strong>3. Sector Encryption (AES-256-XTS)</strong></summary>

```
For each 4096-byte sector at logical block address LBA:

  Tweak = LBA encoded as 16-byte little-endian IV
  Ciphertext = AES-256-XTS-Encrypt(Volume Key, Tweak, Plaintext)

Properties:
  ✅ Same plaintext at different LBAs → different ciphertext
  ✅ No expansion (ciphertext = plaintext size)
  ✅ Random read/write access (no chaining between sectors)
  ❌ No authentication (by design — see THREAT_MODEL.md §6)
```

</details>

<details>
<summary><strong>4. Hidden Volume Architecture</strong></summary>

```
Container layout with hidden volume:

  Byte 0          Byte 4096                              EOF-32KB  EOF
  ┌──────┬─────────────────────────────┬───────────────┬──────────┐
  │Outer │     Outer Volume Data       │ Hidden Volume │ Hidden   │
  │Header│  (encrypted, visible when   │ Data (looks   │ Header   │
  │(GCM) │   outer password given)     │ like random   │ (GCM)    │
  │      │                             │ free space)   │          │
  └──────┴─────────────────────────────┴───────────────┴──────────┘
          ↑                             ↑               ↑
     Outer sees this              Invisible to        Only decryptable
     as its filesystem            outer volume        with hidden password

Key insight: The outer volume's bitmap only tracks outer-volume blocks.
Hidden-volume blocks are OUTSIDE the outer bitmap's scope — the outer
filesystem genuinely doesn't know they exist.
```

</details>

---

## 🔐 Cryptographic Primitives

| Primitive | Standard | Use in DenyFS | Library |
|:---|:---|:---|:---|
| **Argon2id** | RFC 9106 | Password → Master Key | libsodium |
| **HKDF-Expand** | RFC 5869 | Master Key → Header Key | OpenSSL HMAC |
| **AES-256-GCM** | NIST SP 800-38D | Header encryption (authenticated) | OpenSSL EVP |
| **AES-256-XTS** | IEEE 1619-2007 | Sector encryption (disk mode) | OpenSSL EVP |
| **HMAC-SHA256** | RFC 2104 | Bitmap integrity authentication | OpenSSL HMAC |

---

## ⚠️ Known Limitations

| Limitation | Details |
|:---|:---|
| **Flat directory structure** | No subdirectories — single root directory only |
| **Max file size** | 96 KB (24 direct blocks × 4096 bytes) |
| **Max files per volume** | 63 files (64 inodes, inode 0 = root directory) |
| **No dynamic resize** | Container and volume sizes are fixed at creation |
| **No build integrity** | No code signing or reproducible builds — see [BUILD_INTEGRITY.md](BUILD_INTEGRITY.md) |
| **Snapshot vulnerability** | Multiple captures over time can reveal hidden volume activity |

These are **stated scope limitations**, not bugs. A production system would address them; DenyFS prioritizes understanding the cryptographic and deniability properties over feature completeness.

---

## 📚 Documentation

| Document | Contents |
|:---|:---|
| [THREAT_MODEL.md](THREAT_MODEL.md) | Complete adversary model, 7 undefended threat classes, security property evidence matrix, interview Q&A |
| [BENCHMARKS.md](BENCHMARKS.md) | 6-category performance benchmarks with analysis |
| [BUILD_INTEGRITY.md](BUILD_INTEGRITY.md) | Scope limitations around code signing, reproducible builds, supply-chain integrity |
| [PROGRESS_LOG.md](PROGRESS_LOG.md) | Session-by-session development log documenting all 8 phases |
| [Architecture Doc](DenyFS-Architecture-and-Build-Plan.md) | Full design document with cryptographic rationale |

---

## 🗺️ Development Roadmap

- [x] **Phase 1** — Crypto Core: Argon2id KDF, HKDF, AES-256-GCM, AES-256-XTS
- [x] **Phase 2** — Sector I/O: Encrypted read/write with LBA tweaks
- [x] **Phase 3** — Filesystem: Superblock, bitmap, inodes, directories, FUSE
- [x] **Phase 4** — Deniability Hardening: Timing, memory hygiene, write guard
- [x] **Phase 5** — Build Integrity Note: Scope limitations documented
- [x] **Phase 6** — Fuzzing & Stress Tests: AFL++ harnesses, 10 stress tests
- [x] **Phase 7** — Benchmarks: 6-category performance measurements
- [x] **Phase 8** — Threat Model & Writeup: Complete security analysis

---

## 🤝 Contributing

This is a portfolio/research project demonstrating cryptographic engineering principles. Issues and discussions are welcome. If you find a bug in the crypto code, please open an issue.

---

## 📜 License

This project is available under the [MIT License](LICENSE).

---

<p align="center">
  <sub>Built with deliberate engineering by <a href="https://github.com/Akilan4757">@Akilan4757</a></sub>
</p>
