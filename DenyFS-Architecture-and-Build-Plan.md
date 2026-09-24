# DenyFS — Deniable Encrypted Container with Hidden Volumes

**Single source of truth for design, build sequencing, and rationale.**
Everything here should stay in sync with the code — if you change an approach, update this doc in the same commit.

**Revision note:** this document records the current format, implementation choices, and known limits. It distinguishes implemented behavior from design goals and test evidence; it is not a claim that deniability or timing behavior has been formally proven.

---

## 0. What this project actually is (plain-English version)

If you're not deep into tech, here's the idea in normal words:

Imagine a locked box. You give someone the password, they open it, and they see some files — nothing dramatic, just regular documents. What they don't know is that inside that same box, in the space that looks like empty padding, there's a second, completely different set of files, locked with a different password. Without that second password, an observer cannot find or open that second layer.

That's a **hidden volume** — the same idea VeraCrypt (a real, widely used open-source tool) uses. It exists for one specific problem: **making it costly, not impossible, for someone with access to the file to prove a second layer exists.**

That last phrasing is deliberately more careful than "there is no way to prove it exists." Read §9 (Threat Model) before treating this as a guarantee — there are real, known adversaries (repeated snapshots of the file over time, forensic memory capture, a compromised endpoint) against which this property degrades or fails outright. This document says so explicitly rather than overselling.

**Where this is actually useful in the real world:**
- **Journalists and activists crossing borders** where officials can legally compel a device unlock. The outer password reveals ordinary files; there's no easy signature proving a second layer exists — but see §9 for what "no easy signature" does and doesn't cover.
- **People fleeing domestic abuse** who need to keep certain documents inaccessible to a partner who has device access and can pressure them for a password.
- **Whistleblowers and sources** working with journalists, needing storage that survives a forced-unlock scenario without an obvious "something's missing" signal.
- **General privacy-conscious backup**, independent of any coercion scenario.

**Why this is a good portfolio project, separately from the use case above:** it forces real understanding of applied cryptography — key derivation, authenticated vs. unauthenticated encryption, side-channel elimination, memory hygiene, and honest threat-modeling — instead of calling a library function once. The interesting problem isn't "encrypt a file," it's "make the *absence of evidence* itself a property you can defend under questioning."

**What this is not:** a claim of "unbreakable," a replacement for operational security, or a tool that protects you if the device itself is compromised (keylogger, malware, seized while mounted). §9 lists this explicitly.

---

## 1. Stack

| Layer | Choice | Why |
|---|---|---|
| Language | C, built with `-fsanitize=address,undefined` in all dev/test builds, `-D_FORTIFY_SOURCE=2 -fstack-protector-strong` in release builds | This is a security tool; a memory-safety bug in the header parser is not a side issue, it *is* the vulnerability. ASan/UBSan run in Phase 1 onward, not bolted on at the end. |
| Crypto | OpenSSL EVP (AES-256-XTS, AES-256-GCM) | Industry-standard, audited, no hand-rolled primitives |
| KDF | libsodium `crypto_pwhash` (Argon2id) | Memory-hard, resists GPU/ASIC brute force |
| Memory hygiene | libsodium secure allocation and wiping helpers; CLI requests `setrlimit(RLIMIT_CORE, 0)` and warns if the request fails | See §7. The current implementation does not separately check the memory-lock result. |
| Randomness | libsodium `randombytes_buf()` streamed in fixed-size chunks for container fill; the same system CSPRNG API supplies salts, nonces, and keys | The implementation uses libsodium's system-backed random generator. It writes a bounded 64 KiB fill buffer at a time. Creation reports total elapsed time, but does not currently separate or report observed entropy throughput. |
| Filesystem interface | libfuse3 | Standard way to expose a custom filesystem in userspace on Linux |
| Platform | Linux only | Keeps scope sane; loopback + FUSE semantics are Linux-native |

---

## 2. Container Format Spec

This section previously described a header and a vague "free space region" without ever saying where actual file *data* lives. That was the root cause of three separate open questions in review. Fixed here by specifying the outer volume's on-disk layout completely.

```
[Byte 0 – 4095]         Outer volume header (AES-256-GCM, key from outer password)
                         Contains: random salt, random IV, GCM tag, and encrypted
                         payload with the wrapped outer volume/HMAC keys and size.

[Byte 4096 – N]          Outer volume data region — this is DenyFS's own minimal
                         filesystem (superblock + block allocation bitmap + flat
                         inode table + directory entries; see §4, Phase 3). Outer
                         files physically live here. This region is exactly as
                         large as the outer volume's declared size.

[Byte N – EOF]           Remainder of the container. Filled with CSPRNG output at
                         creation. The hidden volume's header AND its data both
                         live somewhere inside this region — see hidden volume
                         layout below. Everything not part of an actual hidden
                         volume stays true random fill.

[Fixed offset: EOF-32KB] Hidden header location. NOT a password-derived offset
                         (see rationale below) — fixed at container-format level,
                         disguised as part of the random tail. Contains its own
                         random salt, random IV, GCM tag, and encrypted payload.
```

**Where hidden volume data physically lives, and why the outer volume can't stomp on it:** the hidden volume occupies a contiguous block range at the *end* of the free-space region, sized at creation time and recorded (encrypted) only in the hidden header. The outer volume's allocation bitmap (§4) is only ever consulted for outer writes, and outer writes are hard-capped to the outer volume's declared size from Byte 4096 forward — the outer filesystem literally cannot address blocks past its own declared boundary under normal operation. That handles the *no-hidden-volume-configured* case for free.

**That alone is not enough — it does not stop a user from later changing the format or from a bug bypassing the cap.** So DenyFS also has an explicit **outer-mount protection** option.

- `denyfs mount container.img --mountpoint DIR` — prompts for one password and mounts whichever volume that password opens. Without the hidden password, DenyFS does not know the hidden range.
- `denyfs mount container.img --protect-hidden --mountpoint DIR` — prompts for **both** passwords. It computes the hidden range from the authenticated hidden header and rejects outer writes that target the protected range. If the hidden password is wrong, the protected mount is refused.

**Why the hidden header uses a fixed offset:** a password-derived offset would require the program to know where to look before it validates the password and could add a full-file scan. A fixed, publicly known slot simplifies lookup. Its salt, IV, tag, and ciphertext are intended to look random when the slot is not decryptable; this is a design goal, not a guarantee against all analysis.

**Salt handling:** the salt used in `Argon2id(password, salt)` for each header is public and randomly generated when that header is created. It is stored in the header's first 16 bytes. Salts are not secret in a properly designed KDF — only the password is. The outer and hidden headers have independent salts.

**Consistent terminology:** the header carries no plaintext `DenyFS` magic or signature. Its salt, IV, GCM tag, and ciphertext are intended to look random; this is a cryptographic design goal, not a guarantee against all analysis.

**Design decisions, locked before coding:**
- Fixed total container size, chosen at creation (e.g. 100MB). No dynamic resizing.
- Single hidden volume only — no nesting.
- All non-file bytes are CSPRNG output, streamed at creation, never zero-filled.

---

## 3. What "failed to decrypt" looks like from the outside — the previously-missing mechanism

AES-GCM gives an unambiguous pass/fail signal for a header. DenyFS hides which header attempt failed behind one generic failure result, while making both attempts on every open. It does not claim that a successful outer password is indistinguishable from a wrong password.

1. `denyfs open` always attempts, in fixed order: (a) derive a key and decrypt the outer header with the supplied password, (b) derive a key and decrypt the fixed hidden-header slot with the same password. Both attempts run even when the first one succeeds.
2. This gives failed-password attempts the same cryptographic work shape: two Argon2id calls and two AES-GCM decrypt attempts. It is not a fixed-time guarantee. Allocation, KDF failure, storage, scheduling, and later filesystem validation can affect elapsed time.
3. If neither header authenticates, the CLI reports `Error: invalid password.` A wrong password against an outer-only container and a wrong password against a container with a hidden volume follow the same two-header attempt sequence. A correct outer password succeeds and opens the outer volume, whether or not a hidden volume exists.
4. On success, DenyFS mounts whichever header matched and does not print the status of the other header attempt. The fixed-work design and its limited timing test are evidence, not a proof of universal indistinguishability.

This is the concrete mechanism used by the implementation. The timing test checks one comparison on one host; it is not a proof that timing is indistinguishable on every platform.

---

## 4. Phased Build Plan

### Phase 0 — Design lock
Deliverable: this document, reviewed and stable, before any code. All decisions in §2–§3 are final before Phase 1 starts.

### Phase 1 — Crypto core (pure library, no FUSE, no filesystem yet)
- Key hierarchy (previously missing — "Argon2id → AES key" was too flat to support the header/volume split this design actually needs):

  ```
  Password ──Argon2id(random salt)──► Master Key
                                           │
                                           ▼
                         HKDF-Expand(context string)
                                           │
                                           ▼
                                    Header Key
                                  (AES-256-GCM)
                                           │
                                           ▼
                             Authenticated header payload
                             ├── random Volume Key (AES-256-XTS)
                             └── random HMAC Key (bitmap HMAC)
  ```
  The header keys are randomly generated, then wrapped by the GCM-protected header payload; they are not direct HKDF outputs. XTS gives no authentication at all — changed ciphertext can silently decrypt to changed plaintext. The current filesystem authenticates the allocation bitmap with its HMAC. Other metadata and file data do not have per-block authentication; the mount path validates filesystem structure and bounds before using it.
- Volume encryption: AES-256-XTS via OpenSSL EVP (`EVP_aes_256_xts`), sector-based, tweak = logical block address relative to the *volume's own* start (outer volume LBA 0 = byte 4096; hidden volume LBA 0 = its own recorded start — this is computed once at mount time and fixed for the mount's duration, closing the "sector numbering shifts if the hidden offset is dynamic" risk raised in review, since the offset is now fixed per §2 anyway).
- Header encryption: AES-256-GCM, per the mechanism in §3.
- CLI: `denyfs create`, `denyfs open` for authentication, and `read-sector` / `write-sector` for raw block experiments. Passwords are prompted or read from file descriptors, not command-line values.
- **Gate:** cipher output verified against published NIST/OpenSSL test vectors. ASan/UBSan clean on the full test run.

### Phase 2 — Volume mounting (raw, no FUSE)
**Decision, not an "or":** DenyFS does its own decryption in userspace and exposes the result through FUSE. It does **not** use a kernel dm-crypt/loopback path with a standard filesystem on top. Reasoning: dm-crypt has no concept of a hidden volume or password-selected mount target — you'd need userspace logic to pick *which* key to hand the kernel before mounting, at which point you've built the interesting part anyway and gained nothing from also involving dm-crypt. Since FUSE is the real path, Phase 2 exists only to validate raw sector decrypt/encrypt correctness before the filesystem layer sits on top of it.
- `denyfs open container.img` authenticates a volume. `read-sector` and `write-sector` exercise raw logical-sector encryption using a password prompt or password file descriptor.
- **Gate:** write known data, close, reopen, byte-identical.

### Phase 3 — Filesystem layer (the part that was previously undefined)
Two things happen in this phase, not one — FUSE glue, and the actual filesystem metadata design, which is the real engineering content review kept flagging as missing.

**3a. On-disk metadata format (this is DenyFS's own, not ext4/FAT via loopback — see Phase 2):**
- Superblock: volume size, block size (4096B), inode count, pointer to bitmap.
- Block allocation bitmap: one bit per block, integrity-protected with the HMAC key from Phase 1 (separate from the GCM header tag — see rationale above). Checked on mount; a failed check refuses mount with a generic error, not a crash.
- Flat inode table: fixed max file count decided at creation (portfolio-scope limitation, stated explicitly rather than silently — a production filesystem would need dynamic inode allocation, DenyFS does not).
- File block mapping: 20 direct data pointers plus single- and double-indirect 4096-byte pointer tables; 64-bit file lengths allow a maximum 4 GiB file. Keep the 64-inode limit (63 files) explicit.
- Format version: the expanded inode layout uses superblock magic `DenyFS03`. DenyFS02 containers are not automatically migrated; users must export data using the old build and recreate containers.
- Directory entries: name → inode mapping, flat directories only (no need to build a general tree-balancing structure for this scope — stated as a scope limitation, not hidden).

**3b. FUSE operations**, now including the two that were missing from the original op list: `getattr`, `read`, `write`, `readdir`, `open`, `truncate`, **`create`, `unlink`**. Without create/unlink this wasn't a filesystem, it was a read-only view of one — fixed.
- Every FUSE handler maps onto: bitmap lookup → sector read/write via the Phase 1/2 crypto layer → inode/directory update. This mapping is now fully specified by 3a, closing the "map onto what, exactly" gap from review.
- **Gate:** mount, `cp` files in and out normally (including creating and deleting files, not just reading pre-existing ones), unmount, remount, verify integrity, verify bitmap integrity check catches deliberate corruption.

### Phase 4 — Deniability hardening (non-negotiable — see §8 for why this is no longer framed as optional under any timeline)
- **External-observable check:** use the fixed-order, two-header attempt sequence and one generic error for failed authentication. Describe it as equal cryptographic work, not fixed wall-clock time. A correct outer password succeeds and opens the outer volume regardless of whether a hidden volume exists.
- **Metadata/log audit — named, not generic.** User-visible host-system leaks remain outside the container format and need operational controls:
  - `/tmp`, shell history, journalctl — original scope, still checked.
  - **Container timestamps** on the host filesystem — the program requests `O_NOATIME` and falls back if permission is denied. Host behavior and writes can still affect timestamps.
  - **Desktop indexers**: `tracker`, `baloo`, GNOME/KDE file indexing — these can index filenames or content the moment a FUSE mount exposes them. Document that users must exclude the mount point from indexer scope; DenyFS cannot prevent a system-level indexer from running, only warn about it.
  - **GVFS** — if the mount point is ever exposed through the desktop's virtual filesystem layer, thumbnail/preview caches can leak filenames. Same treatment: documented user-facing warning, not a code-level fix, because it's outside DenyFS's control.
  - **systemd-journald mount/unmount logging** — `journalctl` will show FUSE mount/unmount events by default. Document (not silently accept) that users needing full deniability of *usage timing*, not just content, need journald log rotation/scrubbing as an operational step outside this tool's scope.
  - This list is the audit. Anything added later gets added here by name, not folded into "eliminate leaks."
- **Memory hygiene (previously entirely absent — this was issue #8 in two consecutive reviews and is fixed here, not deferred again):**
  - Password and key buffers use `sodium_malloc` through `denyfs_secure_alloc()` and are wiped with `sodium_memzero` before release. The implementation does not separately check that libsodium successfully locked each allocation; do not claim swap protection if locking fails.
  - `setrlimit(RLIMIT_CORE, 0)` at process start — the program warns if the request fails and cannot guarantee every host honors it.
  - Explicitly out of scope: protection against cold-boot / RAM-remanence attacks. Memory locking, when successful, reduces swap exposure; it does not defend against a physical RAM attack against a machine seized while mounted. This limitation is carried into §9.
- **Timing:** secret comparisons use `sodium_memcmp`; ordinary filesystem names and structural values are not secrets and use normal comparisons. The current timing test is a limited regression check, not a universal guarantee.
- **Gate:** explain the fixed-work attempt sequence and its limits. A timing test can compare selected distributions on a named host; it cannot prove that every observer or platform sees indistinguishable timing.

### Phase 5 — Build integrity note (short, scoped honestly)
Not a full phase — a documented limitation. A tampered or backdoored `denyfs` binary defeats every property above, and this project does not implement reproducible builds, code signing, or a supply-chain integrity story. Stated explicitly in §9 as an out-of-scope adversary rather than silently assumed away.

### Phase 6 — Threat model + writeup
See §9. This is the section to rehearse for an interview — it's what shows the difference between "encrypted" and "deniable," and it's now the section with the fewest gaps left in it.

### Phase 7 — Test suite
- Seeded correctness cases: correct outer password, correct hidden password, wrong password, corrupted header, corrupted hidden region, corrupted allocation bitmap, and malformed decrypted filesystem metadata.
- Optional live FUSE smoke check: `make test-fuse` exercises mount, create, write, read, truncate, readdir, unlink, and unmount when `/dev/fuse` and `fusermount3` are available.
- Timing regression check: compare failed-password opens for an outer-only container and a container with a hidden volume. The current test uses 50 trials and a 15 ms mean-difference threshold. This is a narrow regression signal, not statistical proof of universal indistinguishability.
- Fuzz the header crypto path and filesystem metadata validators. The current `fuzz_header` harness exercises a fixed-size GCM header decrypt and a few payload checks; it does not invoke the complete `denyfs_vol_open` path or fuzz the superblock/inode validators.
- Fuzz the FUSE operations that exist (create, unlink, read, write, truncate, readdir) after a live FUSE test setup is available. Rename is not implemented.

**Current verification status:** `make all`, the full `make test` suite, and `make test-fuse` pass in WSL Ubuntu. The stress suite exercises the final byte of a sparse 4 GiB file through double-indirect mapping, closes/reopens it, and verifies persistence. The live FUSE smoke also writes and reads that final byte. These tests verify the logical size and mapping, not a 4 GiB physical fill. The 50-trial failed-open timing comparison uses interleaved container types and passed the 15 ms regression threshold. AFL++ is not installed here, so extended campaigns remain unrun; the current harnesses do not fuzz the complete `denyfs_vol_open` metadata parser.

### Phase 8 — Benchmarks (previously entirely absent)
Recorded and included in the final writeup, not just run ad hoc:
- Container creation time (dominated by CSPRNG fill — reported separately from crypto setup time so entropy-pool slowness is visible, per §1).
- Mount time (Argon2id cost is intentional and should be reported, not hidden — e.g. "mount takes ~800ms by design, this is the memory-hardness working as intended").
- Sequential read/write throughput (MB/s) at 4KB sector granularity, encrypted vs. a plaintext baseline for comparison.
- Peak memory usage during Argon2id (this number should roughly match the configured Argon2id memory parameter — reported as a sanity check).

---

## 5. Where an AI coding assistant helps vs. where it can't do the thinking for you

| Helps a lot | Doesn't help — you have to understand it |
|---|---|
| Phase 3b: FUSE callback boilerplate | Phase 2/3a: filesystem metadata design decisions |
| Phase 7: test harness scaffolding | Phase 4: the external-observable mechanism in §3 — this is a design property, not a code pattern |
| General EVP wrapper code | §9: naming your own project's actual weaknesses honestly |

Boilerplate being AI-written doesn't mean it's unreviewed — an off-by-one in a generated `truncate()` handler is still a bug you're responsible for, in a project where the bug *is* the vulnerability class this whole thing is about avoiding.

---

## 6. Terminology framing for interviews

If asked "why should I care, VeraCrypt already exists": the answer is *"I intentionally restricted scope to understand every primitive involved in building a deniable storage system — the objective was never to replace VeraCrypt, it was to understand, well enough to defend under questioning, why VeraCrypt's design choices are the ones they are."* Never claim "I built VeraCrypt."

---

## 7. Password/key lifetime summary (cross-reference to Phase 4, kept here for quick lookup)

- Raw password: read into a `sodium_malloc`'d buffer immediately, never touches a regular `char[]`. libsodium's secure allocator attempts to lock the allocation; this program does not separately inspect or enforce the lock result.
- Master/header keys: derived into secure buffers. Volume and HMAC keys are random values wrapped by the authenticated header and held in secure buffers while mounted. Buffers are wiped with `sodium_memzero` before release.
- No key material is ever passed to a logging call, `printf`, or written to any file, including debug builds — debug builds redact key buffers by construction, not by convention.

---

## 8. Resolving the Phase 4 contradiction directly

An earlier draft of this document named Phase 4 "the part that actually matters" and, separately, listed Phase 4 as the first thing to compress under a tight deadline. Those two statements can't both be true, and leaving them both in the document was a prioritization error, not a wording nit.

**Resolved position:** the two-header attempt sequence and careful secret handling are core design requirements. They reduce specific risks, but they do not prove universal deniability or fixed-time execution. A version of DenyFS without them would have weaker claims and should be documented accordingly.

**What actually is compressible under a tight deadline**, in order:
1. Phase 8 (benchmarks) — useful for the writeup, not load-bearing for the design.
2. Phase 7's fuzzing depth — keep harnesses and regression checks; extended AFL campaigns are a separate effort.
3. Phase 3a's filesystem feature completeness — flat directories, fixed inode count, and no dynamic resize are already scoped-down; further reduction (e.g., smaller fixed file count) is fine and should just be stated as a scope limitation, same as the others.
4. §5's documented-but-unimplemented items (build integrity, cold-boot resistance) can stay documented-only indefinitely — they were never scheduled for implementation in the first place, so there's nothing to cut.

If a hardening item is incomplete, name it and its limits in the writeup instead of presenting the deniability goal as a proven guarantee.

---

## 9. Threat Model

**Explicit adversary model — what DenyFS defends against:**
Adversary has physical access to the container file and can coerce the outer password. Adversary cannot brute-force AES-256 or Argon2id. Adversary cannot obtain the hidden password. Adversary can inspect the container file's bytes and the host filesystem's ordinary metadata (with the mitigations in Phase 4 applied).

**Adversaries DenyFS explicitly does NOT defend against — stated here rather than omitted:**
1. **Repeated snapshots over time.** An adversary who captures the container file at multiple points in time and can diff them may observe that the "free space" region changed in a location consistent with hidden-volume activity, even without decrypting anything. This is a structural limitation of the hidden-volume approach in general (VeraCrypt shares it), not a bug specific to this implementation, and there is no code-level fix — only operational advice (avoid giving an adversary multiple historical copies of the container).
2. **Malware, root compromise, or a keylogger on the host** while DenyFS is in use. If the machine is compromised, both passwords can simply be captured as they're typed, independent of anything this project does.
3. **Cold-boot / RAM-remanence attacks.** The secure allocator attempts memory locking where supported, but the application does not verify success and does not defend against a physical attack that reads DRAM contents after power loss. Named explicitly here rather than left as a silent gap (see Phase 4).
4. **DMA attacks** against a live, mounted system (e.g. via Thunderbolt) — out of scope; would require IOMMU-level protections outside this project.
5. **Evil-maid attacks** — a tampered device or a swapped/backdoored `denyfs` binary. See Phase 5: no reproducible-build or code-signing story exists yet.
6. **A compromised kernel** — FUSE operates in userspace, but the kernel mediates all I/O to it; a compromised kernel can observe everything regardless of anything in userspace.
7. **Cloud backup / sync leakage** — if the container file is synced to a cloud backup service, that service may retain historical versions, recreating the repeated-snapshot problem (#1) outside the user's control.

**Why listing these matters more than it might seem:** a security tool that doesn't say what it *doesn't* do is more dangerous than one that's silent about security entirely, because someone might rely on it for exactly the wrong scenario. This list is the actual interview material — being asked "what about a cold-boot attack" and having a considered, honest, previously-written answer is a stronger interview outcome than either an unprepared "I hadn't thought about that" or an overconfident false claim of coverage.
