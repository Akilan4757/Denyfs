# DenyFS — Deniable Encrypted Container with Hidden Volumes

**Single source of truth for design, build sequencing, and rationale.**
Everything here should stay in sync with the code — if you change an approach, update this doc in the same commit.

**Revision note:** this version closes every open question raised in review. Three things had been silently unresolved across multiple sections — the outer volume's on-disk metadata format, what a failed header check looks like from the outside, and what happens to key material in RAM — and all three are now decided, not deferred. The one internal contradiction (calling Phase 4 "the part that actually matters" and then pre-authorizing it as the first thing to cut) has been removed; see §8.

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
| Memory hygiene | libsodium `sodium_mlock` / `sodium_munlock` / `sodium_memzero`, `setrlimit(RLIMIT_CORE, 0)` | See §7 — key material handling is a first-class design concern, not an afterthought |
| Randomness | `getrandom()` (blocking mode, not `GRND_NONBLOCK`) streamed in fixed-size chunks, never buffered whole in memory | Blocking mode avoids returning low-quality randomness on an under-seeded fresh VM; streaming avoids holding tens of MB of sensitive random fill in a single unlocked buffer. Container creation logs and reports observed throughput so slow entropy pools are visible to the user, not silently eaten. |
| Filesystem interface | libfuse3 | Standard way to expose a custom filesystem in userspace on Linux |
| Platform | Linux only | Keeps scope sane; loopback + FUSE semantics are Linux-native |

---

## 2. Container Format Spec

This section previously described a header and a vague "free space region" without ever saying where actual file *data* lives. That was the root cause of three separate open questions in review. Fixed here by specifying the outer volume's on-disk layout completely.

```
[Byte 0 – 4095]         Outer volume header (AES-256-GCM, key from outer password)
                         Contains: no identifiable signature (see below), wrapped
                         outer volume key, outer volume size, outer allocation
                         bitmap location.

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
                         disguised as part of the random tail. Encrypted with a
                         key derived from the hidden password.
```

**Where hidden volume data physically lives, and why the outer volume can't stomp on it:** the hidden volume occupies a contiguous block range at the *end* of the free-space region, sized at creation time and recorded (encrypted) only in the hidden header. The outer volume's allocation bitmap (§4) is only ever consulted for outer writes, and outer writes are hard-capped to the outer volume's declared size from Byte 4096 forward — the outer filesystem literally cannot address blocks past its own declared boundary under normal operation. That handles the *no-hidden-volume-configured* case for free.

**That alone is not enough — it does not stop a user from later resizing/reusing that space, or from a bug bypassing the cap.** So DenyFS also implements the same mechanism VeraCrypt uses: **outer-mount protection.**

- `denyfs open container.img --outer-password X` — mounts only the outer volume. No protection is possible because the tool doesn't know where the hidden volume is (this is correct — it's what preserves deniability when the hidden password isn't being used at all).
- `denyfs open container.img --outer-password X --protect-hidden` — prompts for **both** passwords. Computes the hidden volume's block range from the hidden header, marks those blocks off-limits in the *in-memory* (never written to the outer header) allocation state, and any outer write instruction targeting that range returns `ENOSPC` instead of succeeding. This is the explicit, documented answer to "what stops the outer volume from overwriting the hidden volume" — previously unanswered.

**Why the hidden header moved from "password-derived offset" to a fixed offset:** a password-derived offset sounds more clever but creates three unsolved problems raised in review — how the program finds the offset before it knows which password is correct, what happens when two different passwords hash near each other, and how you avoid a full-file scan (itself a timing side-channel) to locate it. A **fixed, publicly-known offset** for the header slot removes all three problems. It does not weaken deniability: the header ciphertext at that offset is indistinguishable from random fill either way, and a fixed offset is exactly how VeraCrypt's own outer/hidden header pair works — the secrecy lives entirely in the key, not in the location, which is the correct place for it to live.

**Salt handling:** the salt used in `Argon2id(password, salt)` for header decryption is **public and fixed** in the container format (stored unencrypted right before the header slot). Salts are not secret in a properly designed KDF — only the password is. Stating this explicitly closes the "where does the salt come from before the password is known" gap from review.

**Consistent terminology:** the header carries **no identifiable magic bytes or signature of any kind** — not "obfuscated," not "absent," just genuinely indistinguishable from the random fill around it. (Previous drafts used "obfuscated/absent" in one place and "no identifiable signature" in another — that inconsistency is resolved in favor of the stronger, simpler claim.)

**Design decisions, locked before coding:**
- Fixed total container size, chosen at creation (e.g. 100MB). No dynamic resizing.
- Single hidden volume only — no nesting.
- All non-file bytes are CSPRNG output, streamed at creation, never zero-filled.

---

## 3. What "failed to decrypt" looks like from the outside — the previously-missing mechanism

This is the sharpest gap review identified: Phase 1 uses AES-GCM specifically because it gives an unambiguous pass/fail signal on decrypt, and Phase 4 requires that wrong-password attempts be indistinguishable from right-password ones. Those two facts are only in tension if the pass/fail signal is allowed to leak *outward*. It's fixed by controlling exactly what happens at the boundary between "internal cryptographic result" and "what the user or an observer sees":

1. `denyfs open` always attempts, in fixed order and fixed time regardless of outcome: (a) decrypt outer header with the given password, (b) decrypt the fixed hidden-header slot with the same password.
2. **Exactly one of four internal outcomes occurs** (outer succeeds / hidden succeeds / both fail / — outer and hidden headers use independent keys so "both succeed" cannot happen by design). All four paths execute the same number of AES-GCM verification calls, the same number of memory operations, and take statistically indistinguishable wall-clock time (verified in Phase 6, see below) — this is enforced by never short-circuiting on the first success.
3. **External behavior is identical for "wrong password" and "correct password but this container has no hidden volume":** both produce exactly `Error: invalid password.` No stack trace, no distinct exit code, no timing tell. The tool never reports *which* stage failed, whether a hidden header slot decrypted successfully, or whether a hidden volume exists at all.
4. On success, DenyFS mounts whichever volume matched and gives no external indication that another (unattempted) password might exist.

This is the concrete mechanism that was previously only asserted as a principle ("any difference is a side channel — fix until indistinguishable") without ever specifying what "fixed" means operationally. Phase 6 now includes the specific test that proves it (see below).

---

## 4. Phased Build Plan

### Phase 0 — Design lock
Deliverable: this document, reviewed and stable, before any code. All decisions in §2–§3 are final before Phase 1 starts.

### Phase 1 — Crypto core (pure library, no FUSE, no filesystem yet)
- Key hierarchy (previously missing — "Argon2id → AES key" was too flat to support the header/volume split this design actually needs):

  ```
  Password ──Argon2id(salt)──► Master Key
                                   │
              ┌────────────────────┼────────────────────┐
              ▼                    ▼                     ▼
        Header Key            Volume Key            HMAC/Integrity Key
        (AES-256-GCM,         (AES-256-XTS,          (used only for the
         wraps everything      encrypts the           allocation bitmap's
         below it)              actual file data,      integrity check —
                                 tweak = LBA)            separate from GCM,
                                                          see Phase 3)
  ```
  Rationale for splitting Volume Key from HMAC Key: XTS gives no authentication at all — flipping one ciphertext block silently flips plaintext on decrypt, it doesn't error. That's correct and intentional for a disk-encryption primitive (see Phase 3 note on why XTS, not GCM, for the body), but it means integrity for filesystem *metadata* (the allocation bitmap, specifically — corruption there is a data-loss risk, not just a confidentiality one) needs its own authenticated check, separate from the header's GCM tag.
- Volume encryption: AES-256-XTS via OpenSSL EVP (`EVP_aes_256_xts`), sector-based, tweak = logical block address relative to the *volume's own* start (outer volume LBA 0 = byte 4096; hidden volume LBA 0 = its own recorded start — this is computed once at mount time and fixed for the mount's duration, closing the "sector numbering shifts if the hidden offset is dynamic" risk raised in review, since the offset is now fixed per §2 anyway).
- Header encryption: AES-256-GCM, per the mechanism in §3.
- CLI first: `denyfs create`, `denyfs open <password>` reading/writing raw bytes.
- **Gate:** cipher output verified against published NIST/OpenSSL test vectors. ASan/UBSan clean on the full test run.

### Phase 2 — Volume mounting (raw, no FUSE)
**Decision, not an "or":** DenyFS does its own decryption in userspace and exposes the result through FUSE. It does **not** use a kernel dm-crypt/loopback path with a standard filesystem on top. Reasoning: dm-crypt has no concept of a hidden volume or password-selected mount target — you'd need userspace logic to pick *which* key to hand the kernel before mounting, at which point you've built the interesting part anyway and gained nothing from also involving dm-crypt. Since FUSE is the real path, Phase 2 exists only to validate raw sector decrypt/encrypt correctness before the filesystem layer sits on top of it.
- `denyfs open container.img --password X` decrypts and allows raw `dd` in/out at the sector layer.
- **Gate:** write known data, close, reopen, byte-identical.

### Phase 3 — Filesystem layer (the part that was previously undefined)
Two things happen in this phase, not one — FUSE glue, and the actual filesystem metadata design, which is the real engineering content review kept flagging as missing.

**3a. On-disk metadata format (this is DenyFS's own, not ext4/FAT via loopback — see Phase 2):**
- Superblock: volume size, block size (4096B), inode count, pointer to bitmap.
- Block allocation bitmap: one bit per block, integrity-protected with the HMAC key from Phase 1 (separate from the GCM header tag — see rationale above). Checked on mount; a failed check refuses mount with a generic error, not a crash.
- Flat inode table: fixed max file count decided at creation (portfolio-scope limitation, stated explicitly rather than silently — a production filesystem would need dynamic inode allocation, DenyFS does not).
- Directory entries: name → inode mapping, flat directories only (no need to build a general tree-balancing structure for this scope — stated as a scope limitation, not hidden).

**3b. FUSE operations**, now including the two that were missing from the original op list: `getattr`, `read`, `write`, `readdir`, `open`, `truncate`, **`create`, `unlink`**. Without create/unlink this wasn't a filesystem, it was a read-only view of one — fixed.
- Every FUSE handler maps onto: bitmap lookup → sector read/write via the Phase 1/2 crypto layer → inode/directory update. This mapping is now fully specified by 3a, closing the "map onto what, exactly" gap from review.
- **Gate:** mount, `cp` files in and out normally (including creating and deleting files, not just reading pre-existing ones), unmount, remount, verify integrity, verify bitmap integrity check catches deliberate corruption.

### Phase 4 — Deniability hardening (non-negotiable — see §8 for why this is no longer framed as optional under any timeline)
- **External-observable check:** implement and verify the exact mechanism from §3 — fixed-order, fixed-time attempt sequence, single generic error message, no distinguishable path for "wrong password" vs. "right password, no hidden volume here."
- **Metadata/log audit — named, not generic.** Previous drafts said "audit every write path and eliminate leaks," which is a to-do item, not a completed audit. The actual list, checked one by one:
  - `/tmp`, shell history, journalctl — original scope, still checked.
  - **inode timestamps** (atime/mtime/ctime) on the *outer container file itself*, on the host filesystem — does mounting/using DenyFS touch the container file's own metadata in a way that correlates with hidden-volume activity? Disable atime updates on the container file (`chattr +A` guidance, or open with `O_NOATIME`) and document this as a user-facing setup step, not just a code fix.
  - **Desktop indexers**: `tracker`, `baloo`, GNOME/KDE file indexing — these can index filenames or content the moment a FUSE mount exposes them. Document that users must exclude the mount point from indexer scope; DenyFS cannot prevent a system-level indexer from running, only warn about it.
  - **GVFS** — if the mount point is ever exposed through the desktop's virtual filesystem layer, thumbnail/preview caches can leak filenames. Same treatment: documented user-facing warning, not a code-level fix, because it's outside DenyFS's control.
  - **systemd-journald mount/unmount logging** — `journalctl` will show FUSE mount/unmount events by default. Document (not silently accept) that users needing full deniability of *usage timing*, not just content, need journald log rotation/scrubbing as an operational step outside this tool's scope.
  - This list is the audit. Anything added later gets added here by name, not folded into "eliminate leaks."
- **Memory hygiene (previously entirely absent — this was issue #8 in two consecutive reviews and is fixed here, not deferred again):**
  - All key material (master key, header key, volume key, HMAC key, and the raw password buffer before KDF) is allocated via `sodium_malloc`, locked with `sodium_mlock`, and wiped with `sodium_memzero` — never plain `malloc`/`memset`, since `memset` on a soon-to-be-freed buffer is legally eliminable by the compiler as a dead store and `sodium_memzero` specifically isn't.
  - `setrlimit(RLIMIT_CORE, 0)` at process start — a crash must not leave a coredump containing key material on disk.
  - Explicitly out of scope, stated rather than ignored: full protection against cold-boot / RAM-remanence attacks (data physically read out of DRAM within seconds of power loss) is **not achievable in userspace** and is not claimed. `sodium_mlock` prevents swap-to-disk exposure; it does not defend against a physical RAM attack against a machine seized while mounted. This limitation is carried into §9 as a named adversary, not hidden.
- **Timing:** all password/key comparisons use `sodium_memcmp`, never `memcmp`. Verified in Phase 6, not just asserted here.
- **Gate:** you can explain, out loud, without notes, why each property above holds — and Phase 6 has an automated test proving the observable-behavior claim, not just a code review of it.

### Phase 5 — Build integrity note (short, scoped honestly)
Not a full phase — a documented limitation. A tampered or backdoored `denyfs` binary defeats every property above, and this project does not implement reproducible builds, code signing, or a supply-chain integrity story. Stated explicitly in §9 as an out-of-scope adversary rather than silently assumed away.

### Phase 6 — Threat model + writeup
See §9. This is the section to rehearse for an interview — it's what shows the difference between "encrypted" and "deniable," and it's now the section with the fewest gaps left in it.

### Phase 7 — Test suite
- Seeded correctness cases: correct outer password, correct hidden password, wrong password, corrupted header, corrupted hidden region, corrupted allocation bitmap.
- **The test that was missing in every prior draft, and is the actual proof of the project's core claim:** take a container built with **no hidden volume configured at all**, run the hidden-password path against it, and diff both the returned behavior and the wall-clock timing distribution against a genuine wrong-password attempt on a container that **does** have a hidden volume. These two must be indistinguishable (statistically, over many trials — not just "look the same once") or Phase 4 has not actually succeeded regardless of what the code review concluded.
- Fuzz the **header parser first**, not the FUSE layer — the header/format-parsing code runs on attacker-controlled bytes before any password is verified, making it the actual pre-auth attack surface. FUSE operations only run after a successful mount and are lower priority.
- Basic FUSE-layer fuzzing (create/delete/rename loops) after the header parser is covered.

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

- Raw password: read into a `sodium_malloc`'d, `sodium_mlock`'d buffer immediately, never touches a regular `char[]`.
- Master/header/volume/HMAC keys: derived into similarly locked buffers, zeroed with `sodium_memzero` the moment the mount/unmount operation no longer needs them.
- No key material is ever passed to a logging call, `printf`, or written to any file, including debug builds — debug builds redact key buffers by construction, not by convention.

---

## 8. Resolving the Phase 4 contradiction directly

An earlier draft of this document named Phase 4 "the part that actually matters" and, separately, listed Phase 4 as the first thing to compress under a tight deadline. Those two statements can't both be true, and leaving them both in the document was a prioritization error, not a wording nit.

**Resolved position:** Phase 4's core requirement — the external-observable mechanism in §3, and the memory-hygiene items in Phase 4 — is **not compressible under any timeline.** It is the entire thesis of the project; a version of DenyFS without it is an encrypted container with an unsubstantiated deniability claim bolted on, which is a materially different and much weaker project.

**What actually is compressible under a tight deadline**, in order:
1. Phase 8 (benchmarks) — nice for the writeup, not load-bearing for the claim.
2. Phase 7's fuzzing depth — keep the specific indistinguishability test (it's the one that matters most), drop extended AFL campaigns if time-constrained.
3. Phase 3a's filesystem feature completeness — flat directories, fixed inode count, and no dynamic resize are already scoped-down; further reduction (e.g., smaller fixed file count) is fine and should just be stated as a scope limitation, same as the others.
4. §5's documented-but-unimplemented items (build integrity, cold-boot resistance) can stay documented-only indefinitely — they were never scheduled for implementation in the first place, so there's nothing to cut.

If you genuinely cannot finish Phase 4 in the available time, the honest move is to say so in the writeup — *"Phase 4's mechanism is designed and documented in §3 but not yet fully implemented/tested; here's specifically what's missing"* — rather than shipping a version that quietly skips it while still calling the project "deniable."

---

## 9. Threat Model

**Explicit adversary model — what DenyFS defends against:**
Adversary has physical access to the container file and can coerce the outer password. Adversary cannot brute-force AES-256 or Argon2id. Adversary cannot obtain the hidden password. Adversary can inspect the container file's bytes and the host filesystem's ordinary metadata (with the mitigations in Phase 4 applied).

**Adversaries DenyFS explicitly does NOT defend against — stated here rather than omitted:**
1. **Repeated snapshots over time.** An adversary who captures the container file at multiple points in time and can diff them may observe that the "free space" region changed in a location consistent with hidden-volume activity, even without decrypting anything. This is a structural limitation of the hidden-volume approach in general (VeraCrypt shares it), not a bug specific to this implementation, and there is no code-level fix — only operational advice (avoid giving an adversary multiple historical copies of the container).
2. **Malware, root compromise, or a keylogger on the host** while DenyFS is in use. If the machine is compromised, both passwords can simply be captured as they're typed, independent of anything this project does.
3. **Cold-boot / RAM-remanence attacks.** `sodium_mlock` prevents key material from being swapped to disk, but does not defend against a physical attack that reads DRAM contents within seconds of a power cut on a machine seized while mounted. Named explicitly here rather than left as a silent gap (see Phase 4).
4. **DMA attacks** against a live, mounted system (e.g. via Thunderbolt) — out of scope; would require IOMMU-level protections outside this project.
5. **Evil-maid attacks** — a tampered device or a swapped/backdoored `denyfs` binary. See Phase 5: no reproducible-build or code-signing story exists yet.
6. **A compromised kernel** — FUSE operates in userspace, but the kernel mediates all I/O to it; a compromised kernel can observe everything regardless of anything in userspace.
7. **Cloud backup / sync leakage** — if the container file is synced to a cloud backup service, that service may retain historical versions, recreating the repeated-snapshot problem (#1) outside the user's control.

**Why listing these matters more than it might seem:** a security tool that doesn't say what it *doesn't* do is more dangerous than one that's silent about security entirely, because someone might rely on it for exactly the wrong scenario. This list is the actual interview material — being asked "what about a cold-boot attack" and having a considered, honest, previously-written answer is a stronger interview outcome than either an unprepared "I hadn't thought about that" or an overconfident false claim of coverage.
