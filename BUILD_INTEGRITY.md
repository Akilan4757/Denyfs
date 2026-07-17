# DenyFS — Build Integrity Statement

This document is the Phase 5 deliverable. It exists to state, explicitly and in one place, every build-integrity property that DenyFS **does not implement** — so that no user, reviewer, or future developer treats them as present by default.

A security tool that doesn't say what it *doesn't* do is more dangerous than one that's silent about security entirely, because someone might rely on it for exactly the wrong scenario.

---

## 1. The Core Problem

Every security property DenyFS claims — deniable encryption, timing side-channel resistance, memory hygiene, hidden volume indistinguishability — is a property of the **source code as designed**. None of those properties survive a compromised binary. If the `denyfs` executable a user runs is not the one produced by honest compilation of this source, every guarantee is void.

This is not hypothetical. The three specific threat vectors are:

### 1a. Backdoored Binary Distribution

An adversary substitutes or patches the compiled `denyfs` binary (on disk, in transit, via a package repository, or via a compromised build server). The modified binary could:
- Log passwords to a hidden file or network endpoint before passing them to Argon2id.
- Emit the master key alongside the encrypted header during `create`.
- Weaken the Argon2id parameters (lower memory/iterations) while reporting the original values.
- Skip the hidden-header decryption attempt entirely, leaking hidden-volume presence via timing.

### 1b. Compiler/Toolchain Compromise (Thompson Attack)

A compromised `gcc`, `ld`, or `libc` inserts behavior not present in the source. Classic example: a compiler that recognizes password-handling patterns and injects exfiltration code during compilation. The resulting binary passes source-level audit because the backdoor exists only in the compiler's output, not in any file a reviewer reads.

This extends to any dependency in the build chain: `libsodium`, `libssl`, `libfuse3`, `libc`, the kernel's `getrandom()` implementation, and the linker itself.

### 1c. Dependency Compromise (Supply-Chain Attack)

A malicious update to `libsodium`, `OpenSSL`, or `libfuse3` — delivered through the distribution's package manager — could silently weaken cryptographic operations. Examples:
- A patched `crypto_pwhash` that reduces Argon2id iterations internally while accepting the caller's parameters.
- A patched `EVP_aes_256_xts` that uses a fixed or predictable tweak instead of the caller-supplied LBA.
- A patched `EVP_aes_256_gcm` that always reports authentication success, defeating tamper detection.

---

## 2. What DenyFS Does NOT Implement

### 2a. Reproducible Builds

DenyFS has **no reproducible build infrastructure**. Two compilations of the same source, on different machines or at different times, will produce different binaries due to:
- Differing compiler versions, optimization passes, and code generation.
- Differing linked library versions (OpenSSL 3.x minor versions, libsodium point releases).
- Timestamps or build-path strings embedded by the toolchain.
- ASLR-related position-independent code differences.

Without reproducible builds, there is no way to independently verify that a given binary corresponds to a given source tree. A user cannot confirm "this binary was built from commit X" without trusting the builder.

**What would be needed (not implemented):**
- Pinned toolchain versions (compiler, linker, libc).
- Pinned dependency versions with hash-locked archives.
- Deterministic build flags eliminating timestamps and path-dependent output.
- A reference build environment (Docker/Nix) producing bit-identical output across machines.
- Published reference hashes (SHA-256) for each tagged release.

### 2b. Code Signing

DenyFS binaries are **not signed**. There is no mechanism to verify:
- That a binary was produced by an authorized builder.
- That a binary has not been modified after compilation.
- That a binary corresponds to any particular source revision.

**What would be needed (not implemented):**
- A signing key pair (e.g., Ed25519 via `minisign` or GPG).
- A signature file distributed alongside each binary.
- A documented verification procedure for end users.
- Key management: revocation, rotation, and trust-on-first-use or PKI anchoring.

### 2c. Supply-Chain Integrity

DenyFS does **not verify the integrity of its build dependencies** beyond what the OS package manager provides. Specifically:
- No hash pinning of `libsodium`, `libssl`, or `libfuse3` source archives or packages.
- No vendored (in-tree) copies of dependencies with known-good hashes.
- No Software Bill of Materials (SBOM).
- No automated dependency audit (e.g., checking CVE databases against linked library versions).

**What would be needed (not implemented):**
- Vendored or hash-locked dependency sources.
- Build-time verification of dependency checksums.
- SBOM generation listing exact versions and hashes of all linked libraries.

---

## 3. What This Means for Users

**If you build DenyFS from source yourself**, on a machine you control, using a compiler and libraries you trust, and you audit the source — the security properties documented in the README and architecture file hold as designed.

**If you receive a pre-built binary from any source**, including this repository's releases (if any exist in the future), you are trusting:
1. The builder's machine was not compromised.
2. The compiler was not trojaned.
3. The linked libraries were genuine.
4. No modification occurred in transit.

None of these can be verified with the current project infrastructure. This is a **known, stated limitation**, not a bug or oversight.

---

## 4. Recommended User Mitigations

These are operational steps outside DenyFS's scope, listed for completeness:

1. **Build from source** on a trusted machine rather than using pre-built binaries.
2. **Verify compiler integrity** — use distribution-signed packages for `gcc`/`clang` and verify their signatures.
3. **Verify dependency integrity** — install `libsodium`, `libssl`, and `libfuse3` from distribution-signed packages; check `apt` signature verification is enabled and functioning.
4. **Audit the source** — the codebase is intentionally small (~1200 lines across 7 source files) specifically to make manual audit feasible.
5. **Compare checksums** — if building on multiple machines, compare `sha256sum` output of the resulting binary as a smoke test (will not match exactly without reproducible builds, but gross differences indicate a problem).
6. **Air-gap sensitive builds** — for high-threat-model use cases, build on an air-gapped machine with a verified toolchain.

---

## 5. Cross-Reference

- **Architecture document §9, adversary #5**: "Evil-maid attacks — a tampered device or a swapped/backdoored `denyfs` binary. See Phase 5: no reproducible-build or code-signing story exists yet."
- **Architecture document §4, Phase 5**: "Not a full phase — a documented limitation."
- **Architecture document §8**: Build integrity is listed as compressible item #4 — "documented-but-unimplemented items can stay documented-only indefinitely; they were never scheduled for implementation."
- **README, Known Limitations**: "No build integrity checks or reproducible compilation paths exist. A backdoored binary voids all security properties."

---

## 6. Why This Document Exists Instead of a Fix

Implementing reproducible builds, code signing, and supply-chain verification is real engineering work that requires ongoing maintenance (key management, CI infrastructure, dependency tracking). For a portfolio project whose purpose is demonstrating applied cryptography and deniable storage design, the honest approach is to **name the gap explicitly** rather than either:
- Silently omitting it and hoping no one asks.
- Bolting on a token gesture (e.g., a single GPG signature with no verification story) that creates a false sense of coverage.

This document is the deliverable. The limitation is stated. The threat vectors are named. The mitigations are the user's operational responsibility.
