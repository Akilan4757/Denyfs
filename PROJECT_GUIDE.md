# DenyFS: Project Guide from First Idea to Internals

This guide explains what DenyFS does, how a user operates it, and how its code works. It starts with the everyday idea and gradually adds the implementation details. DenyFS is a local encrypted-storage application for Linux and WSL2, with CLI and dashboard workflows. Review the security, integrity, and recovery limits in this guide and the threat model when deciding whether it fits your data.

## 1. The basic idea

DenyFS stores an encrypted filesystem inside one ordinary-sized file called a **container**. A container can hold an outer volume and, optionally, a hidden volume.

Think of the container as a large book whose pages initially contain random-looking marks. The outer password opens one section and shows a normal, small filesystem. The hidden password opens a different section placed in space the outer filesystem does not use. To someone who only has the outer password, the hidden section is meant to look like unused random space.

This is called **plausible deniability**. It does not mean that DenyFS can prove a hidden volume is absent. It means the bytes in unused space do not carry a simple marker that says a hidden volume is present. Repeated copies of the container, a compromised computer, or other clues can still reveal activity. See [THREAT_MODEL.md](THREAT_MODEL.md) before relying on this property.

## 2. What a user can do

The command-line program can:

- Create and format a new container.
- Add one hidden volume to an existing container.
- Open a volume to check a password and inspect basic filesystem counts.
- Mount the selected volume through FUSE so it appears like a regular directory.
- Ask DenyFS to protect a hidden volume while the outer volume is mounted. This requires the hidden password.
- Read and write individual encrypted sectors for low-level experiments.

Passwords are prompted without echo by default. For scripts, the CLI accepts file descriptors (`--password-fd` and `--hidden-password-fd`) so secrets do not need to appear in command arguments. Supplying a file descriptor is only as safe as the process that created and controls that descriptor.

Example on Linux or WSL with FUSE support:

```sh
make
./denyfs create vault.img --size 50
./denyfs create-hidden vault.img --size 10
mkdir -p /tmp/vault
./denyfs mount vault.img --mountpoint /tmp/vault
# Use /tmp/vault like a regular directory while DenyFS runs.
fusermount3 -u /tmp/vault
```

The project supports a flat root directory only. Do not add a second hidden volume: the format has one hidden-header slot, and there is no safe way to detect an existing hidden volume without its password. Use different outer and hidden passwords. New hidden-volume creation rejects identical passwords; on older containers that used the same password, the outer header wins during open.

## 3. The container, from the outside inward

All offsets are byte offsets. Sizes are fixed when the container is created.

```text
0                     4096              outer end     EOF - 32768         EOF
| outer GCM header     | outer filesystem | unused space | hidden GCM header | random tail |
|                     | XTS-encrypted    | hidden data is placed before its header |
```

- **Outer header (first 4096 bytes):** contains a random salt, a random GCM nonce, an authentication tag, and encrypted header data. The header data contains the outer volume size and randomly generated keys. There is no plaintext `DenyFS` signature in the header.
- **Outer volume:** starts at byte 4096 and takes half of the container's byte size. It has a superblock, allocation bitmap, fixed inode table, root-directory blocks, and file-data blocks.
- **Unused/hidden area:** the rest of the file is initially filled with libsodium's cryptographic random generator. Creating a hidden volume writes its filesystem at the end of this region, just before the hidden-header slot.
- **Hidden header:** sits at `EOF - 32768`. The final 32 KiB includes this 4 KiB header and a random tail. Its salt is random and stored as part of the header; salts are public values, not secrets.

The outer filesystem's declared size bounds its block addresses. When `--protect-hidden` is used, DenyFS also learns the hidden range from the hidden header and refuses outer writes into the protected range. Without that option, the outer filesystem still has its own size limit, but the protection check is not active.

## 4. How creating a container works

1. DenyFS creates a new file without replacing an existing file and fills it with random bytes in small chunks.
2. It generates a fresh random salt, an XTS volume key, and a bitmap-HMAC key.
3. Argon2id derives a 32-byte master key from the password and salt. A small HKDF step derives the header-encryption key from that master key.
4. DenyFS puts the volume key, HMAC key, and size information in a header payload, then encrypts and authenticates that payload with AES-256-GCM.
5. It formats the outer filesystem and encrypts its 4096-byte blocks with AES-256-XTS.

The volume and HMAC keys are random keys wrapped by the password-protected header. They are not directly derived from the password. This makes the header act like a sealed envelope: the password opens the envelope, and the envelope contains the keys used for filesystem data.

Creating a hidden volume follows the same key and format steps, but it writes the hidden filesystem into the unused tail region and writes its encrypted header at the fixed slot. Because unused bytes are not distinguishable from hidden ciphertext by inspection alone, the hidden filesystem has no visible allocation map in the outer volume.

## 5. How opening and password selection work

When opening a container, DenyFS reads both header slots. It then always performs two password derivations and two AES-GCM header-decryption attempts: one for the outer header and one for the hidden header. If the outer header authenticates, DenyFS selects the outer volume. Otherwise, if the hidden header authenticates, it selects the hidden volume. If neither authenticates, the CLI shows the generic message `Error: invalid password.`

Doing both cryptographic attempts gives wrong-password cases a similar work shape. It does **not** make the whole program fixed-time: operating systems, memory allocation, disk I/O, and successful filesystem validation can change elapsed time. A timing test is evidence about one tested setup, not a proof that every observer can never distinguish cases.

After selecting a header, DenyFS checks that the volume size fits inside the container. It decrypts the superblock, validates its sizes and layout before allocating or reading from those sizes, reads the bitmap and verifies its HMAC, then checks inode block references and directory entries before exposing the volume.

## 6. Encryption and key details

| Item | What DenyFS does | What that means |
|---|---|---|
| Password KDF | Argon2id, libsodium, 64 MiB memory limit and opslimit 4 | Makes password guessing more expensive; a weak password is still weak. |
| Header | AES-256-GCM | Detects a wrong password or changed header through its authentication tag. |
| Header-key derivation | HMAC-SHA256-based HKDF-Expand with a fixed context string | Separates the GCM header key from the Argon2id result. |
| Filesystem blocks | AES-256-XTS, 4096 bytes per block, tweak is the volume-relative block number | Supports random-access disk encryption without expanding blocks. |
| Allocation bitmap | HMAC-SHA256 using the random HMAC key stored inside the encrypted header | Detects bitmap changes. It does not authenticate file contents or every metadata block. |
| Random fill and keys | libsodium `randombytes_buf` | Supplies the random bytes used for containers, salts, nonces, and volume keys. |

AES-XTS has **no authentication**. A change to encrypted file data may decrypt to changed plaintext without an error. DenyFS does not add a per-block authentication tag because extra visible structures can weaken the hidden-space design. The bitmap has a separate HMAC because a changed allocation map can make the filesystem unsafe to traverse.

## 7. How the filesystem works

Each volume consists of 4096-byte logical blocks. Logical block 0 is the superblock. The following blocks store the allocation bitmap and inode table. Remaining blocks hold the root directory and file data.

- The **superblock** records the volume layout and free counts.
- The **bitmap** uses one bit per logical block to track allocation.
- The **inode table** has 64 fixed entries. Inode 0 is the root directory; the other 63 can represent files.
- Each file inode uses 20 direct pointers, a single-indirect table, and a double-indirect table. With 4096-byte blocks, this maps files up to 4 GiB; the file size is stored in 64 bits.
- The root directory has fixed-size entries and no subdirectories.
- File create, lookup, read, write, truncate, unlink, and directory listing operations are implemented in `src/fs.c` and exposed to Linux through FUSE callbacks in `src/fuse_ops.c`.

A fully allocated 4 GiB file needs space for its data blocks, pointer tables, and
filesystem metadata. A 4101 MiB hidden volume fits one; with the current layout,
that requires an 8203 MiB container because the outer volume takes half the
container. Container creation fills the whole file with random bytes, so this
large example can take several minutes and needs more than 8 GiB of free space.
The volume can hold at most 63 files, each no larger than 4 GiB, subject to the
actual free space in that volume.

The expanded inode format is DenyFS03. DenyFS02 containers from earlier builds
are not automatically upgraded; copy their files out with the old build before
creating new containers.

When an application writes part of a block, DenyFS decrypts that block, changes the requested bytes, encrypts the full block again, and writes it back. New blocks are zero-filled before use. Truncating a file shorter also clears the unused tail of its last retained block so that later extension does not expose old bytes from that file.

Truncating a file larger creates a sparse file: unwritten gaps read as zeroes and do not consume data blocks. Actual writes still need free space in the volume.

The on-disk filesystem is intentionally small. It is not a general-purpose or crash-journaled filesystem; sudden power loss during multiple metadata writes can leave a volume inconsistent. Deleted sectors are freed for reuse but are not securely erased from every physical storage layer.

## 8. Protecting the hidden area during an outer mount

The outer volume knows only its own declared block range. With `--protect-hidden`, the user provides the outer password and hidden password. DenyFS authenticates the hidden header, calculates its range, and rejects writes that reach that range. If protection was requested but the hidden password does not authenticate, the mount is refused so the user does not mistakenly believe protection is active.

This guard prevents normal DenyFS filesystem writes from overwriting the protected region. It does not protect against another program modifying the container directly, a compromised kernel, disk rollback, or a bug elsewhere in the host.

## 9. Security and practical limits

DenyFS is a usable local storage application, but its deniability property is an intended design goal under a limited single-snapshot threat model, not a guarantee. It has not undergone independent security review; file blocks are not authenticated, and there is no crash journal. Repeated container snapshots can reveal changed regions. Malware or a keylogger can capture passwords. Host logs, indexers, previews, backups, swap policy, and filesystem timestamps are outside the container format and need operational care.

The application attempts to lock secret buffers and wipes key buffers when they are released, and the CLI disables core dumps where the operating system permits it. This does not protect secrets from root, memory-forensics, cold-boot, DMA, or a compromised kernel. FUSE has not been exercised on every supported Linux setup, and extended AFL++ campaigns are separate from having fuzz harness source code.

Read [THREAT_MODEL.md](THREAT_MODEL.md) for the threat-by-threat analysis, [BUILD_INTEGRITY.md](BUILD_INTEGRITY.md) for supply-chain limitations, and [DenyFS-Architecture-and-Build-Plan.md](DenyFS-Architecture-and-Build-Plan.md) for design decisions and build phases.

## 10. Source map

| Path | Responsibility |
|---|---|
| `src/crypto.c`, `src/crypto.h` | KDF, HKDF, header AEAD, sector encryption, HMAC, secure allocation helpers |
| `src/fs.c`, `src/fs.h` | Container creation, volume selection, filesystem format, metadata validation, file operations |
| `src/fuse_ops.c`, `src/fuse_ops.h` | Bridges the filesystem API to Linux FUSE |
| `src/main.c` | CLI, password input, mount/open/create commands, core-dump limit |
| `tests/` | Correctness, timing, stress, fuzz-harness, and benchmark source files |
| `Makefile` | Build targets for the binary and the separate harnesses |
| `README.md` | Project landing page, commands, and summary |
