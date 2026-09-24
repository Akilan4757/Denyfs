# DenyFS Project Handbook

**A practical guide to the purpose, implementation, setup, operation, testing,
and presentation of DenyFS**

This handbook starts with the simplest explanation and moves into the source
code and on-disk design. It is written for users, students, reviewers, and
presenters who need one place to understand the complete project.

> **Project status:** DenyFS is an educational prototype. It is useful for
> learning about encrypted containers, filesystems, FUSE, and plausible
> deniability. It has not received a formal security audit. Do not treat it as a
> replacement for established, reviewed storage encryption software or as the
> only copy of important data.

## Contents

1. [The idea in plain language](#1-the-idea-in-plain-language)
2. [What DenyFS can do](#2-what-denyfs-can-do)
3. [Requirements and supported setup](#3-requirements-and-supported-setup)
4. [Build and start the project](#4-build-and-start-the-project)
5. [Dashboard user guide](#5-dashboard-user-guide)
6. [Command-line user guide](#6-command-line-user-guide)
7. [Architecture at a glance](#7-architecture-at-a-glance)
8. [Container format and data placement](#8-container-format-and-data-placement)
9. [Cryptography and key flow](#9-cryptography-and-key-flow)
10. [Filesystem implementation](#10-filesystem-implementation)
11. [Hidden volumes and write protection](#11-hidden-volumes-and-write-protection)
12. [Capacity and the 4 GiB file limit](#12-capacity-and-the-4-gib-file-limit)
13. [Security properties and limitations](#13-security-properties-and-limitations)
14. [Tests, benchmarks, and what they establish](#14-tests-benchmarks-and-what-they-establish)
15. [Troubleshooting](#15-troubleshooting)
16. [Where DenyFS fits](#16-where-denyfs-fits)
17. [How to present or demonstrate the project](#17-how-to-present-or-demonstrate-the-project)
18. [Source map and terms](#18-source-map-and-terms)

---

## 1. The idea in plain language

DenyFS stores a small filesystem inside one ordinary file called a **container**.
The container is encrypted. When a user enters the outer passphrase, DenyFS
opens the outer filesystem and Linux can show it as a directory. A container
can also have one **hidden volume** in space the outer filesystem does not use.
The hidden volume has a separate passphrase and its own filesystem.

The project explores **plausible deniability**. Unused container space is
random-filled when a container is created. Later, encrypted hidden-volume data
also looks random to someone without its key. An observer with only the outer
passphrase is intended to see the outer filesystem and no simple marker that
proves a hidden filesystem exists.

That is a limited design goal. DenyFS cannot prove that hidden data is absent.
Repeated copies of a container may expose which regions changed. A compromised
computer, password capture, logs, backups, filesystem timestamps, or other
operational evidence can reveal activity. See the [threat model](THREAT_MODEL.md)
for a fuller discussion.

### A simple mental model

Think of the container as a box of pages covered in random-looking marks. One
passphrase opens a small filing system in the first part of the box. A second
passphrase opens a different filing system stored in a separate unused area.
Both filing systems are encrypted, and they use different keys. Linux FUSE
provides the directory-like view while a volume is open.

### A deeper one-sentence model

The C program derives a header key from a passphrase with Argon2id, authenticates
and decrypts a fixed-size AES-GCM header to recover random volume keys, validates
an encrypted block filesystem, and exposes its file operations through a
single-threaded libfuse3 adapter.

---

## 2. What DenyFS can do

The current project provides:

- A C command-line program to create a container and format its outer volume.
- A command to create one hidden volume inside the available container space.
- A command to test a passphrase and report basic volume details without
  mounting.
- A Linux FUSE mount that exposes the selected volume as a normal directory.
- An optional outer-mount guard that rejects DenyFS writes into a hidden-volume
  range when the user supplies the hidden passphrase.
- An optional local web dashboard for selecting files, encrypting them into a
  new container, importing and exporting containers, unlocking volumes, and
  downloading decrypted files.
- AES-256-XTS sector encryption, AES-256-GCM authenticated headers, Argon2id
  password derivation, and an HMAC-SHA256 for the block allocation bitmap.
- A flat root directory with up to 63 files. Each file may be up to 4 GiB,
  subject to available volume space.
- Correctness, timing-regression, stress, FUSE smoke, fuzz-harness, and
  benchmark source code.

The filesystem does not have subdirectories, file-block authentication, a
crash-recovery journal, or an automatic backup system. Container sizes are fixed
when created. See [Section 13](#13-security-properties-and-limitations) and
[Section 14](#14-tests-benchmarks-and-what-they-establish) for exact limits.

---

## 3. Requirements and supported setup

### Linux packages

The supported development and dashboard path is Ubuntu or Debian Linux, or
Ubuntu under WSL2 with FUSE available. Install the compiler, build tools,
headers, crypto libraries, FUSE libraries, and FUSE helper:

```bash
sudo apt update
sudo apt install build-essential pkg-config libsodium-dev libssl-dev libfuse3-dev fuse3
```

The project uses:

| Dependency | Purpose |
|---|---|
| GCC or compatible C compiler | Builds the CLI, tests, and harnesses |
| Make | Runs the provided build targets |
| libsodium | Argon2id, secure random bytes, memory utilities |
| OpenSSL libcrypto | AES-GCM, AES-XTS, and HMAC-SHA256 |
| libfuse3 | Connects the filesystem operations to Linux |
| `fusermount3` | Mount and unmount helper used by FUSE |
| Python 3 standard library | Runs the dashboard API; no Python packages are required |

The C unit tests do not require FUSE for their core filesystem checks. The
dashboard and the FUSE integration smoke test do require a working FUSE device.

### Windows with WSL2

Use an Ubuntu WSL2 distribution with `/dev/fuse` and `fusermount3` available.
Check them from the WSL shell:

```bash
test -c /dev/fuse && echo "FUSE device is available"
command -v fusermount3
```

Install the packages above, then build and run the project inside WSL. Windows
can open the dashboard at `http://127.0.0.1:8765` through WSL localhost
forwarding. Keep container files in the Linux filesystem, for example under
`~/vaults`, and mount FUSE directories under `/tmp` or another Linux path.
Mounting from `/mnt/c` can be slow or behave differently from a native Linux
filesystem.

### macOS and native Windows

The project is built around Linux FUSE. The portable cryptographic and filesystem
source can be studied or some non-mount tests may be adaptable elsewhere, but
the supported end-to-end mount and dashboard workflow is Linux/WSL2. macOS FUSE
and native Windows FUSE behavior are not covered by the current project tests.

---

## 4. Build and start the project

Run these commands from the directory containing the `Makefile`.

### Build everything

```bash
make all
```

This builds the sanitizer-enabled `denyfs` executable, optimized
`denyfs-release`, five test programs, two fuzz harnesses, and the optimized
benchmark executable. The sanitizer build is useful for development; use
`denyfs-release` for normal mounting and dashboard use.

Build only the release CLI with:

```bash
make release
```

### Start the dashboard

```bash
make dashboard
```

That target builds the release program if needed and starts the dashboard
server. Leave the terminal process running while using the dashboard. Open
<http://127.0.0.1:8765> in a browser on the same machine.

The equivalent two-step command is:

```bash
make release
python3 dashboard/server.py
```

The server accepts options for a different release binary, local vault library,
mount directory, and port:

```bash
python3 dashboard/server.py \
  --binary ./denyfs-release \
  --data-dir ~/.local/share/denyfs-dashboard/vaults \
  --mount-dir /tmp/denyfs-dashboard-mounts \
  --port 8765
```

It rejects non-loopback bind addresses. Its default encrypted-vault library is
`~/.local/share/denyfs-dashboard/vaults/`; temporary mounts use
`/tmp/denyfs-dashboard-mounts/`. The dashboard uses Python's standard library.

### Stop the dashboard

Press Ctrl+C in the terminal running the server. During normal shutdown, the
server attempts to unmount the active volume. If the process or machine is
forcibly terminated, check for a stale FUSE mount before starting another
session.

### Rebuild or remove generated outputs

`make clean` removes the project binaries and known test images. Run it only
when you intend to remove those generated files. It does not remove dashboard
vaults in the default home-directory library.

---

## 5. Dashboard user guide

The dashboard is a local interface over the existing DenyFS release CLI and
FUSE filesystem. It does not implement a separate browser encryption format.
The browser uploads selected files to the local Python server, which creates a
real container and writes them through the mounted DenyFS filesystem.

### Encrypt selected files

1. Start the dashboard and open `http://127.0.0.1:8765`.
2. Choose **Encrypt files** and select or drag files into the page.
3. Enter a vault name, a container size, and a passphrase.
4. Start encryption and keep the tab and server running until the operation
   completes and the vault is locked.
5. The encrypted `.denyfs` file appears in the dashboard's local vault library.

Container size is the size of the complete container file. Roughly half is the
outer volume; the remaining space contains unused space and can hold a hidden
volume. DenyFS random-fills the entire container at creation time. A large
container therefore consumes its full size on disk and can take several minutes
to create.

The dashboard inherits filesystem limits: flat filenames only, up to 63 files
per volume, no duplicate names in the same volume, and up to 4 GiB per file.
The total data must fit in the selected volume after its filesystem metadata.

### Unlock and decrypt a file

1. Choose a vault in **Unlock vault**.
2. Enter the outer or hidden passphrase for the volume to open.
3. Choose **Decrypt & save** next to a listed file.
4. The browser downloads that file as plaintext to its normal download location.
5. Choose **Lock vault** when finished. This unmounts the volume and flushes
   filesystem changes.

### Import and export containers

Use the library's import action to copy an existing `.denyfs` container into
the dashboard's local library. Importing needs free space for an additional
copy. Export saves an encrypted container file to a location selected by the
browser. The dashboard does not automatically remove plaintext files after a
download; manage those files using your operating system and backup practices.

### Local handling and visual design

- The API listens on loopback (`127.0.0.1`); it is intended for use on the same
  device and does not provide a remote multi-user service.
- Passphrases are sent to that local server for an operation. They are not put
  in DenyFS command-line arguments, server request logs, or the vault library.
- The mounted DenyFS process retains its keys in memory while the volume is
  unlocked. Lock the volume when the work is complete.
- In WSL2, container library and mount locations should be on the Linux side,
  not on a Windows-mounted path.
- The interface uses a neutral Apple-style system font and spacing, translucent
  panels, restrained liquid-glass blur and animation, and reduced-motion
  support. Its project-defined palette is ink `#17243A`, cloud `#F2F6FB`, DenyFS
  blue `#3478F6`, secure mint `#21A886`, soft violet `#7E6BE8`, and warm coral
  `#DC675C`. These are dashboard design choices; the repository has no separate
  corporate brand manual.

More detail is in [dashboard/README.md](dashboard/README.md).

---

## 6. Command-line user guide

The CLI prompts for a password without echo when no password file descriptor is
provided. It does not accept plaintext passphrases as command-line options.
Interactive prompts are the simplest option for manual use.

The dashboard accepts passphrases from 1 to 511 UTF-8 bytes and rejects line
breaks. The CLI's secure input buffers also hold up to 511 bytes. Use a
passphrase you can reproduce exactly; DenyFS has no recovery or reset feature.

### Create a container and outer volume

```bash
./denyfs create ~/vaults/demo.denyfs --size 64
```

`--size` is an integer number of MiB for the whole container. Creation uses
exclusive file creation, so an existing file at that path is not overwritten.
It fills the new container with random bytes, writes the encrypted header, and
formats the outer filesystem.

### Add one hidden volume

```bash
./denyfs create-hidden ~/vaults/demo.denyfs --size 8
```

The CLI asks for the outer passphrase to authenticate the existing container,
then for a distinct hidden-volume passphrase. `--size` here is the hidden volume
size in MiB. The command checks that it fits in the unused region before
formatting it. Creating a hidden volume writes a hidden header and filesystem
into that region; it is not a reversible toggle.

Do not run hidden-volume creation a second time to overwrite a volume you want
to keep. The file format has one hidden-header slot and the program does not
provide a safe hidden-volume discovery or resize operation.

### Check a password without mounting

```bash
./denyfs open ~/vaults/demo.denyfs
```

On success the CLI prints the selected volume type and basic volume and
filesystem counts, then closes it. On failure it reports a generic invalid
password message. Use distinct outer and hidden passphrases so password
selection is predictable.

### Mount a volume

```bash
mkdir -p /tmp/denyfs-demo
./denyfs mount ~/vaults/demo.denyfs --mountpoint /tmp/denyfs-demo
```

The same mount command opens the outer or hidden filesystem according to the
passphrase. Use the mount path like a normal directory while the command is
running. In another terminal, unmount it with:

```bash
fusermount3 -u /tmp/denyfs-demo
```

If `fusermount3` is not available, install the `fuse3` package. Avoid opening
sensitive files in desktop applications during a deniability demonstration:
thumbnailers, indexers, recent-file lists, and application caches may create
evidence outside the container.

### Protect the hidden range during an outer mount

```bash
./denyfs mount ~/vaults/demo.denyfs \
  --mountpoint /tmp/denyfs-outer \
  --protect-hidden
```

The program asks for both the outer and hidden passphrases. It authenticates the
outer volume and the hidden header, calculates the hidden range, then refuses
normal DenyFS writes that intersect that range. If hidden authentication fails,
the requested protection cannot be established and the mount is refused.

This check protects writes made through this DenyFS mount path. It is not a
general protection against direct edits to the container file, a compromised
kernel, or another program that bypasses DenyFS.

### Password file descriptors for automation

The CLI supports `--password-fd <fd>` and, where applicable,
`--hidden-password-fd <fd>`. A file descriptor keeps the secret out of process
arguments. The process that opens and supplies the descriptor still needs to
protect the secret. Prefer an interactive prompt for manual work and a secret
manager or carefully controlled pipe for automation. Do not put real passwords
in shell history, scripts, environment variables, or process arguments.

Examples of option placement:

```text
denyfs create <path> --size <MiB> --password-fd <fd>
denyfs create-hidden <path> --size <MiB> --password-fd <fd> --hidden-password-fd <fd>
denyfs open <path> --password-fd <fd>
denyfs mount <path> --mountpoint <dir> --password-fd <fd>
```

The read/write sector commands are low-level experiments for one logical
sector. They are not normal file-management commands and can corrupt a mounted
filesystem if used against its metadata.

### Full command list

```text
denyfs create <path> --size <MiB> [--password-fd <fd>]
denyfs create-hidden <path> --size <MiB> [--password-fd <fd>] [--hidden-password-fd <fd>]
denyfs open <path> [--password-fd <fd>] [--protect-hidden] [--hidden-password-fd <fd>]
denyfs mount <path> --mountpoint <dir> [--password-fd <fd>] [--protect-hidden] [--hidden-password-fd <fd>]
denyfs write-sector <path> --lba <n> --data <file> [--password-fd <fd>]
denyfs read-sector <path> --lba <n> --output <file> [--password-fd <fd>]
```

---

## 7. Architecture at a glance

```text
Passphrase
    |
    v
Argon2id(password, random salt)
    |
    v
32-byte master key -- HKDF-Expand/HMAC-SHA256 --> 32-byte header key
                                                     |
                                                     v
                                      AES-256-GCM authenticates header
                                                     |
                           +-------------------------+----------------------+
                           |                                                |
                           v                                                v
                    64-byte XTS key                                  32-byte HMAC key
                           |                                                |
                           v                                                v
                 AES-256-XTS per 4 KiB block                   Allocation bitmap check
                           |
                           v
           Superblock + bitmap + inode table + file blocks
                           |
                           v
                 filesystem API in src/fs.c
                           |
                           v
                FUSE callbacks in src/fuse_ops.c
                           |
                           v
              mounted Linux directory or dashboard
```

The dashboard is an additional interface layer. It calls the same release CLI
and uses the same container and filesystem format as direct command-line use.

### Main components

1. **CLI (`src/main.c`)** reads passwords interactively or from file descriptors,
   parses commands, and starts the filesystem or FUSE mount.
2. **Crypto layer (`src/crypto.c`)** delegates standard primitives to libsodium
   and OpenSSL.
3. **Filesystem layer (`src/fs.c`)** creates containers, authenticates and
   selects volumes, validates filesystem metadata, allocates blocks, and
   implements file operations.
4. **FUSE adapter (`src/fuse_ops.c`)** maps kernel requests such as open, read,
   write, list, truncate, and unlink to filesystem functions. It runs in the
   foreground and uses a single-threaded FUSE loop.
5. **Dashboard (`dashboard/server.py` and browser assets)** provides a local
   web interface and sends file operations to the release CLI and mount.

---

## 8. Container format and data placement

The format uses fixed offsets and fixed-size encrypted blocks. The current
filesystem superblock identifies itself as `DenyFS03`.

```text
byte 0                                                        end of file
|                                                                    |
v                                                                    v
+----------------+------------------------+------------------------+----------+
| outer header   | outer volume           | free / hidden area      | reserved |
| 4096 bytes     | starts at byte 4096     | hidden filesystem may   | 32 KiB   |
| AES-256-GCM    | about half the file     | occupy an ending region |          |
+----------------+------------------------+------------------------+----------+
                                                                       ^
                                            hidden header at EOF - 32 KiB
```

- **Container creation:** creates a new file, fills its full declared size with
  libsodium-generated random bytes in 64 KiB chunks, then writes the outer
  header and filesystem. It does not overwrite an existing path.
- **Outer header:** occupies bytes 0 through 4095. Its public fields are a
  16-byte random salt, a 12-byte GCM IV, a 16-byte authentication tag, and
  4052 bytes of ciphertext. The decrypted payload contains the volume size,
  bitmap information, a random 64-byte XTS key, a random 32-byte HMAC key, and
  reserved random bytes.
- **Outer volume:** begins immediately after the first 4096-byte header. Its
  declared size is half of the complete container size. The filesystem itself
  starts at that volume offset.
- **Hidden volume:** is placed in unused space before a fixed hidden-header
  location. The hidden header begins 32 KiB before end-of-file. The hidden
  filesystem occupies the range immediately before that header; the rest of
  the reserved tail is left as random-looking bytes.
- **Hidden header:** is another 4096-byte AES-GCM header with its own salt, IV,
  tag, and independently generated volume keys.

The hidden volume is not stored as a separate file. Both volumes occupy ranges
inside the same container. The outer filesystem has a size boundary and its
allocation metadata does not describe hidden-volume blocks.

---

## 9. Cryptography and key flow

### Password derivation

Each header has its own random 16-byte salt. DenyFS passes the passphrase and
salt to libsodium's Argon2id 1.3 implementation with:

- Operation limit: 4
- Memory limit: 64 MiB
- Output: 32-byte master key

A fixed-context HMAC-SHA256 HKDF-Expand step derives a separate 32-byte header
key from the master key. The context string in the implementation is
`DenyFS Header Key V1`.

### Header authentication and encryption

The header payload is encrypted with AES-256-GCM using a fresh random 12-byte
IV. Its 16-byte tag authenticates the payload. A wrong passphrase or a changed
header should fail authentication before its contained volume keys are used.

### Filesystem block encryption

Every filesystem block is 4096 bytes and encrypted with AES-256-XTS. XTS uses a
64-byte key (two 256-bit AES keys) and the volume-relative logical block number
as its tweak. That lets the filesystem read and write blocks independently
without adding a separate nonce or expanding each block.

XTS provides confidentiality for sector data; it does not authenticate a block.
Changes to file data may decrypt to changed plaintext without a cryptographic
error. The project does not have a per-block authentication tag.

### Bitmap integrity

The random 32-byte HMAC key is stored inside the authenticated encrypted
header. DenyFS uses HMAC-SHA256 to detect changes to the allocation bitmap. The
bitmap HMAC is stored in the encrypted superblock. This check does not
authenticate file contents or all other metadata.

### Randomness and memory handling

libsodium's secure random generator supplies the container fill, keys, salts,
IVs, and other random values. Key buffers use libsodium secure allocation and
are wiped when released; the program also attempts to disable core dumps. OS
policy affects how much memory locking and protection the process receives.
These measures do not protect secrets from a compromised host, privileged
attacker, memory capture, or malicious kernel.

---

## 10. Filesystem implementation

Each volume is a sequence of 4096-byte logical blocks. Logical block zero is
the superblock. The remaining layout is described by offsets and counts in that
superblock.

### Metadata regions

1. **Superblock:** magic/version, block size, volume block count, inode count,
   metadata offsets, free-space counts, and bitmap HMAC.
2. **Allocation bitmap:** one bit per logical block. Metadata blocks are marked
   allocated; data blocks are marked as files and pointer tables use them.
3. **Inode table:** 64 fixed 128-byte inode records, occupying two 4096-byte
   blocks. Inode zero is the root directory; the remaining 63 slots are files.
4. **Data area:** directory blocks, file-data blocks, and file pointer tables.

The root directory is flat. A 4096-byte directory block has sixteen 256-byte
entries, but the fixed inode table limits a volume to 63 files regardless of
directory-block capacity. Names may contain up to 250 bytes/characters as
validated by the project, and duplicate names are rejected.

### Inodes and large files

An inode records file size, count of allocated data blocks, modification time,
and block references. The address map has:

- 20 direct data-block pointers.
- One single-indirect block containing 1024 32-bit block numbers.
- One double-indirect root whose 1024 entries point to 1024-entry pointer
  blocks.

This address map has more theoretical space than the project permits. The
explicit file-size ceiling is 4 GiB. Files are sparse: extending a file's size
without writing its intervening data creates zero-reading gaps and does not
allocate every block. Writing to those gaps allocates blocks as needed.

### Reads, writes, and metadata persistence

A read locates the file's logical data block, reads its ciphertext from the
container, decrypts it using the block number as the XTS tweak, and copies the
requested byte range to the caller.

A write allocates blocks when needed. For a partial-sector update, DenyFS reads
and decrypts the existing 4096-byte block, changes the requested bytes, then
encrypts and writes the full block. Newly allocated data blocks are initialized
to zero. Truncating can allocate or release data and pointer blocks; the
filesystem clears the retained block tail when shortening a file so later
growth does not reveal stale bytes from that file.

FUSE operations flush the filesystem metadata through the project's volume
flush path. The implementation uses stdio flushing, not a complete journaled
transaction protocol or a universal power-loss durability guarantee. A crash
during related writes can leave inconsistent metadata.

Unlinking frees blocks for later reuse. It is not secure erase: old copies may
remain in snapshots, storage remapping, backups, or host caches.

---

## 11. Hidden volumes and write protection

### How password selection works

Each open attempt reads both fixed header locations. It runs Argon2id and an
AES-GCM header-decryption attempt for the outer header and for the hidden
header. The passphrase is tested against both salts. If the outer header
authenticates, the outer volume is selected; otherwise, an authenticated hidden
header selects the hidden volume. If neither succeeds, the CLI reports a
generic invalid-password message.

Running both derivations gives failed-open paths a similar cryptographic work
shape. It does not make the complete program constant-time: successful metadata
validation, disk behavior, system load, memory allocation, and other effects
can still change elapsed time.

Use different outer and hidden passphrases. Hidden-volume creation rejects
identical passphrases, and the outer header is checked first when opening.

### What outer protection does

When mounting the outer volume with `--protect-hidden`, DenyFS authenticates
both volumes, computes the hidden volume's absolute sector range, and rejects
outer filesystem writes falling within that range. The protection is an
application-level write check, not a read-only mount. Writes in the outer
filesystem's normal region can still proceed.

The guard cannot prevent direct writes to the container outside DenyFS, host
rollback, kernel compromise, or every possible software defect. The user must
keep the hidden passphrase available to establish the protected range.

### Deniability boundaries

The design aims for random-looking unused and encrypted regions in one
container snapshot. It does not promise indistinguishability under repeated
snapshots. Writing new outer data may overwrite formerly unused blocks, and
writing hidden data changes a region that can be compared across copies. The
container's host filesystem metadata and the computer's operating history also
remain outside the encrypted filesystem.

---

## 12. Capacity and the 4 GiB file limit

There are two different sizes to track:

1. The **container size** is the size of the complete `.denyfs` file.
2. The **volume size** is the filesystem capacity selected by its header.

The outer volume is half the container size. A hidden volume takes a requested
size from the unused region before the hidden header. Filesystem metadata and
pointer blocks reduce space available for user data.

### One 4 GiB file

The filesystem allows a file to be as large as 4 GiB. To fully allocate that
much file data in one hidden volume, the current guidance is at least a 4101
MiB hidden volume. Since the outer volume takes half of the complete file, use
at least an 8203 MiB container to leave room for it. This example needs more
than 8 GiB of free host storage, and initial random filling can take several
minutes.

This guidance fits one fully allocated 4 GiB file, not an unlimited number of
4 GiB files. The 63-file limit is per volume, and every file competes for the
same volume capacity. A sparse 4 GiB file with only a few written blocks uses
far less actual block space.

### Capacity planning checklist

- Reserve container space for the entire random-filled file.
- Leave room for filesystem metadata and pointer blocks.
- Count the total actual data across all files in the chosen volume.
- Plan to store at most 63 files in one flat directory.
- Remember that importing a container into the dashboard makes another copy.
- Use a backup destination separate from the only container copy.
- Do not treat deleting a file as secure erasure.

The 4 GiB limit is checked by filesystem operations. The stress test verifies
the maximum logical size with sparse writes near its end and rejects sizes
above it. It does not perform a full physical write of four billion bytes.

---

## 13. Security properties and limitations

### What the implementation is designed to provide

- **Header confidentiality and integrity:** AES-256-GCM protects each header
  payload and rejects altered headers or incorrect keys.
- **File-block confidentiality:** AES-256-XTS encrypts filesystem sectors with
  block-address tweaks.
- **Password derivation cost:** Argon2id increases the cost of testing guessed
  passwords. It cannot make a weak or reused password strong.
- **Bitmap integrity:** HMAC-SHA256 checks the allocation bitmap before relying
  on it.
- **Outer write protection option:** the FUSE filesystem can reject writes into
  the hidden range when mounted with the hidden password.
- **Limited plausible-deniability design:** unused space is random-filled and
  encrypted blocks do not add a per-block authentication structure.

### What it does not provide

- A formal guarantee that a hidden volume cannot be discovered.
- Protection from malware, keyloggers, a compromised kernel, privileged access,
  or an attacker controlling the running machine.
- Authentication for file data blocks or every filesystem metadata block.
- A crash journal, transactional metadata updates, or guaranteed recovery after
  sudden power loss.
- Secure deletion, automatic backups, container resize, nested directories, or
  more than one hidden volume.
- A formally reviewed implementation, signed builds, reproducible builds, or a
  complete dependency supply-chain verification system.

### Host and workflow evidence

Mounting a filesystem does not encrypt the rest of the computer. Desktop search
indexers, preview generators, office applications, recent-file lists, swap,
crash reporting, terminal history, backup software, and host logs can leave
evidence or plaintext copies. The CLI prints warnings about indexers, caches,
mount logs, and host metadata. Avoid unnecessary application exposure when
demonstrating the deniability design.

### Practical handling

- Make more than one protected copy of important containers.
- Verify that you can unlock and read a backup before removing a source file.
- Use a strong, unique passphrase and keep it in an appropriate password
  manager.
- Unmount or lock the volume when work is done.
- Keep decrypted downloads and temporary files under the same care as the
  original plaintext.
- Use the hidden-range guard when mounting the outer volume in a workflow where
  protecting hidden data from accidental DenyFS writes matters.
- Read [THREAT_MODEL.md](THREAT_MODEL.md) and
  [BUILD_INTEGRITY.md](BUILD_INTEGRITY.md) for the project's detailed threat and
  build-trust analysis.

---

## 14. Tests, benchmarks, and what they establish

### Test commands

```bash
make test
make test-fuse
./test_bench
```

`make test` runs five programs:

| Program | Coverage |
|---|---|
| `test_crypto` | Argon2id, key derivation, AES-GCM, AES-XTS |
| `test_volume` | Container sector reads and writes, wrong passwords, LBA bounds, ciphertext checks |
| `test_fs` | Create/lookup/read/write/list/truncate/unlink, persistence, bitmap HMAC, hidden volume and protection |
| `test_timing` | Interleaved wrong-password timing comparison for outer-only and outer-plus-hidden containers |
| `test_stress` | Header and metadata corruption, 63-file capacity, 500 create/delete cycles, 4 GiB sparse boundary, oversized-file rejection, filename bounds, interleaved operations |

`make test-fuse` creates a temporary container, mounts it, checks create/read,
truncate, list, and unlink operations, then performs a sparse write and read at
the last byte of a 4 GiB file. The temporary image and mount are removed by the
test script.

The repository includes `tests/fuzz_header.c` and `tests/fuzz_sector.c` as
fuzzing harnesses. Building harnesses is not the same as running a sustained
fuzzing campaign. The normal `make test` target does not run AFL++.

### Latest verification run

On **2026-09-24**, from Ubuntu 26.04 in WSL2 on Linux kernel 6.6.114.1, the
following were run:

- `make test`: all five test programs passed.
- `make test-fuse`: passed, including normal FUSE file operations and the 4 GiB
  sparse-file read/write check.
- The timing regression run measured a 5.2202 ms difference between mean
  wrong-password opens for outer-only and outer-plus-hidden containers, within
  the test's 15 ms threshold.
- The stress program passed its 4 GiB sparse mapping, persistence, truncate,
  and over-limit rejection checks.

This is evidence for these source paths in this test environment. It is not a
formal security proof, full-filesystem endurance test, recovery test, or full
physical 4 GiB write benchmark.

### Performance baseline

The latest documented benchmark uses GCC 15.2.0, `-O2`, Ubuntu 26.04 under WSL2,
OpenSSL and libsodium system packages, a 10 MiB container, and five trials for
timed tests (raw XTS is one loop):

| Operation | Result | Scope |
|---|---:|---|
| Argon2id, one call | 162.71 ms mean | 64 MiB configured memory limit |
| Open volume | 316.79 ms mean | Two sequential KDF calls |
| Create 10 MiB container | 354.89 ms mean | Includes random filling |
| AES-256-XTS encrypt | 2,413.92 MB/s | Raw crypto, no filesystem or disk I/O |
| AES-256-XTS decrypt | 2,103.11 MB/s | Raw crypto, no filesystem or disk I/O |
| Sequential write | 1.91 MB/s | Small 96 KiB test, one sector per call |
| Sequential read | 14.47 MB/s | Small 96 KiB test, one sector per call |

These are host-specific measurements. The small read/write tests are not a
sustained large-file throughput benchmark. The 4 GiB tests use sparse files and
do not measure a full 4 GiB physical write or creation of an 8 GiB container.
See [BENCHMARKS.md](BENCHMARKS.md) for environment details and historical
results.

---

## 15. Troubleshooting

### `make` cannot find headers or libraries

Install the packages from [Section 3](#3-requirements-and-supported-setup),
especially `libsodium-dev`, `libssl-dev`, `libfuse3-dev`, and `pkg-config`.
Check that `pkg-config --cflags --libs fuse3` returns FUSE flags.

### Dashboard reports that the release executable is missing

Build it from the project root:

```bash
make release
```

If using a custom path, pass it with `--binary` when starting the dashboard.

### Dashboard says FUSE is unavailable

Check `test -c /dev/fuse`, install `fuse3`, and confirm
`command -v fusermount3`. Under WSL2, use a distribution and configuration
where FUSE is exposed. Run the dashboard inside WSL, not as a native Windows
Python process.

### `fusermount3 -u` cannot unmount

Close programs using files under the mount directory, then retry. Check active
mounts with `mountpoint <path>`. If a process was killed unexpectedly, inspect
and clean up the stale FUSE mount before attempting another dashboard session.

### The password is rejected

Check the spelling, keyboard layout, selected container, and whether the
passphrase belongs to the outer or hidden volume. The filesystem does not
provide password recovery. A hidden-volume passphrase is distinct from the
outer one.

### Creating a large container is slow or fails

Creation random-fills the full container, so it needs free storage equal to the
requested container size and time proportional to that size and the host
storage. Check free space in the filesystem where the container library lives.
The dashboard import operation also needs enough free space to make another
complete copy.

### File creation reports no space or too many files

Check both the selected volume's free blocks and the fixed 63-file limit. A
large sparse file may have a 4 GiB logical length while using little space, but
writing its full contents requires the corresponding volume capacity.

### Dashboard opens but cannot complete file encryption

Keep the server process running, use a local loopback tab, check available space
in the vault library, avoid duplicate filenames, and ensure every selected file
fits within filesystem and volume limits. If the browser or server was
interrupted, inspect the library and lock or remove only the incomplete demo
vault you intended to create.

---

## 16. Where DenyFS fits

### Good fits

- A class or personal study project about storage encryption architecture.
- A controlled demonstration of Argon2id, authenticated headers, block
  encryption, FUSE, and filesystem metadata.
- A code-review exercise about the difference between confidentiality,
  integrity, deniability, and host-level evidence.
- A prototype for measuring how container size, random filling, password KDF
  work, and per-block I/O affect performance.

### Poor fits

- A production system holding irreplaceable, regulated, or life-critical data.
- A promise that a hidden volume is impossible to detect.
- Workflows that require reliable crash recovery, audited tamper detection for
  every file block, concurrent multi-user access, subdirectories, or resizing.
- A device that may already be compromised or monitored.
- An only copy of a backup or any workflow without a recovery plan.

The project's value is that the code and design tradeoffs can be studied and
demonstrated. For operational security, use established tools that match the
actual threat model and have independent review.

---

## 17. How to present or demonstrate the project

### Suggested short presentation

1. **Problem:** ordinary encryption hides content, but an observer can still
   see that an encrypted volume exists.
2. **Design goal:** show how random-filled unused space and a separately keyed
   hidden volume explore plausible deniability under a limited snapshot model.
3. **Architecture:** explain the key flow: Argon2id, header key derivation,
   AES-GCM header, AES-XTS blocks, filesystem, and FUSE.
4. **Implementation:** point to `src/crypto.c`, `src/fs.c`, and
   `src/fuse_ops.c`; describe how the same CLI powers the dashboard.
5. **Demo:** create a small disposable container, mount the outer volume, then
   mount the hidden volume with its other passphrase. Or use the dashboard to
   encrypt one harmless file and decrypt it to a download.
6. **Evidence:** show the tests and benchmarks, including what the 4 GiB sparse
   boundary test verifies.
7. **Limits:** explain unauthenticated file blocks, lack of a crash journal,
   host evidence, and why the project is not a formal security product.

### Safe live-demo outline

Use throwaway names and harmless sample content. Keep an untouched copy of any
important source file. For a CLI demo, a small container is enough:

```bash
mkdir -p ~/denyfs-demo /tmp/denyfs-demo-mount
./denyfs create ~/denyfs-demo/presentation.denyfs --size 64
./denyfs create-hidden ~/denyfs-demo/presentation.denyfs --size 8
```

For the outer view, run the mount command and create a small visible file in a
second terminal. Unmount it. Then mount the same container using the hidden
passphrase and show the separate directory contents. Use a separate
presentation container; do not create the hidden volume over data you need.

For a dashboard demo, start with a small text or image file, encrypt it into a
small container, then unlock and decrypt it. This demonstrates the complete
interface without waiting for a multi-gigabyte random fill. Avoid claiming that
a successful demo proves resistance to every forensic or coercion scenario.

### Presentation language that stays accurate

Useful phrasing:

- “DenyFS explores a deniable encrypted-container design under a limited
  single-snapshot model.”
- “The header is authenticated with AES-GCM; file blocks use AES-XTS and do not
  have per-block authentication.”
- “The stress test exercises a sparse file at the 4 GiB logical boundary; it
  does not show a full 4 GiB throughput measurement.”
- “The dashboard calls the same Linux/FUSE implementation as the CLI.”

Avoid claims that the hidden volume is impossible to find, that every block is
authenticated, that the system has passed a security audit, or that the
benchmark measures sustained storage throughput.

---

## 18. Source map and terms

### Repository map

| Path | What it contains |
|---|---|
| `README.md` | Project landing page and quick start |
| `documentation.md` | This complete project handbook |
| `PROJECT_GUIDE.md` | Plain-language architecture walkthrough |
| `DenyFS-Architecture-and-Build-Plan.md` | Original design and build phases |
| `THREAT_MODEL.md` | Adversaries, assumptions, protections, and gaps |
| `BUILD_INTEGRITY.md` | Build and supply-chain properties not implemented |
| `BENCHMARKS.md` | Current and historical measurements |
| `PROGRESS_LOG.md` | Development history |
| `Makefile` | Build, dashboard, test, FUSE, and cleanup targets |
| `src/crypto.c`, `src/crypto.h` | Key derivation, headers, sector crypto, HMAC, secure allocation |
| `src/fs.c`, `src/fs.h` | Container format, volume open, metadata, block mapping, file operations |
| `src/fuse_ops.c`, `src/fuse_ops.h` | FUSE adapter |
| `src/main.c` | CLI, passphrase input, mount startup, sector commands |
| `tests/` | Unit, integration, stress, fuzz harness, and benchmark sources |
| `dashboard/server.py` | Loopback-only dashboard API and mount lifecycle |
| `dashboard/index.html`, `styles.css`, `app.js` | Dashboard interface and browser behavior |
| `dashboard/README.md` | Dashboard workflow, local storage, and visual system |

### Glossary

| Term | Meaning in this project |
|---|---|
| Container | The single host file holding headers, volumes, and unused space |
| Outer volume | The volume opened by the outer passphrase, beginning after the first header |
| Hidden volume | Optional second volume stored in an unused container region |
| FUSE | Linux interface for implementing a filesystem in a userspace process |
| Logical block / sector | One 4096-byte filesystem unit encrypted with an LBA tweak |
| LBA | Logical block address; used as the AES-XTS tweak input |
| Inode | Filesystem record mapping a file to its metadata and data blocks |
| Sparse file | File with a large logical size but unallocated ranges that read as zeros |
| KDF | Key derivation function; here Argon2id derives a key from a passphrase and salt |
| AEAD | Authenticated encryption with associated data; AES-GCM authenticates the header |
| XTS | AES disk-encryption mode for independently addressed data blocks; it does not authenticate them |
| CSPRNG | Cryptographically secure pseudorandom number generator |
| Plausible deniability | A design goal of making hidden data difficult to distinguish under stated assumptions, not proof of absence |

---

## Further reading

- [Project README](README.md)
- [Dashboard guide](dashboard/README.md)
- [Architecture and build plan](DenyFS-Architecture-and-Build-Plan.md)
- [Threat model](THREAT_MODEL.md)
- [Build integrity statement](BUILD_INTEGRITY.md)
- [Benchmark report](BENCHMARKS.md)
