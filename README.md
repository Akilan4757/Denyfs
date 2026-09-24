# DenyFS

DenyFS is an educational encrypted-container filesystem written in C. A single
container file holds an outer filesystem and can hold one optional hidden
filesystem. Linux FUSE makes an unlocked volume appear as a normal directory.
A local browser dashboard is included for encrypting selected files and
decrypting them back to downloads.

> **Project status:** prototype for learning, demonstrations, and controlled
> experiments. DenyFS has not had a formal security audit and is not a reviewed
> replacement for VeraCrypt, LUKS, FileVault, or a production backup system.
> Its hidden-volume design is a limited single-snapshot goal, not a guarantee
> against repeated snapshots, host evidence, or a compromised device.

## Capabilities

- Create an encrypted container and format its outer volume.
- Create one hidden volume in unused container space.
- Open or mount the volume selected by a passphrase.
- Mount the outer volume with an optional guard that refuses writes into the
  hidden-volume range.
- Use the command line or a loopback-only dashboard to manage files.
- Encrypt 4096-byte filesystem blocks with AES-256-XTS; protect volume headers
  with AES-256-GCM; derive password keys with Argon2id.
- Store files up to 4 GiB each, with at most 63 files in each flat root
  directory. Available total capacity depends on the volume size.

See [documentation.md](documentation.md) for the full handbook, including the
design, architecture, setup, commands, dashboard, limits, security model,
troubleshooting, and presentation guide.

## Quick start: Linux or WSL2

Install the required packages on Ubuntu or Debian:

```bash
sudo apt update
sudo apt install build-essential pkg-config libsodium-dev libssl-dev libfuse3-dev fuse3
```

Build the project from its root directory:

```bash
make all
```

Create and mount a small container:

```bash
./denyfs create vault.img --size 50
mkdir -p /tmp/denyfs-vault
./denyfs mount vault.img --mountpoint /tmp/denyfs-vault
```

The CLI prompts for the password without echo. Use the mounted directory while
the command is running. In another terminal, unmount it when finished:

```bash
fusermount3 -u /tmp/denyfs-vault
```

The `--size` value is in MiB and specifies the complete container file. New
containers are filled with random bytes, so allow enough free disk space for the
full container.

## Start the dashboard

The dashboard needs Linux with FUSE. On Windows, run it from WSL2 with `/dev/fuse`
and `fusermount3` available. Start it from the project root:

```bash
make dashboard
```

Open <http://127.0.0.1:8765>. The dashboard creates real DenyFS containers,
imports and exports encrypted containers, unlocks outer or hidden volumes, and
downloads selected decrypted files. See [dashboard/README.md](dashboard/README.md)
for workflow and storage details.

To fit one fully allocated 4 GiB file, use at least a 4101 MiB volume. The
current layout places the outer volume in roughly half the container; a hidden
volume of that size therefore needs an 8203 MiB container. Creating it random-
fills more than 8 GiB and can take several minutes. Leave extra room if storing
more data or filesystem metadata.

## CLI commands

```text
./denyfs create <path> --size <MiB>
./denyfs create-hidden <path> --size <MiB>
./denyfs open <path>
./denyfs mount <path> --mountpoint <directory>
./denyfs mount <path> --mountpoint <directory> --protect-hidden
```

Passwords are requested interactively. For scripts, the CLI accepts
`--password-fd <fd>` and `--hidden-password-fd <fd>` so passwords do not appear
in process arguments. See the handbook for safe examples and the complete
command reference.

## Build and verification

```bash
make all          # CLI, release CLI, tests, fuzz harnesses, benchmark harness
make test         # crypto, sector I/O, filesystem, timing, and stress tests
make test-fuse    # Linux FUSE mount and file-operation smoke test
./test_bench      # optional performance baseline
```

The full test suite and FUSE smoke test were run on **2026-09-24** in Ubuntu on
WSL2. All five `make test` programs and the FUSE smoke test passed, including
the 4 GiB sparse-file boundary check. This verifies the tested environment and
operations; it is not a security audit or a full 4 GiB physical-throughput test.
Detailed results and benchmark scope are in [BENCHMARKS.md](BENCHMARKS.md).

## Project documents

- [Full project handbook](documentation.md)
- [Dashboard guide](dashboard/README.md)
- [Plain-language project guide](PROJECT_GUIDE.md)
- [Architecture and build plan](DenyFS-Architecture-and-Build-Plan.md)
- [Threat model](THREAT_MODEL.md)
- [Build integrity statement](BUILD_INTEGRITY.md)
- [Benchmarks](BENCHMARKS.md)
- [Progress log](PROGRESS_LOG.md)

## Source map

| Path | Role |
|---|---|
| `src/crypto.c`, `src/crypto.h` | Password KDF, key derivation, header encryption, sector encryption, HMAC |
| `src/fs.c`, `src/fs.h` | Container format, volume selection, encrypted filesystem operations |
| `src/fuse_ops.c`, `src/fuse_ops.h` | Linux FUSE filesystem adapter |
| `src/main.c` | CLI and password input |
| `dashboard/` | Local web dashboard and its Python API |
| `tests/` | Correctness, timing, stress, FUSE, fuzz harnesses, benchmark source |
| `Makefile` | Build and run targets |

## License

MIT. See [LICENSE](LICENSE).
