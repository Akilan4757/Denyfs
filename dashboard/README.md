# DenyFS Dashboard

The dashboard is a local browser interface for the DenyFS Linux/FUSE program. It creates real DenyFS containers, copies selected files into them, and mounts existing containers so you can decrypt and download files again. It does not define a second, browser-only encryption format.

For the complete project handbook, including the architecture, CLI, security model, test results, capacity planning, and presentation guide, see [../documentation.md](../documentation.md).

## Run it

Build and run it inside Linux. On Windows, use WSL2 with `/dev/fuse` enabled and the DenyFS dependencies installed.

```bash
cd /path/to/Denyfs-main
make release
python3 dashboard/server.py
```

Or run `make dashboard` to build the release CLI and start the dashboard in one step.

Then open <http://127.0.0.1:8765>. The server binds to loopback only. By default, encrypted containers are stored in `~/.local/share/denyfs-dashboard/vaults/`; temporary FUSE mount points are created under `/tmp/denyfs-dashboard-mounts/`. To use a different binary, library directory, mount directory, or port:

```bash
python3 dashboard/server.py \
  --binary ./denyfs-release \
  --data-dir ~/.local/share/denyfs-dashboard/vaults/ \
  --mount-dir /tmp/denyfs-dashboard-mounts \
  --port 8765
```

The release binary needs `libfuse3`, libsodium, OpenSSL, and the FUSE mount helper (`fusermount3`). The Python server uses only the standard library. In WSL, keep the vault library and mount directory in the Linux filesystem (for example, under your Linux home and `/tmp`); avoid placing FUSE mount points under `/mnt/c`.

## Encrypt files

1. Choose **Encrypt files** and select or drag in up to 63 files.
2. Set a vault name, container size, and passphrase.
3. Choose **Encrypt files** and leave the dashboard open until it says the vault is locked.

The dashboard writes the new `.denyfs` container in its local vault library. Container size is the full encrypted file size; the current DenyFS format exposes about half of it as the outer filesystem. The rest is reserved for the other half of the container and layout. Allow extra space for filesystem metadata. For one fully allocated 4 GiB file, use at least an 8203 MiB container. Creation fills the entire container with random bytes, so large containers need considerable free disk space and can take several minutes.

DenyFS currently stores files in a single flat directory: no subfolders, 63 files per vault, and at most 4 GiB per file. Files with duplicate names cannot be added to the same vault.

## Decrypt files

Choose a vault in **Unlock vault**, enter its passphrase, and select **Decrypt & save** next to a file. A vault created by this dashboard is already in the library. To open a container elsewhere, import it first; import copies the encrypted container into the local library and requires free space for another copy. Unlocking with the hidden-volume passphrase opens that hidden volume when the container has one.

Downloaded files are plaintext. Your browser saves them to its normal download location. Use **Lock vault** when you finish; locking unmounts the filesystem and flushes filesystem changes.

## Local handling

- The server listens only on `127.0.0.1` and does not send files to a cloud service.
- Passphrases are sent to the local server in the operation request, are not included in CLI arguments or server request logs, and are not saved in the vault library. DenyFS keeps key material in the mounted process memory while a vault is open.
- The dashboard library contains encrypted containers. Use **Export** in the library to save a copy elsewhere. Decrypted downloads are managed by your browser and are not automatically erased after download.
- Keep the dashboard process running while a vault is mounted. On normal shutdown (Ctrl+C), it attempts to unmount the active vault. If the process or machine is forcibly terminated, check for a stale mount before restarting.

The dashboard inherits DenyFS's limits: no crash journal, no authentication tag for file data blocks, and no formal guarantee of universal hidden-volume deniability. See the project [threat model](../THREAT_MODEL.md) before relying on it for sensitive data.

## Visual system

The repository did not include a formal brand palette, so the dashboard defines a small DenyFS UI palette using Apple-style system neutrals:

| Token | Color | Use |
|---|---|---|
| Ink | `#17243A` | Primary text |
| Cloud | `#F2F6FB` | Main canvas |
| DenyFS blue | `#3478F6` | Primary actions and focus |
| Secure mint | `#21A886` | Unlocked/healthy states |
| Soft violet | `#7E6BE8` | Secondary information |
| Warm coral | `#DC675C` | Errors |

Panels use translucent white, restrained blur, and subtle specular gradients. The interface uses the native system font stack, includes reduced-motion support, and adapts to mobile screens.
