#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="${1:-$project_root/denyfs-release}"

if [[ ! -x "$binary" ]]; then
    echo "FUSE smoke test: executable not found: $binary" >&2
    exit 1
fi
if [[ ! -c /dev/fuse ]] || ! command -v fusermount3 >/dev/null 2>&1; then
    echo "FUSE smoke test requires /dev/fuse and fusermount3." >&2
    exit 77
fi

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/denyfs-fuse-smoke.XXXXXX")"
image="$tmpdir/volume.img"
mount_dir="$tmpdir/mnt"
mount_log="$tmpdir/mount.log"
password='denyfs-fuse-smoke-password'
mount_pid=''

mkdir "$mount_dir"

cleanup() {
    if mountpoint -q "$mount_dir"; then
        fusermount3 -u "$mount_dir" || true
    fi
    if [[ -n "$mount_pid" ]] && kill -0 "$mount_pid" 2>/dev/null; then
        kill "$mount_pid" 2>/dev/null || true
        wait "$mount_pid" 2>/dev/null || true
    fi
    rm -rf -- "$tmpdir"
}
trap cleanup EXIT INT TERM

printf '%s\n' "$password" | "$binary" create "$image" --size 8 --password-fd 0

(printf '%s\n' "$password" | "$binary" mount "$image" \
    --mountpoint "$mount_dir" --password-fd 0) >"$mount_log" 2>&1 &
mount_pid=$!

mounted=0
for ((attempt = 0; attempt < 100; attempt++)); do
    if mountpoint -q "$mount_dir"; then
        mounted=1
        break
    fi
    if ! kill -0 "$mount_pid" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

if [[ "$mounted" -ne 1 ]]; then
    cat "$mount_log" >&2
    echo "FUSE smoke test could not mount the test volume." >&2
    exit 1
fi

printf 'fuse-smoke-data' >"$mount_dir/check.txt"
if [[ "$(cat "$mount_dir/check.txt")" != 'fuse-smoke-data' ]]; then
    echo "FUSE smoke test readback did not match." >&2
    exit 1
fi

printf 'fuse' >"$tmpdir/expected.txt"
truncate -s 4 "$mount_dir/check.txt"
cmp "$tmpdir/expected.txt" "$mount_dir/check.txt"
if [[ "$(ls -1 "$mount_dir")" != 'check.txt' ]]; then
    echo "FUSE smoke test directory listing did not match." >&2
    exit 1
fi
rm "$mount_dir/check.txt"
if [[ -e "$mount_dir/check.txt" ]]; then
    echo "FUSE smoke test unlink did not remove the file." >&2
    exit 1
fi

truncate -s 4294967296 "$mount_dir/large-sparse.bin"
if [[ "$(stat -c '%s' "$mount_dir/large-sparse.bin")" != '4294967296' ]]; then
    echo "FUSE smoke test could not expose a 4 GiB file size." >&2
    exit 1
fi
printf 'Z' | dd of="$mount_dir/large-sparse.bin" bs=1 seek=4294967295 conv=notrunc status=none
printf 'Z' >"$tmpdir/expected-last-byte"
dd if="$mount_dir/large-sparse.bin" bs=1 skip=4294967295 count=1 status=none >"$tmpdir/read-last-byte"
cmp "$tmpdir/expected-last-byte" "$tmpdir/read-last-byte"
rm "$mount_dir/large-sparse.bin"

fusermount3 -u "$mount_dir"
wait "$mount_pid"
mount_pid=''

echo "FUSE smoke test passed: normal file operations and 4 GiB sparse-file read/write."
