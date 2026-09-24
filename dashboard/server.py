#!/usr/bin/env python3
"""Loopback-only web dashboard for the DenyFS Linux/FUSE CLI."""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit


APP_DIR = Path(__file__).resolve().parent
PROJECT_DIR = APP_DIR.parent
MAX_FILE_SIZE = 4 * 1024**3
MAX_CONTAINER_SIZE = 1024**4
MAX_JSON_SIZE = 1024 * 1024
CHUNK_SIZE = 1024 * 1024
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")
SESSION_LOCK = threading.RLock()
STATE: dict[str, object] = {"busy": False, "session": None}


@dataclass
class MountSession:
    session_id: str
    mode: str
    vault_name: str
    mount_dir: Path
    process: subprocess.Popen
    expected_files: dict[str, int] = field(default_factory=dict)
    uploaded_files: set[str] = field(default_factory=set)


def safe_vault_stem(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Enter a vault name.")
    value = value.strip()
    if value.lower().endswith(".denyfs"):
        value = value[:-7]
    if not NAME_RE.fullmatch(value) or value in {".", ".."} or value.endswith((".", " ")):
        raise ValueError("Use a vault name with letters, numbers, spaces, dots, dashes, or underscores.")
    return value


def safe_file_name(value: object) -> str:
    if not isinstance(value, str) or not value or value in {".", ".."}:
        raise ValueError("A file has an invalid name.")
    if "/" in value or "\\" in value or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError("DenyFS stores files in one flat folder. Rename files without folder paths or control characters.")
    if len(value.encode("utf-8")) > 250:
        raise ValueError("A file name is longer than DenyFS supports (250 UTF-8 bytes).")
    return value


def safe_library_name(value: str) -> str:
    if not isinstance(value, str) or not value.endswith(".denyfs"):
        raise ValueError("Choose a DenyFS vault from the library.")
    stem = value[:-7]
    if not NAME_RE.fullmatch(stem) or stem in {".", ".."} or stem.endswith((".", " ")):
        raise ValueError("Invalid vault name.")
    return value


def write_all(fd: int, payload: bytes | bytearray) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def validate_password(password: object) -> str:
    if not isinstance(password, str):
        raise ValueError("Enter a passphrase.")
    try:
        length = len(password.encode("utf-8"))
    except UnicodeEncodeError:
        raise ValueError("Enter a valid passphrase.")
    if not length or length > 511 or any(char in password for char in ("\0", "\n", "\r")):
        raise ValueError("Passphrases must be 1–511 UTF-8 bytes and cannot contain a line break.")
    return password


def run_with_password(binary: Path, args: list[str], password: str,
                      timeout: int | None = None) -> subprocess.CompletedProcess | subprocess.Popen:
    try:
        secret = bytearray(password.encode("utf-8"))
    except (AttributeError, UnicodeEncodeError):
        raise ValueError("Enter a valid passphrase.")
    if not secret or len(secret) > 511 or any(ch in secret for ch in (0, 10, 13)):
        for index in range(len(secret)):
            secret[index] = 0
        raise ValueError("Passphrases must be 1–511 UTF-8 bytes and cannot contain a line break.")

    read_fd, write_fd = os.pipe()
    try:
        write_all(write_fd, secret)
        write_all(write_fd, b"\n")
    except Exception:
        os.close(read_fd)
        raise
    finally:
        os.close(write_fd)
        for index in range(len(secret)):
            secret[index] = 0

    try:
        if args[0] == "mount":
            return subprocess.Popen(
                [str(binary), *args, "--password-fd", str(read_fd)],
                cwd=PROJECT_DIR,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                pass_fds=(read_fd,),
                start_new_session=True,
                close_fds=True,
            )
        return subprocess.run(
            [str(binary), *args, "--password-fd", str(read_fd)],
            cwd=PROJECT_DIR,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            pass_fds=(read_fd,),
            timeout=timeout,
            check=False,
        )
    finally:
        os.close(read_fd)


def is_mount(path: Path) -> bool:
    return path.is_mount()


def start_mount(binary: Path, mount_root: Path, vault_path: Path, vault_name: str,
                password: str, mode: str, expected_files: dict[str, int] | None = None) -> MountSession:
    if platform.system() != "Linux":
        raise RuntimeError("The DenyFS dashboard needs Linux with FUSE. On Windows, run it inside WSL2.")
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError("Build the executable DenyFS release binary first with `make release`.")
    if not Path("/dev/fuse").exists():
        raise RuntimeError("FUSE is unavailable. Enable /dev/fuse in WSL or install the Linux FUSE package.")
    if not (shutil.which("fusermount3") or shutil.which("fusermount")):
        raise RuntimeError("fusermount3 is missing. Install fuse3 before mounting a vault.")

    session_id = uuid.uuid4().hex
    mount_dir = mount_root / session_id
    mount_dir.mkdir(mode=0o700, exist_ok=False)
    process: subprocess.Popen | None = None
    try:
        process = run_with_password(
            binary,
            ["mount", str(vault_path), "--mountpoint", str(mount_dir)],
            password,
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("DenyFS could not unlock this vault. Check its password, format, and FUSE setup.")
            if is_mount(mount_dir):
                break
            time.sleep(0.05)
        else:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            raise RuntimeError("The vault did not mount in time. Check that FUSE is enabled.")

        return MountSession(
            session_id=session_id,
            mode=mode,
            vault_name=vault_name,
            mount_dir=mount_dir,
            process=process,
            expected_files=expected_files or {},
        )
    except Exception:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        try:
            mount_dir.rmdir()
        except OSError:
            pass
        raise


def stop_mount(session: MountSession) -> bool:
    if is_mount(session.mount_dir):
        unmount_tool = shutil.which("fusermount3") or shutil.which("fusermount")
        if not unmount_tool:
            return False
        result = subprocess.run(
            [unmount_tool, "-u", str(session.mount_dir)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
        if result.returncode != 0 and is_mount(session.mount_dir):
            return False

    try:
        session.process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        return False
    try:
        session.mount_dir.rmdir()
    except OSError:
        pass
    return True


def list_mounted_files(session: MountSession) -> list[dict[str, object]]:
    files: list[dict[str, object]] = []
    for entry in os.scandir(session.mount_dir):
        try:
            if entry.is_file(follow_symlinks=False):
                name = safe_file_name(entry.name)
                files.append({"name": name, "size": entry.stat(follow_symlinks=False).st_size})
        except (OSError, ValueError):
            continue
    files.sort(key=lambda item: str(item["name"]).casefold())
    return files


def check_container(data_dir: Path, name: str) -> Path:
    name = safe_library_name(name)
    path = data_dir / name
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise ValueError("That vault is not in the local library. Import its container file first.")
    if not path.is_file() or path.is_symlink() or info.st_size < 4096:
        raise ValueError("That file is not a valid local DenyFS container.")
    return path


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "DenyFS-Dashboard/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *args: object) -> None:
        # Request paths and payloads can contain private filenames. Keep the local server quiet.
        return

    def _local_request(self) -> bool:
        host = self.headers.get("Host", "")
        try:
            host_name = urlsplit("//" + host).hostname
        except ValueError:
            host_name = None
        if host_name not in {"127.0.0.1", "localhost", "::1"}:
            self._send_json(403, {"error": "This dashboard only accepts connections from this device."})
            return False
        origin = self.headers.get("Origin")
        if origin:
            origin_scheme = ""
            try:
                origin_parts = urlsplit(origin)
                origin_host = origin_parts.hostname
                origin_scheme = origin_parts.scheme
                origin_port = origin_parts.port or (443 if origin_parts.scheme == "https" else 80)
                host_port = urlsplit("//" + host).port or int(self.server.server_port)
            except ValueError:
                origin_host = None
                origin_port = None
                host_port = None
            if (origin_host not in {"127.0.0.1", "localhost", "::1"}
                    or origin_host != host_name or origin_port != host_port
                    or origin_scheme != "http"):
                self._send_json(403, {"error": "This dashboard only accepts requests from this device."})
                return False
        return True

    def _send_json(self, status: int, value: dict[str, object]) -> None:
        payload = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        self.end_headers()
        self.wfile.write(payload)

    def _security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )

    def _read_json(self) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "0"))
        if length < 2 or length > MAX_JSON_SIZE:
            raise ValueError("The request was empty or too large.")
        try:
            body = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("The request could not be read.")
        if not isinstance(body, dict):
            raise ValueError("The request is invalid.")
        return body

    def _data_dir(self) -> Path:
        return self.server.data_dir  # type: ignore[attr-defined, no-any-return]

    def _binary(self) -> Path:
        return self.server.binary  # type: ignore[attr-defined, no-any-return]

    def _mount_root(self) -> Path:
        return self.server.mount_root  # type: ignore[attr-defined, no-any-return]

    def _current_session(self) -> MountSession | None:
        with SESSION_LOCK:
            item = STATE.get("session")
            return item if isinstance(item, MountSession) else None

    def _authorized_session(self) -> MountSession | None:
        session = self._current_session()
        if session is None or self.headers.get("X-DenyFS-Session") != session.session_id:
            return None
        return session

    def do_GET(self) -> None:
        if not self._local_request():
            return
        parsed = urlsplit(self.path)
        route = parsed.path
        query = parse_qs(parsed.query, keep_blank_values=True)

        if route == "/api/status":
            session = self._current_session()
            with SESSION_LOCK:
                busy = bool(STATE.get("busy"))
            self._send_json(200, {
                "available": platform.system() == "Linux" and self._binary().is_file() and os.access(self._binary(), os.X_OK),
                "linux": platform.system() == "Linux",
                "fuse": Path("/dev/fuse").exists(),
                "fusermount": bool(shutil.which("fusermount3") or shutil.which("fusermount")),
                "binary": self._binary().name if self._binary().is_file() else None,
                "busy": busy,
                "session_id": session.session_id if session else None,
                "session_mode": session.mode if session else None,
                "vault_name": session.vault_name if session else None,
            })
            return

        if route == "/api/vaults":
            records = []
            for path in sorted(self._data_dir().glob("*.denyfs"), key=lambda item: item.name.casefold()):
                try:
                    info = path.lstat()
                    if stat.S_ISREG(info.st_mode):
                        records.append({
                            "name": path.name,
                            "size": info.st_size,
                            "modified": int(info.st_mtime),
                        })
                except OSError:
                    continue
            self._send_json(200, {"vaults": records})
            return

        if route == "/api/session/files":
            session = self._authorized_session()
            if session is None:
                self._send_json(403, {"error": "This vault session is no longer active."})
                return
            self._send_json(200, {
                "vault_name": session.vault_name,
                "files": list_mounted_files(session),
            })
            return

        if route == "/api/session/download":
            session = self._current_session()
            query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
            if session and query.get("session_id", [""])[0] != session.session_id:
                session = None
            if session is None or session.mode != "decrypt":
                self._send_json(403, {"error": "Unlock a vault before downloading files."})
                return
            try:
                name = safe_file_name(query.get("name", [""])[0])
                file_path = session.mount_dir / name
                info = file_path.stat(follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_SIZE:
                    raise ValueError("That file cannot be downloaded.")
            except (OSError, ValueError) as exc:
                self._send_json(404, {"error": str(exc) or "File not found."})
                return
            self._send_download(file_path, name, info.st_size)
            return

        if route == "/api/vaults/download":
            try:
                name = safe_library_name(query.get("name", [""])[0])
                path = check_container(self._data_dir(), name)
                self._send_download(path, name, path.stat().st_size)
            except (OSError, ValueError) as exc:
                self._send_json(404, {"error": str(exc) or "Vault not found."})
            return

        if route in {"/", "/index.html", "/styles.css", "/app.js"}:
            asset_name = "index.html" if route in {"/", "/index.html"} else route.lstrip("/")
            path = APP_DIR / asset_name
            try:
                payload = path.read_bytes()
            except OSError:
                self._send_json(404, {"error": "Dashboard asset not found."})
                return
            self.send_response(200)
            self.send_header("Content-Type", mimetypes.guess_type(path.name)[0] or "application/octet-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-cache")
            self._security_headers()
            self.end_headers()
            self.wfile.write(payload)
            return

        self._send_json(404, {"error": "Not found."})

    def _send_download(self, path: Path, filename: str, size: int) -> None:
        encoded_name = quote(filename, safe="")
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.send_header(
            "Content-Disposition",
            f"attachment; filename*=UTF-8''{encoded_name}",
        )
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        self.end_headers()
        with path.open("rb") as stream:
            shutil.copyfileobj(stream, self.wfile, length=CHUNK_SIZE)

    def do_POST(self) -> None:
        if not self._local_request():
            return
        route = urlsplit(self.path).path
        try:
            if route == "/api/encrypt":
                self._encrypt()
            elif route == "/api/encrypt/file":
                self._upload_encrypted_file()
            elif route == "/api/encrypt/finish":
                self._finish_encrypt()
            elif route == "/api/decrypt":
                self._decrypt()
            elif route == "/api/session/lock":
                self._lock_session()
            elif route == "/api/vaults/import":
                self._import_vault()
            else:
                self._send_json(404, {"error": "Not found."})
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
        except (OSError, subprocess.SubprocessError) as exc:
            self._send_json(500, {"error": f"The local vault operation failed: {exc.__class__.__name__}."})
        except RuntimeError as exc:
            self._send_json(500, {"error": str(exc)})

    def _reserve_operation(self) -> bool:
        with SESSION_LOCK:
            if STATE.get("busy") or STATE.get("session") is not None:
                return False
            STATE["busy"] = True
            return True

    def _release_operation(self) -> None:
        with SESSION_LOCK:
            STATE["busy"] = False

    def _encrypt(self) -> None:
        body = self._read_json()
        stem = safe_vault_stem(body.get("name"))
        password = validate_password(body.get("password"))
        try:
            size_mib = int(body.get("size_mib", 0))
        except (TypeError, ValueError):
            raise ValueError("Enter a valid container size in MiB.")
        if size_mib < 8 or size_mib > 65536:
            raise ValueError("Container size must be between 8 MiB and 65,536 MiB.")

        raw_files = body.get("files")
        if not isinstance(raw_files, list) or not raw_files or len(raw_files) > 63:
            raise ValueError("Choose between 1 and 63 files for this flat DenyFS vault.")
        expected: dict[str, int] = {}
        total_bytes = 0
        for item in raw_files:
            if not isinstance(item, dict):
                raise ValueError("The selected file list is invalid.")
            name = safe_file_name(item.get("name"))
            if name in expected:
                raise ValueError(f"Two selected files have the same name: {name}")
            try:
                size = int(item.get("size", -1))
            except (TypeError, ValueError):
                raise ValueError("A selected file has an invalid size.")
            if size < 0 or size > MAX_FILE_SIZE:
                raise ValueError(f"{name} is larger than DenyFS's 4 GiB per-file limit.")
            expected[name] = size
            total_bytes += size

        volume_bytes = size_mib * 1024 * 1024 // 2
        required_bytes = total_bytes + max(5 * 1024 * 1024, total_bytes // 1024)
        if required_bytes > volume_bytes:
            need_mib = (required_bytes * 2 + 1024 * 1024 - 1) // (1024 * 1024)
            raise ValueError(
                f"Those files need about {need_mib} MiB of container space. "
                "DenyFS exposes roughly half the container as the outer vault."
            )

        if not self._reserve_operation():
            self._send_json(409, {"error": "Finish or lock the current vault session first."})
            return

        vault_name = stem + ".denyfs"
        vault_path = self._data_dir() / vault_name
        try:
            if platform.system() != "Linux":
                raise RuntimeError("The DenyFS dashboard needs Linux with FUSE. On Windows, run it inside WSL2.")
            if not self._binary().is_file():
                raise RuntimeError("Build the DenyFS release binary first with `make release`.")
            if not Path("/dev/fuse").exists():
                raise RuntimeError("FUSE is unavailable. Enable /dev/fuse in WSL or install the Linux FUSE package.")
            if not (shutil.which("fusermount3") or shutil.which("fusermount")):
                raise RuntimeError("fusermount3 is missing. Install fuse3 before creating a vault.")
            if vault_path.exists():
                raise ValueError("A vault with that name already exists in the local library.")
            if shutil.disk_usage(self._data_dir()).free < size_mib * 1024 * 1024:
                raise ValueError("There is not enough free space in the local vault library for that container.")
            result = run_with_password(
                self._binary(),
                ["create", str(vault_path), "--size", str(size_mib)],
                password,
            )
            if not isinstance(result, subprocess.CompletedProcess) or result.returncode != 0:
                raise RuntimeError("DenyFS could not create the container. Check free disk space and the selected size.")
            try:
                session = start_mount(
                    self._binary(), self._mount_root(), vault_path, vault_name, password,
                    "encrypt", expected,
                )
            except RuntimeError as exc:
                raise RuntimeError(f"The container was created as {vault_name}, but it could not be mounted. {exc}")
            with SESSION_LOCK:
                STATE["session"] = session
            self._send_json(200, {
                "session_id": session.session_id,
                "vault_name": vault_name,
                "file_count": len(expected),
                "message": "Vault created and mounted. Files can now be encrypted into it.",
            })
        except Exception:
            # Container creation is intentionally not undone on mount failure.
            raise
        finally:
            self._release_operation()

    def _upload_encrypted_file(self) -> None:
        session = self._authorized_session()
        if session is None or session.mode != "encrypt":
            self._send_json(403, {"error": "Start an encryption session before uploading files."})
            return
        raw_name = self.headers.get("X-File-Name", "")
        try:
            name = safe_file_name(unquote(raw_name))
            length = int(self.headers.get("Content-Length", "-1"))
        except (ValueError, TypeError):
            raise ValueError("The uploaded file metadata is invalid.")
        if length < 0 or length > MAX_FILE_SIZE:
            raise ValueError("DenyFS accepts files up to 4 GiB each.")
        if name not in session.expected_files or session.expected_files[name] != length:
            raise ValueError("This file was not part of the selected import list or its size changed.")
        if name in session.uploaded_files:
            raise ValueError("That file has already been added to this vault.")

        destination = session.mount_dir / name
        created = False
        remaining = length
        try:
            with destination.open("xb") as output:
                created = True
                while remaining:
                    chunk = self.rfile.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise OSError("The browser upload ended early.")
                    output.write(chunk)
                    remaining -= len(chunk)
                output.flush()
        except Exception:
            if created:
                try:
                    destination.unlink()
                except OSError:
                    pass
            raise
        session.uploaded_files.add(name)
        self._send_json(200, {"name": name, "size": length, "uploaded": len(session.uploaded_files)})

    def _finish_encrypt(self) -> None:
        session = self._authorized_session()
        if session is None or session.mode != "encrypt":
            self._send_json(403, {"error": "There is no active encryption session."})
            return
        missing = set(session.expected_files) - session.uploaded_files
        if missing:
            self._send_json(409, {
                "error": f"{len(missing)} file(s) were not uploaded. Lock the vault to save the files already added."
            })
            return
        if not self._reserve_close(session):
            self._send_json(409, {"error": "The vault is already closing."})
            return
        try:
            if not stop_mount(session):
                self._send_json(500, {"error": "DenyFS could not cleanly unmount the vault. Keep this dashboard open and retry Lock."})
                return
            with SESSION_LOCK:
                STATE["session"] = None
            self._send_json(200, {
                "vault_name": session.vault_name,
                "file_count": len(session.uploaded_files),
                "message": "Files encrypted and the vault is locked.",
            })
        finally:
            self._release_operation()

    def _decrypt(self) -> None:
        body = self._read_json()
        name = safe_library_name(body.get("vault_name", ""))
        password = validate_password(body.get("password"))
        vault_path = check_container(self._data_dir(), name)
        if not self._reserve_operation():
            self._send_json(409, {"error": "Finish or lock the current vault session first."})
            return
        try:
            session = start_mount(
                self._binary(), self._mount_root(), vault_path, name, password, "decrypt",
            )
            with SESSION_LOCK:
                STATE["session"] = session
            try:
                files = list_mounted_files(session)
            except Exception:
                if stop_mount(session):
                    with SESSION_LOCK:
                        if STATE.get("session") is session:
                            STATE["session"] = None
                raise
            self._send_json(200, {
                "session_id": session.session_id,
                "vault_name": name,
                "files": files,
                "message": "Vault unlocked. Choose a file to decrypt and download.",
            })
        finally:
            self._release_operation()

    def _reserve_close(self, session: MountSession) -> bool:
        with SESSION_LOCK:
            if STATE.get("busy") or STATE.get("session") is not session:
                return False
            STATE["busy"] = True
            return True

    def _lock_session(self) -> None:
        body = self._read_json()
        session_id = body.get("session_id")
        session = self._current_session()
        if not session or session.session_id != session_id:
            self._send_json(409, {"error": "That vault session is no longer active."})
            return
        if not self._reserve_close(session):
            self._send_json(409, {"error": "The vault is already closing."})
            return
        try:
            if not stop_mount(session):
                self._send_json(500, {"error": "DenyFS could not cleanly unmount the vault. Keep this dashboard open and retry."})
                return
            with SESSION_LOCK:
                STATE["session"] = None
            self._send_json(200, {"message": "Vault locked."})
        finally:
            self._release_operation()

    def _import_vault(self) -> None:
        query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        requested_name = unquote(query.get("name", [""])[0])
        requested_name = Path(requested_name).name
        if requested_name.lower().endswith((".img", ".dny")):
            requested_name = requested_name.rsplit(".", 1)[0]
        stem = safe_vault_stem(requested_name)
        length = int(self.headers.get("Content-Length", "-1"))
        if length < 1024 * 1024 or length > MAX_CONTAINER_SIZE or length % 4096:
            raise ValueError("Choose an aligned DenyFS container between 1 MiB and 1 TiB.")
        target = self._data_dir() / (stem + ".denyfs")
        if target.exists():
            raise ValueError("A vault with that name already exists. Rename the imported container first.")
        if shutil.disk_usage(self._data_dir()).free < length:
            raise ValueError("There is not enough free space to import a second copy of this container.")
        partial = self._data_dir() / ("." + stem + "." + uuid.uuid4().hex + ".upload")
        remaining = length
        try:
            with partial.open("xb") as output:
                os.chmod(partial, 0o600)
                while remaining:
                    chunk = self.rfile.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise OSError("The container upload ended early.")
                    output.write(chunk)
                    remaining -= len(chunk)
                output.flush()
            os.link(partial, target)
            partial.unlink()
        except Exception:
            try:
                partial.unlink()
            except OSError:
                pass
            raise
        self._send_json(200, {"name": target.name, "size": length})


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the local DenyFS dashboard.")
    parser.add_argument("--binary", default=str(PROJECT_DIR / "denyfs-release"), help="Path to the built denyfs-release CLI")
    default_data_dir = Path.home() / ".local" / "share" / "denyfs-dashboard" / "vaults"
    parser.add_argument("--data-dir", default=str(default_data_dir), help="Local directory for encrypted container files")
    parser.add_argument("--mount-dir", default=str(Path(tempfile.gettempdir()) / "denyfs-dashboard-mounts"), help="Linux filesystem directory for temporary FUSE mount points")
    parser.add_argument("--host", default="127.0.0.1", help="Loopback only; remote binds are rejected")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        parser.error("The dashboard must bind to a loopback address.")

    binary = Path(args.binary).expanduser().resolve()
    data_dir = Path(args.data_dir).expanduser().resolve()
    mount_root = Path(args.mount_dir).expanduser().resolve()
    data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    mount_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(data_dir, 0o700)
    os.chmod(mount_root, 0o700)

    server = ThreadingHTTPServer((args.host, args.port), DashboardHandler)
    server.daemon_threads = False
    server.binary = binary  # type: ignore[attr-defined]
    server.data_dir = data_dir  # type: ignore[attr-defined]
    server.mount_root = mount_root  # type: ignore[attr-defined]
    print(f"DenyFS Dashboard: http://127.0.0.1:{args.port}")
    print(f"Local encrypted-vault library: {data_dir}")
    print(f"Temporary FUSE mounts: {mount_root}")
    print("Press Ctrl+C to stop the dashboard server.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard server.")
    finally:
        # Wait for in-flight create/upload requests before locking their mount.
        server.server_close()
        with SESSION_LOCK:
            session = STATE.get("session")
        if isinstance(session, MountSession):
            if not stop_mount(session):
                print("Warning: could not unmount the active DenyFS vault; unlock state may remain until manually unmounted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
