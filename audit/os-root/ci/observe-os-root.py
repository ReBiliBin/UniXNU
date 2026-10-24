#!/usr/bin/env python3
"""Bounded, serial QMP observation of the pinned UniXNU original-userland VM.

Only generated JSON and PNG under --public-dir are publication candidates.
Raw command output, serial/kernel text, QEMU scratch and input files stay private.
This script never publishes artifacts and never declares the UI visually normal.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import traceback
import zlib

DEVICE_PIN = "97b75b1f63c6b7e895cd7646029db741d5fe5488"
PS_BLOB = "f505c43b2bfcf14cc2a3dca5a2a80eeb8d57f301"
LAUNCHD_SHA = "8cec9a3c44a443b08e977ccc5d577850316ad428c575dc01f09b018dbd5b6a25"
EXPECTED = {
    "native_owner_root_accepted": 1, "native_owner_root_decision": 1,
    "native_owner_root_readonly": 1, "native_owner_cache_status": 0,
    "native_owner_cache_mount_status": 0, "native_owner_cache_authorized": 1,
    "native_owner_cache_native_union": 1, "native_owner_data_status": 0,
    "native_owner_data_readonly": 0, "native_owner_boot_manifest_status": 0,
}
VALUES = tuple(EXPECTED) + ("native_legacy_stage", "native_legacy_frame_count")
SERVICE_NAMES = {"logd", "configd", "securityd"}
ERROR_REASONS = {
    "kernel log unavailable: invalid msgbuf pointer",
    "kernel log unavailable: invalid msgbuf magic",
    "kernel log unavailable: ring size exceeds collector bounds",
    "kernel log unavailable: invalid ring write index",
    "kernel log unavailable: invalid ring pointer",
    "path outside the dedicated project", "expected project regular file", "forbidden QEMU backend",
    "unexpected QEMU boot parameters", "no exact private QMP socket",
    "QMP socket is not in the project temporary directory", "QMP socket is not ready",
    "QMP endpoint is not a socket", "disk is not a read-only project regular file",
    "OS/SystemOS backends do not match the intended run", "unexpected firmware or ESP drive",
    "firmware/variables/ESP path validation failed", "unexpected QEMU device list", "QEMU child is not ready",
    "cannot identify exactly one live QEMU child for this run", "invalid QMP greeting", "QMP closed",
    "unexpected PPM format", "unexpected framebuffer dimensions", "PPM pixel size mismatch",
    "public output must be a new project subdirectory", "TMPDIR must be a project directory",
    "unexpected observation source or missing regular-file adaptation", "unexpected OS raw length",
    "preparation receipt or original launchd/raw binding mismatch", "multiple new VM run directories",
    "VM failed to become observable", "QEMU PID identity changed", "observation budget exhausted", "timed out",
}
QMP_OPERATIONS = {"qmp_capabilities", "query-status", "screendump", "send-key", "input-send-event", "quit"}


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for data in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            h.update(data)
    return h.hexdigest()


def write_json(path, data):
    target = Path(path)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    temporary.replace(target)


def within(path, project, *, regular=False):
    result = Path(path).resolve(strict=True)
    if result == project or project not in result.parents:
        raise ValueError("path outside the dedicated project")
    if regular and not stat.S_ISREG(result.stat().st_mode):
        raise ValueError("expected project regular file")
    return result


def blob(path):
    content = Path(path).read_bytes()
    return hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()


def processes():
    text = subprocess.check_output(["ps", "-ww", "-axo", "pid=,ppid=,command="],
                                   text=True, timeout=10)
    rows = []
    for line in text.splitlines():
        found = re.match(r"\s*(\d+)\s+(\d+)\s+(.*)", line)
        if found:
            rows.append((int(found[1]), int(found[2]), found[3]))
    return rows


def verify_vm(run, runner_pid, project, os_raw, tmp):
    """Associate this run's exact QMP/serial paths with a live child PID."""
    command = (run / "command.txt").read_text()
    if re.search(r"host_device|usb-host|vfio|/dev/|\\\\\.\\|(?:^| )-netdev(?: |$)", command):
        raise ValueError("forbidden QEMU backend")
    if (command.count("-nic none") != 1 or "-accel tcg" not in command
            or "-display none" not in command or "-no-reboot" not in command
            or "-shared" in command or "memory-backend-file" in command):
        raise ValueError("unexpected QEMU boot parameters")
    qmp_match = re.search(r"(?:^| )-qmp unix:([^,\n]+),server=on,wait=off(?: |$)", command)
    if not qmp_match:
        raise ValueError("no exact private QMP socket")
    sock = Path(qmp_match[1]).resolve()
    if tmp not in sock.parents:
        raise ValueError("QMP socket is not in the project temporary directory")
    if not sock.exists():
        raise FileNotFoundError("QMP socket is not ready")
    if not sock.is_socket():
        raise ValueError("QMP endpoint is not a socket")
    # JSON arguments are joined without shell quoting in command.txt. Decode
    # them as JSON, rather than interpreting this record as shell syntax.
    backends = []
    for found in re.finditer(r"(?:^| )-blockdev ", command):
        obj, _ = json.JSONDecoder().raw_decode(command[found.end():])
        if (obj.get("driver") != "raw" or obj.get("read-only") is not True
                or obj.get("file", {}).get("driver") != "file"
                or obj["file"].get("read-only") is not True):
            raise ValueError("disk is not a read-only project regular file")
        backends.append((obj.get("node-name"), within(obj["file"]["filename"], project, regular=True)))
    if dict(backends).get("os") != os_raw or set(dict(backends)) != {"os", "systemos"}:
        raise ValueError("OS/SystemOS backends do not match the intended run")
    drives = re.findall(r"(?:^| )-drive (\S+)", command)
    firmware, variables, esp = False, False, False
    for drive in drives:
        if drive.startswith("if=pflash,format=raw,readonly=on,file="):
            path = Path(drive.split("file=", 1)[1]).resolve(strict=True)
            firmware = path.name == "edk2-aarch64-code.fd" and path.is_file()
        elif drive.startswith("if=pflash,format=raw,file="):
            path = within(drive.split("file=", 1)[1], project, regular=True)
            variables = tmp in path.parents and path.name == "vars.fd"
        elif drive.startswith("if=none,id=esp,format=raw,readonly=on,file=fat:"):
            esp = Path(drive.split("file=fat:", 1)[1]).resolve(strict=True) == run / "esp"
        else:
            raise ValueError("unexpected firmware or ESP drive")
    if len(drives) != 3 or not all((firmware, variables, esp)):
        raise ValueError("firmware/variables/ESP path validation failed")
    allowed_devices = {"virtio-blk-pci,drive=esp", "ramfb", "qemu-xhci", "usb-kbd",
                       "virtio-blk-device,drive=os", "virtio-blk-device,drive=systemos",
                       "virtio-tablet-device", "virtio-keyboard-device"}
    if set(re.findall(r"(?:^| )-device (\S+)", command)) != allowed_devices:
        raise ValueError("unexpected QEMU device list")
    serial = str(run / "serial.log")
    matches = [(pid, line) for pid, parent, line in processes()
               if parent == runner_pid and "qemu-system-aarch64" in line
               and str(sock) in line and serial in line]
    if not matches:
        raise FileNotFoundError("QEMU child is not ready")
    if len(matches) != 1:
        raise ValueError("cannot identify exactly one live QEMU child for this run")
    return sock, matches[0][0]


class QMP:
    """One operation group, one connection; always close before qemu-ps."""
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.sock.settimeout(10)
            self.sock.connect(str(self.path))
            self.stream = self.sock.makefile("rwb", buffering=0)
            if not json.loads(self.stream.readline()).get("QMP"):
                raise ValueError("invalid QMP greeting")
            self.execute("qmp_capabilities")
            return self
        except BaseException:
            if hasattr(self, "stream"):
                self.stream.close()
            self.sock.close()
            raise

    def execute(self, name, **arguments):
        self.stream.write((json.dumps({"execute": name, "arguments": arguments}) + "\n").encode())
        while True:
            line = self.stream.readline()
            if not line:
                raise ConnectionError("QMP closed")
            reply = json.loads(line)
            if "error" in reply:
                raise RuntimeError("QMP command failed: " + name)
            if "return" in reply:
                return reply["return"]

    def __exit__(self, *_):
        self.stream.close()
        self.sock.close()


def ppm_pixels(data):
    """Parse binary P6 without stripping legitimate leading pixel whitespace."""
    tokens, at = [], 0
    while len(tokens) < 4:
        while at < len(data):
            if data[at:at + 1].isspace():
                at += 1
            elif data[at:at + 1] == b"#":
                at = data.index(b"\n", at) + 1
            else:
                break
        end = at
        while end < len(data) and not data[end:end + 1].isspace():
            end += 1
        tokens.append(data[at:end])
        at = end
    if tokens[0] != b"P6" or tokens[3] != b"255":
        raise ValueError("unexpected PPM format")
    width, height = int(tokens[1]), int(tokens[2])
    if not 1 <= width <= 4096 or not 1 <= height <= 4096:
        raise ValueError("unexpected framebuffer dimensions")
    at += 2 if data[at:at + 2] == b"\r\n" else 1
    pixels = data[at:]
    if len(pixels) != width * height * 3:
        raise ValueError("PPM pixel size mismatch")
    return width, height, pixels


def encode_png(width, height, pixels):
    def chunk(kind, body):
        return (struct.pack(">I", len(body)) + kind + body
                + struct.pack(">I", zlib.crc32(kind + body) & 0xffffffff))
    rows = b"".join(b"\0" + pixels[y * width * 3:(y + 1) * width * 3] for y in range(height))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows, 6)) + chunk(b"IEND", b""))


def pixel_stats(width, height, pixels, previous=None):
    count = width * height
    result = {"width": width, "height": height, "pixels_sha256": hashlib.sha256(pixels).hexdigest(),
              "nonblack_pixels": sum(pixels[i:i + 3] != b"\0\0\0" for i in range(0, len(pixels), 3)),
              "nonwhite_pixels": sum(pixels[i:i + 3] != b"\xff\xff\xff" for i in range(0, len(pixels), 3))}
    result["single_color"] = pixels == pixels[:3] * count
    if previous is not None and len(previous) == len(pixels):
        result["changed_pixels_from_previous"] = sum(
            pixels[i:i + 3] != previous[i:i + 3] for i in range(0, len(pixels), 3))
    return result


def parse_procs(text):
    rows = []
    for line in text.splitlines():
        found = re.fullmatch(r"\s*(\d+)\s+(idle|run|stop|zombie|reaped|\d+)\s+([\w ._/-]{1,64})", line,
                             flags=re.ASCII)
        if found:
            rows.append({"pid": int(found[1]), "state": found[2], "name": found[3].strip()})
    return rows


def parse_values(text):
    result = {}
    for name, decimal in re.findall(r"^(\w+) = (\d+) \(0x[0-9a-f]+\)$", text, flags=re.M):
        if name in VALUES:
            result[name] = int(decimal)
    return result


def sanitized_log(text):
    """Necessary diagnostic text only; never export raw register/memory dumps."""
    keep = []
    for line in text.splitlines():
        if not re.search(r"launchd|dyld|panic|jetsam|apfs|owner_|native_|SpringBoard|backboardd|"
                         r"AMFI|trust.?cache|ENOSPC|EROFS|mount|I/O error", line, re.I):
            continue
        if (len(line) > 1000 or re.search(r"(?:\b[0-9a-f]{8,16}\b\s+){2}|"
                                         r"(?:\b[0-9a-f]{2}\b\s+){4}|"
                                         r"\b(?:registers?|machine.?code|hexdump)\b", line, re.I)):
            continue
        line = re.sub(r"0x[0-9a-f]+|\b[0-9a-f]{16,}\b", "<hex>", line, flags=re.I)
        keep.append("".join(c for c in line if 32 <= ord(c) < 127))
    return "\n".join(keep[-2000:]) + "\n"


def diagnostic_text(text, project=None):
    """Retain startup/error formats only, with no PEM, dumps or encoded payloads.

    This is intentionally narrower than a general log scrubber: unmatched lines
    are discarded. Raw traceback source lines and raw monitor replies never pass.
    """
    keep, pem = [], False
    secret = re.compile(r"\b(?:api[_-]?key|access[_-]?token|github_token|password|authorization|"
                        r"client[_-]?secret|private[_-]?key)\b", re.I)
    for raw in text.splitlines():
        if "-----BEGIN " in raw:
            pem = True
        if pem:
            if "-----END " in raw:
                pem = False
            continue
        line = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", raw).strip()
        if not line or len(line) > 1200 or secret.search(line):
            continue
        if (re.search(r"(?:\b(?:0x)?[0-9a-f]{8,16}\b[ ,:\t]+){2}|"
                      r"(?:\b[0-9a-f]{2}\b\s+){4}|"
                      r"\b(?:registers?|machine.?code|hexdump|pmemsave)\b|\bx\d{1,2}\s*=", line, re.I)
                or re.match(r"(?:0x)?[0-9a-f]{8,16}\s*:", line, re.I)):
            continue
        allowed = bool(
            line in ERROR_REASONS
            or line == "Traceback (most recent call last):"
            or re.fullmatch(r'File "[^"\r\n]+", line \d+(?:, in [A-Za-z0-9_<>.]+)?', line)
            or re.match(r"(?:qemu-system-aarch64|qemu-img|mcopy|xcrun|ld|ld64\.lld|lld|clang): ", line)
            or re.match(r"dyld(?:\[\d+\])?: (?:Library not loaded|Symbol not found|missing symbol)", line, re.I)
            or re.match(r"(?:Referenced from|Reason|Library not loaded): ", line)
            or re.match(r"(?:UNIXNU|DARWINBOOT): ", line)
            or re.fullmatch(r"qemu exit -?\d+; \d+ screenshots in .+", line)
            or re.fullmatch(r"(?:[^ ]+ )?serial\.log has no kernel load address yet", line)
            or re.fullmatch(r"\S+/serial\.log has no kernel load address yet", line)
            or re.fullmatch(r"(?:" + "|".join(map(re.escape, VALUES + ("cpu_ttep", "allproc", "msgbufp")))
                            + r") is not a kernel symbol", line)
            or re.match(r"(?:FileNotFoundError|ConnectionRefusedError|ConnectionResetError|TimeoutError|"
                        r"PermissionError|OSError|RuntimeError|ValueError|CalledProcessError|SystemExit): ", line)
        )
        if not allowed:
            continue
        exception_line = re.fullmatch(r"([A-Za-z]+Error|SystemExit): (.*)", line)
        if exception_line and exception_line[1] != "CalledProcessError":
            kind, detail = exception_line.groups()
            errno = re.match(r"\[Errno (\d+)\]", detail)
            if errno:
                number = int(errno[1])
                line = f"{kind}: errno {number}: {os.strerror(number)}"
            elif detail not in ERROR_REASONS and not (
                    detail.startswith("QMP command failed: ")
                    and detail.removeprefix("QMP command failed: ") in QMP_OPERATIONS):
                line = kind + ": exception detail withheld"
        # Do not reproduce a CalledProcessError's argv, which may contain more
        # than filenames in future revisions. Its numeric exit status suffices.
        if line.startswith("CalledProcessError:"):
            status = re.search(r"(?:exit status|returncode) (-?\d+)", line)
            line = "CalledProcessError: child exit status " + (status[1] if status else "unavailable")
        if project is not None:
            line = line.replace(str(project), "$PROJECT")
        line = re.sub(r"0x[0-9a-f]+|\b[0-9a-f]{8,}\b", "<hex>", line, flags=re.I)
        line = re.sub(r"(?<![A-Za-z0-9_/.\\-])[A-Za-z0-9+/=_-]{32,}(?![A-Za-z0-9_/.\\-])",
                      "<encoded>", line)
        line = "".join(c for c in line if 32 <= ord(c) < 127)
        keep.append(line)
    return "\n".join(keep[-500:]) + ("\n" if keep else "")


def exception_reason(exception, project):
    """Publish a known reason, never an arbitrary exception string or repr."""
    message = str(exception)
    if message in ERROR_REASONS:
        return message
    if message.startswith("QMP command failed: ") and message.removeprefix("QMP command failed: ") in QMP_OPERATIONS:
        return message
    if isinstance(exception, subprocess.TimeoutExpired):
        return "subprocess exceeded timeout (" + str(round(float(exception.timeout), 3)) + " seconds)"
    if isinstance(exception, subprocess.CalledProcessError):
        return "subprocess returned exit status " + str(int(exception.returncode))
    if isinstance(exception, OSError) and isinstance(exception.errno, int):
        reason = f"errno {exception.errno}: {os.strerror(exception.errno)}"
        filename = exception.filename
        if filename is not None:
            filename = str(filename).replace(str(project), "$PROJECT")
            if re.fullmatch(r"[A-Za-z0-9_./\\:@+() $,\[\]-]{1,400}", filename):
                reason += "; file=" + filename
        return reason
    if isinstance(exception, json.JSONDecodeError):
        return f"invalid JSON at line {exception.lineno}, column {exception.colno}"
    if isinstance(exception, KeyboardInterrupt) and re.fullmatch(r"signal \d+", message):
        return message
    return "exception detail withheld; original traceback retained privately"


def acceptance(samples):
    valid = []
    for sample in samples:
        names = {p["name"] for p in sample.get("processes", []) if p["state"] not in {"zombie", "reaped"}}
        pid1 = any(p["pid"] == 1 and p["name"] == "launchd" and p["state"] in {"run", "idle"}
                   for p in sample.get("processes", []))
        policy = all(sample.get("values", {}).get(k) == v for k, v in EXPECTED.items())
        if pid1 and len(names & SERVICE_NAMES) >= 2 and policy:
            valid.append((sample, names))
    latest = samples[-1] if samples else None
    stable = [(a, b, an, bn) for a, an in valid for b, bn in valid
              if b is latest and b["elapsed_seconds"] - a["elapsed_seconds"] >= 60]
    ui = any({"SpringBoard", "backboardd"} <= an & bn
             and a["values"].get("native_legacy_stage") == b["values"].get("native_legacy_stage") == 10
             and b["values"].get("native_legacy_frame_count", 0) > a["values"].get("native_legacy_frame_count", 0)
             for a, b, an, bn in stable)
    return {"original_userland_runtime_criteria": bool(stable), "ui_telemetry_candidate": ui,
            "ui_visually_normal": None, "input_visually_responded": None,
            "manual_review_required": True,
            "note": "Process names, increasing frames and QMP input acceptance do not prove a normal UI."}


class Observer:
    def __init__(self, args):
        self.args = args
        self.project = args.project_root.resolve(strict=True)
        self.tree = within(args.tree, self.project)
        self.raw = within(args.os_raw_image, self.project, regular=True)
        self.public = args.public_dir.resolve()
        if self.project not in self.public.parents or self.public.exists():
            raise ValueError("public output must be a new project subdirectory")
        self.public.mkdir(parents=True)
        (self.public / "screenshots").mkdir()
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{os.getpid()}"
        self.private = self.project / "work/os-root-observer" / stamp
        self.private.mkdir(parents=True, exist_ok=False)
        self.tmp = Path(os.environ.get("TMPDIR", str(self.project / ".q"))).resolve()
        if self.project not in self.tmp.parents:
            raise ValueError("TMPDIR must be a project directory")
        self.tmp.mkdir(parents=True, exist_ok=True)
        self.summary = {"schema": 1, "device_source_pin": DEVICE_PIN, "started_utc": utc(),
                        "budget_seconds": args.seconds, "samples": [], "screenshots": [],
                        "input_steps": [], "errors": [], "publication_scope": "generated whitelist JSON and rendered PNG only"}
        self.runner = None
        self.run = None
        self.diagnostic_run = None
        self.socket = None
        self.vm_pid = None
        self.previous_pixels = None
        self.start = time.monotonic()
        self.deadline = self.start + args.seconds

    def elapsed(self):
        return round(time.monotonic() - self.start, 3)

    def remaining(self):
        return max(0, self.deadline - time.monotonic())

    def save(self):
        self.summary["acceptance"] = acceptance(self.summary["samples"])
        write_json(self.public / "os-root-summary.json", self.summary)

    def error(self, code, exception=None):
        record = {"elapsed_seconds": self.elapsed(), "code": code}
        if exception is not None:
            record["exception_type"] = type(exception).__name__
            record["reason"] = exception_reason(exception, self.project)
            with (self.private / "observer-errors.txt").open("a") as stream:
                stream.write(traceback.format_exc() + "\n")
        self.summary["errors"].append(record)
        self.save()

    def preflight(self):
        ps = within(self.tree / "scripts/qemu-ps.py", self.project, regular=True)
        run = within(self.tree / "scripts/run-qemu.py", self.project, regular=True)
        if blob(ps) != PS_BLOB or "--os-raw-image" not in run.read_text():
            raise ValueError("unexpected observation source or missing regular-file adaptation")
        if self.raw.stat().st_size != 6077580800:
            raise ValueError("unexpected OS raw length")
        # build-os-root detached the authenticated source mount after preparing
        # Data. Consume its checked receipt, rather than remounting for runtime.
        prepared = within(self.tree / "build/os-root-inputs.json", self.project, regular=True)
        receipt = json.loads(prepared.read_text())
        launchd_sha = receipt.get("original_launchd_sha256")
        raw_hash = digest(self.raw)
        raw_record = receipt.get("os_raw_image", {})
        if (receipt.get("schema") != 1 or receipt.get("ready") is not True
                or receipt.get("device_commit") != DEVICE_PIN or launchd_sha != LAUNCHD_SHA
                or receipt.get("original_launchd_hash_verified") is not True
                or raw_record != {"path": str(self.raw), "size": 6077580800, "sha256": raw_hash}):
            raise ValueError("preparation receipt or original launchd/raw binding mismatch")
        self.summary["inputs"] = {"os_raw_bytes": self.raw.stat().st_size, "os_raw_sha256": raw_hash,
                                   "original_launchd_sha256": launchd_sha, "original_launchd_hash_verified": True,
                                   "qemu_ps_git_blob": blob(ps), "run_qemu_sha256": digest(run),
                                   "preparation_report_sha256": digest(prepared)}
        self.save()

    def launch(self):
        directory = self.tree.parent / "run"
        before = set(directory.iterdir()) if directory.exists() else set()
        self.run_parent, self.run_before = directory, before
        command = [sys.executable, str(self.tree / "scripts/run-qemu.py"), "--os-root",
                   "--os-raw-image", str(self.raw), "--accel", "tcg", "--display", "none",
                   "--screen", "firmware", "--seconds", str(self.args.seconds),
                   "--every", str(self.args.seconds + 30)]
        write_json(self.private / "observer-command.json", command)
        environment = dict(os.environ, TMPDIR=str(self.tmp), UNIXNU_AUDIT_PROJECT_ROOT=str(self.project),
                           UNIXNU_QEMU_ACCEL="tcg")
        self.output = (self.private / "runner-output.log").open("wb")
        self.runner = subprocess.Popen(command, cwd=self.tree, env=environment, stdout=self.output,
                                       stderr=subprocess.STDOUT, start_new_session=True)
        self.summary["runner_pid"] = self.runner.pid
        while self.remaining() and self.runner.poll() is None:
            new = sorted(p for p in directory.iterdir() if p not in before) if directory.exists() else []
            if len(new) > 1:
                raise ValueError("multiple new VM run directories")
            if new:
                self.diagnostic_run = within(new[0], self.project)
            if new and (new[0] / "command.txt").is_file():
                candidate = within(new[0], self.project)
                try:
                    self.socket, self.vm_pid = verify_vm(candidate, self.runner.pid, self.project, self.raw, self.tmp)
                    self.run = candidate
                    self.summary["vm_pid"] = self.vm_pid
                    self.summary["run_relative_path"] = str(self.run.relative_to(self.project))
                    self.summary["qemu_command_sha256"] = digest(self.run / "command.txt")
                    self.summary["launch_wait_seconds"] = self.elapsed()
                    self.summary["qemu_observable_utc"] = utc()
                    self.start = time.monotonic()
                    self.deadline = self.start + self.args.seconds
                    self.save()
                    return
                except FileNotFoundError:
                    if self.elapsed() > 120:
                        raise
            time.sleep(1)
        raise RuntimeError("VM failed to become observable")

    def check_live(self):
        if self.runner.poll() is not None:
            return False
        _, current = verify_vm(self.run, self.runner.pid, self.project, self.raw, self.tmp)
        if current != self.vm_pid:
            raise ValueError("QEMU PID identity changed")
        return True

    def ps(self, label, flags):
        remaining = min(self.args.sample_timeout, self.remaining())
        if remaining < 1:
            raise TimeoutError("observation budget exhausted")
        result = subprocess.run([sys.executable, str(self.tree / "scripts/qemu-ps.py"), "--run", str(self.run), *flags],
                                cwd=self.tree, capture_output=True, timeout=remaining)
        raw = self.private / (label + ".txt")
        raw.write_bytes(result.stdout + b"\n--- STDERR ---\n" + result.stderr)
        status = {"exit_code": result.returncode, "raw_output_sha256": digest(raw)}
        diagnostics = diagnostic_text(result.stderr.decode("utf-8", "replace") + "\n"
                                      + result.stdout.decode("utf-8", "replace"), self.project)
        if diagnostics:
            status["diagnostic_excerpt"] = diagnostics.splitlines()[-6:]
        return status, result.stdout.decode("utf-8", "replace")

    def sample(self):
        sample = {"elapsed_seconds": self.elapsed(), "vm_pid": self.vm_pid, "observed_utc": utc(),
                  "processes": [], "values": {}, "commands": {},
                  "kernel_log_available": False, "panic_text_seen": None}
        label = f"sample-{len(self.summary['samples']):03d}"
        for kind in ("processes", "values", "log"):
            try:
                if not self.check_live():
                    break
                flags = []
                if kind == "values":
                    flags = [part for name in VALUES for part in ("--value", name)]
                log = self.private / (label + "-kernel.log")
                if kind == "log":
                    flags = ["--log", str(log)]
                status, text = self.ps(label + "-" + kind, flags)
                sample["commands"][kind] = status
                if kind == "processes" and status["exit_code"] == 0:
                    sample["processes"] = parse_procs(text)
                elif kind == "values":
                    sample["values"] = parse_values(text)
                elif kind == "log" and status["exit_code"] == 0 and log.is_file():
                    sample["kernel_log_available"] = True
                    sample["kernel_log_sha256"] = digest(log)
                    kernel = log.read_text(errors="replace")
                    sample["panic_text_seen"] = bool(re.search(r"panic\(cpu|panicString|Kernel panic", kernel, re.I))
                    (self.public / (label + "-kernel.log")).write_text(sanitized_log(kernel))
            except Exception as exc:
                self.error("sample_" + kind + "_failed", exc)
            finally:
                # qemu-ps reads physical memory privately; no dump is publishable.
                (self.run / "pmem.bin").unlink(missing_ok=True)
        sample["completed_elapsed_seconds"] = self.elapsed()
        self.summary["samples"].append(sample)
        write_json(self.public / (label + ".json"), sample)
        self.save()

    def screenshot(self, label):
        self.check_live()
        private_ppm = self.private / (label + ".ppm")
        try:
            with QMP(self.socket) as monitor:
                status = monitor.execute("query-status")
                monitor.execute("screendump", filename=str(private_ppm))
            width, height, pixels = ppm_pixels(private_ppm.read_bytes())
            png = self.public / "screenshots" / (label + ".png")
            png.write_bytes(encode_png(width, height, pixels))
            record = {"file": "screenshots/" + png.name, "elapsed_seconds": self.elapsed(),
                      "vm_pid": self.vm_pid, "sha256": digest(png),
                      "qemu_status": status.get("status") if status.get("status") in
                      {"running", "paused", "shutdown", "guest-panicked", "prelaunch"} else "other",
                      **pixel_stats(width, height, pixels, self.previous_pixels)}
            self.summary["screenshots"].append(record)
            self.previous_pixels = pixels
            self.save()
            return record
        finally:
            private_ppm.unlink(missing_ok=True)

    def inputs(self):
        """Fixed simulated VM controls; QMP acknowledgement is not guest/UI proof."""
        self.screenshot("input-before")
        steps = [("home", 3), ("tap-quarter", 10), ("home-return", 3)]
        for name, wait in steps:
            if self.remaining() < wait + 5 or not self.check_live():
                self.summary["input_steps"].append({"step": name, "skipped": True})
                break
            record = {"step": name, "elapsed_seconds": self.elapsed(), "vm_pid": self.vm_pid,
                      "transport_acknowledged": False, "guest_response_verified": None}
            with QMP(self.socket) as monitor:
                if name.startswith("home"):
                    monitor.execute("send-key", keys=[{"type": "qcode", "data": "home"}], **{"hold-time": 100})
                else:
                    monitor.execute("input-send-event", events=[
                        {"type": "abs", "data": {"axis": "x", "value": 8192}},
                        {"type": "abs", "data": {"axis": "y", "value": 8192}},
                        {"type": "btn", "data": {"down": True, "button": "left"}}])
                    time.sleep(0.15)
                    monitor.execute("input-send-event", events=[
                        {"type": "btn", "data": {"down": False, "button": "left"}}])
                record["transport_acknowledged"] = True
            self.summary["input_steps"].append(record)
            self.save()
            time.sleep(wait)
            self.screenshot("input-after-" + name)

    def observe(self):
        next_sample, input_attempted = 0, False
        while self.remaining() > 1 and self.check_live():
            if self.elapsed() >= next_sample:
                self.sample()
                if self.remaining() > 12 and self.check_live():
                    try:
                        self.screenshot(f"screen-{int(self.elapsed()):04d}s")
                    except Exception as exc:
                        self.error("screenshot_failed", exc)
                next_sample = self.elapsed() + self.args.every
            ui = acceptance(self.summary["samples"])["ui_telemetry_candidate"]
            if not input_attempted and ui and self.elapsed() >= min(600, self.args.seconds // 2) and self.remaining() > 40:
                input_attempted = True
                try:
                    self.inputs()
                except Exception as exc:
                    self.error("input_sequence_failed", exc)
            time.sleep(min(1, self.remaining()))
        self.summary["observation_completed_elapsed_seconds"] = self.elapsed()
        self.summary["input_attempted"] = input_attempted
        self.summary["termination_reason"] = "budget_complete" if self.remaining() <= 1 else "vm_or_runner_exited_early"

    def cleanup(self):
        # The child runner has its own session: only terminate that owned group.
        if self.runner is not None:
            vm_owned = False
            if self.vm_pid is not None:
                try:
                    vm_owned = (os.getpgid(self.vm_pid) == self.runner.pid and any(
                        pid == self.vm_pid and str(self.socket) in line and str(self.run / "serial.log") in line
                        for pid, _, line in processes()))
                except ProcessLookupError:
                    pass
            if vm_owned:
                try:
                    with QMP(self.socket) as monitor:
                        monitor.execute("quit")
                    self.summary["qmp_quit_acknowledged"] = True
                except Exception as exc:
                    self.error("qmp_quit_failed", exc)
            if self.runner.poll() is None:
                try:
                    if self.run is None:
                        os.killpg(self.runner.pid, signal.SIGTERM)
                    self.runner.wait(timeout=45)
                except subprocess.TimeoutExpired:
                    self.summary["runner_force_terminated"] = True
                    os.killpg(self.runner.pid, signal.SIGTERM)
                    try:
                        self.runner.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(self.runner.pid, signal.SIGKILL)
                        self.runner.wait(timeout=10)
            # An early Python-runner exception must not leave its QEMU child.
            if vm_owned:
                try:
                    if os.getpgid(self.vm_pid) == self.runner.pid:
                        os.killpg(self.runner.pid, signal.SIGTERM)
                        self.summary["owned_vm_group_cleanup_requested"] = True
                except ProcessLookupError:
                    pass
                limit = time.monotonic() + 5
                while time.monotonic() < limit:
                    try:
                        if os.getpgid(self.vm_pid) != self.runner.pid:
                            break
                    except ProcessLookupError:
                        break
                    time.sleep(0.1)
                try:
                    if os.getpgid(self.vm_pid) == self.runner.pid:
                        os.killpg(self.runner.pid, signal.SIGKILL)
                        self.summary["owned_vm_group_kill_requested"] = True
                except ProcessLookupError:
                    pass
            self.summary["runner_exit_code"] = self.runner.returncode
            self.output.close()
            raw = self.private / "runner-output.log"
            text = raw.read_text(errors="replace")
            actual = re.findall(r"qemu exit (-?\d+);", text)
            self.summary["qemu_reported_exit_code"] = int(actual[-1]) if actual else None
            self.summary["runner_output_sha256"] = digest(raw)
            if self.run is not None and (self.run / "run-result.json").is_file():
                lifecycle = json.loads((self.run / "run-result.json").read_text())
                self.summary["run_lifecycle"] = {
                    key: lifecycle[key] for key in
                    ("qemu_exit", "screenshots", "elapsed_seconds", "requested_seconds")
                    if key in lifecycle and type(lifecycle[key]) in (int, float)
                }
        if self.run is not None:
            (self.run / "pmem.bin").unlink(missing_ok=True)
            for name in ("serial.log", "qemu.log", "command.txt"):
                path = self.run / name
                if path.is_file():
                    self.summary[name.replace(".", "_") + "_sha256"] = digest(path)
        try:
            self.export_diagnostics()
        except Exception as exc:
            self.error("diagnostics_export_failed", exc)
        self.summary["finished_utc"] = utc()
        self.summary["total_elapsed_seconds"] = self.elapsed()
        self.save()

    def export_diagnostics(self):
        """Export only filtered text, including runs that failed before ready."""
        candidate = self.run or self.diagnostic_run
        if candidate is None and hasattr(self, "run_parent") and self.run_parent.exists():
            new = [p for p in self.run_parent.iterdir() if p not in self.run_before]
            if len(new) == 1:
                candidate = within(new[0], self.project)
        sources = {"runner": self.private / "runner-output.log"}
        if candidate is not None:
            candidate = within(candidate, self.project)
            self.summary["diagnostic_run_relative_path"] = str(candidate.relative_to(self.project))
            sources.update({"serial": candidate / "serial.log", "qemu": candidate / "qemu.log"})
        records = []
        for kind, source in sources.items():
            if not source.is_file():
                continue
            source = within(source, self.project, regular=True)
            size = source.stat().st_size
            with source.open("rb") as stream:
                if size > 512 * 1024:
                    data = stream.read(256 * 1024)
                    stream.seek(-256 * 1024, 2)
                    data += b"\n" + stream.read()
                else:
                    data = stream.read()
            filtered = diagnostic_text(data.decode("utf-8", "replace"), self.project)
            target = self.public / ("observer-" + kind + "-diagnostic.log")
            target.write_text("# Filtered startup/error text; raw source remains private.\n" +
                              (filtered or "# No diagnostic lines matched the publication whitelist.\n"))
            records.append({"file": target.name, "raw_bytes": size, "sampled_bytes": len(data),
                            "raw_sha256": digest(source), "sanitized_sha256": digest(target),
                            "kept_lines": len(filtered.splitlines()), "filter_version": 1})
        self.summary["diagnostics"] = records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--tree", type=Path, required=True)
    parser.add_argument("--os-raw-image", type=Path, required=True)
    parser.add_argument("--public-dir", type=Path, required=True,
                        help="new output directory; only whitelist JSON/log and rendered PNG")
    parser.add_argument("--seconds", type=int, default=900)
    parser.add_argument("--every", type=int, default=60)
    parser.add_argument("--sample-timeout", type=int, default=30)
    args = parser.parse_args()
    if not 120 <= args.seconds <= 1200 or not 30 <= args.every <= 120 or not 5 <= args.sample_timeout <= 60:
        parser.error("bounded seconds/every/sample-timeout required")
    observer = Observer(args)
    def interrupt(signum, _):
        raise KeyboardInterrupt(f"signal {signum}")
    signal.signal(signal.SIGTERM, interrupt)
    failed = False
    try:
        observer.preflight()
        # Hashing and source validation do not consume the 900-second boot budget.
        observer.start = time.monotonic()
        observer.deadline = observer.start + args.seconds
        observer.launch()
        observer.observe()
    except BaseException as exc:
        failed = True
        observer.error("observer_failed", exc)
    finally:
        observer.cleanup()
    result = observer.summary["acceptance"]
    # This success only means the runtime/telemetry checks passed; visual review
    # remains mandatory and is deliberately never auto-promoted to a UI pass.
    code = 0 if (not failed and result["original_userland_runtime_criteria"]
                 and result["ui_telemetry_candidate"]
                 and observer.summary.get("runner_exit_code") == 0
                 and observer.summary.get("qemu_reported_exit_code") == 0
                 and observer.summary.get("termination_reason") == "budget_complete"
                 and not any(s.get("panic_text_seen") for s in observer.summary["samples"])) else 2
    observer.summary["observer_exit_code"] = code
    observer.save()
    print(json.dumps({"observer_exit_code": code, "runtime_criteria": result["original_userland_runtime_criteria"],
                      "ui_telemetry_candidate": result["ui_telemetry_candidate"],
                      "ui_visually_normal": None, "manual_review_required": True}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
