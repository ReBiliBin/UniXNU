#!/usr/bin/env python3
"""Compare EFI variable-file setup at the failed ABI probe's 8 GiB size.

CPU execution stays paused (-S). A listening GDB server is only a host/QEMU
startup check, never a kernel, OS, graphics or hardware success.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time

ROOT = Path(os.environ['GITHUB_WORKSPACE']).resolve()
OUT = ROOT / 'audit-runtime/qemu-startup-probe'
OUT.mkdir(parents=True, exist_ok=False)
QEMU = Path(shutil.which('qemu-system-aarch64')).resolve()
CODE = QEMU.parents[1] / 'share/qemu/edk2-aarch64-code.fd'
ORIGINAL_VARS = CODE.with_name('edk2-arm-vars.fd')

def identity(path):
    if not path.is_file():
        return {'exists': False}
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'exists': True, 'bytes': path.stat().st_size, 'sha256': digest, 'path': str(path)}

reports = []
for mode in ('upstream-vars', 'fresh-code-sized-vars'):
    directory = OUT / mode
    directory.mkdir()
    esp = directory / 'esp'
    esp.mkdir()
    variables = directory / 'vars.fd'
    if mode == 'upstream-vars':
        if ORIGINAL_VARS.is_file():
            shutil.copyfile(ORIGINAL_VARS, variables)
    else:
        with variables.open('wb') as stream:
            stream.truncate(CODE.stat().st_size)
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    argv = [str(QEMU), '-M', 'virt,virtualization=off,secure=off,gic-version=3',
            '-accel', 'tcg', '-cpu', 'cortex-a710', '-m', '8192', '-smp', '1',
            '-display', 'none', '-monitor', 'none', '-nic', 'none', '-no-reboot',
            '-serial', 'none', '-gdb', 'tcp:127.0.0.1:' + str(port), '-S',
            '-device', 'ramfb', '-drive', 'if=pflash,format=raw,readonly=on,file=' + str(CODE)]
    if variables.is_file():
        argv += ['-drive', 'if=pflash,format=raw,file=' + str(variables)]
    argv += ['-drive', 'if=none,id=esp,format=raw,readonly=on,file=fat:' + str(esp),
             '-device', 'virtio-blk-pci,drive=esp']
    record = {'mode': mode, 'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'argv': argv, 'code': identity(CODE), 'vars': identity(variables),
              'upstream_vars': identity(ORIGINAL_VARS), 'gdb_connected': False,
              'guest_cpu_executed': False}
    start = time.monotonic()
    with (directory / 'stderr.log').open('wb') as errors:
        process = subprocess.Popen(argv, cwd=ROOT, stdout=errors, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            while time.monotonic() - start < 30 and process.poll() is None:
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                        record['gdb_connected'] = True
                        record['elapsed_seconds'] = time.monotonic() - start
                    break
                except OSError:
                    time.sleep(0.05)
            record['pre_cleanup_exit_code'] = process.poll()
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
    record.update(final_exit_code=process.returncode, total_seconds=time.monotonic() - start,
                  stderr=(directory / 'stderr.log').read_text(errors='replace')[:8000])
    reports.append(record)
    print(json.dumps(record), flush=True)
report = {'scope': 'paused host/QEMU GDB startup only; no kernel/OS executed',
          'qemu_version': subprocess.check_output([QEMU, '--version'], text=True), 'probes': reports}
(ROOT / 'audit-runtime/qemu-startup-probe.json').write_text(json.dumps(report, indent=2) + '\n')
if not reports[-1]['gdb_connected']:
    raise SystemExit('Fresh-variable 8 GiB QEMU startup failed; see the diagnostic report')
