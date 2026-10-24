#!/usr/bin/env python3
"""Stage only known text reports and rendered PNG diagnostics, never VM data."""
import hashlib
import json
import os
from pathlib import Path
import re

ROOT = Path(os.environ['GITHUB_WORKSPACE']).resolve()
DEST = ROOT / 'public-logs'
DEST.mkdir(exist_ok=True)
TEXT = DEST / 'build-text'
TEXT.mkdir(exist_ok=True)
manifest = []

def clean(text):
    # Public jobs still must not accidentally archive key material or memory dumps.
    text = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----',
                  '[private key omitted]', text, flags=re.S)
    for name in ('GITHUB_TOKEN', 'GH_TOKEN', 'UNIXNU_DEVICE_TOKEN'):
        value = os.environ.get(name, '')
        if value:
            text = text.replace(value, '[credential omitted]')
    unsafe = r'(?:memory|machine_code|instructions|private_key|gdb_stops|argument_memory|entry_bytes|read_memory|registers|partial_report|prefix_bytes)'
    metadata = re.compile(r'(?:sha256|hash|digest|commit|blob)', re.I)
    encoded = re.compile(r'(?<![A-Za-z0-9_])[A-Za-z0-9+/]{96,}={0,2}(?![A-Za-z0-9_])')
    hex_bytes = re.compile(r'(?<![A-Za-z0-9_])[0-9a-fA-F]{24,}(?![A-Za-z0-9_])')
    def value_safe(value, key=''):
        if isinstance(value, dict):
            return {k: ('[raw diagnostic omitted]' if re.fullmatch(unsafe, k) else value_safe(v, k))
                    for k, v in value.items()}
        if isinstance(value, list):
            return [value_safe(v, key) for v in value]
        if isinstance(value, str):
            if metadata.search(key) and re.fullmatch(r'[0-9a-fA-F]{40}|[0-9a-fA-F]{64}', value):
                return value
            return encoded.sub('[encoded data omitted]', hex_bytes.sub('[hex data omitted]', value))
        return value
    try:
        return json.dumps(value_safe(json.loads(text)), indent=2) + '\n'
    except json.JSONDecodeError:
        pass
    lines = []
    for line in text.splitlines():
        if re.search(r'^\s*(?:0x)?[0-9a-fA-F]{8,16}:\s+(?:0x)?[0-9a-fA-F]{8,}', line):
            continue
        if re.search(r'[\"\x27]' + unsafe + r'[\"\x27]\s*:', line):
            continue
        def hide_hex(match):
            before = line[max(0, match.start() - 80):match.start()]
            if len(match.group()) in (40, 64) and metadata.search(before):
                return match.group()
            if match.start() == 0 and len(match.group()) == 64 and re.match(r'\s+\S', line[match.end():]):
                return match.group()  # shasum output
            return '[hex data omitted]'
        line = encoded.sub('[encoded data omitted]', hex_bytes.sub(hide_hex, line))
        lines.append(line)
    return '\n'.join(lines) + '\n'

sources = []
runtime = ROOT / 'audit-runtime'
for pattern in ('resources-*.json', 'source-identity.json', 'patch-install-*.json', 'ipsw-input.json',
                'qemu-startup-probe.json', 'host-make-*.json', 'hdiutil-identity.json',
                'native-baseline/*.log', 'native-baseline/*.txt'):
    sources.extend(runtime.glob(pattern))
logs = ROOT / 'out/qemu/logs'
for pattern in ('archive-*.log', 'kernel*.log', 'prelink.log', 'package.log', 'payload-*.log',
                'storage-headers.log', 'native-user-run.log', 'native-user-check.log', 'os-root-prepare.log'):
    sources.extend(logs.glob(pattern))
for relative in ('build/os-root-inputs.json', 'build/os-root-preparation-commands.json',
                 'build/verified-root-os/verification.json', 'build/verified-root-systemos/verification.json'):
    path = ROOT / 'out/qemu/tree' / relative
    if path.is_file():
        sources.append(path)
for label in ('darwinboot-storage-native-metadata', 'darwinboot-owner-hvf-mobile-graphics-legacy-class'):
    directory = ROOT / 'out/qemu/tree/build' / label
    for name in ('gdb-stderr.log', 'gdb-uart.log', 'gdb-startup.json'):
        path = directory / name
        if path.is_file():
            sources.append(path)
    failure = directory / 'gdb-failure.json'
    if failure.is_file():
        original = json.loads(failure.read_text())
        reduced = {key: original.get(key) for key in
                   ('kernel_sha256', 'qemu_accelerator', 'qemu_memory_mib', 'qemu_cpu_model', 'error', 'qemu_exit_code')}
        # Never copy partial_report, memory reads, registers or machine code.
        (runtime / (label + '-failure-summary.json')).write_text(json.dumps(reduced, indent=2) + '\n')
        sources.append(runtime / (label + '-failure-summary.json'))
seen = set()
for path in sources:
    if path in seen or not path.is_file() or path.stat().st_size > 30_000_000:
        continue
    seen.add(path)
    data = path.read_bytes()
    if b'\0' in data:
        continue
    try:
        text = clean(data.decode('utf-8'))
    except UnicodeDecodeError:
        continue
    name = str(path.relative_to(ROOT)).replace('/', '__').replace('\\', '__') + '.log'
    target = TEXT / name
    target.write_text(text, encoding='utf-8')

# The observer owns its explicit report schema. Validate every staged entry,
# reject links or unexpected media, and hash the final public bytes.
allowed_reports = ('os-root-summary.json', 'processes-', 'sanitized-kernel-userland.log',
                   'observation-error.json', 'execution.json', 'sample-', 'input-', 'screenshot-',
                   'observer-runner-diagnostic.log', 'observer-serial-diagnostic.log', 'observer-qemu-diagnostic.log')
for path in sorted(DEST.rglob('*')):
    if path.is_symlink():
        raise RuntimeError('No symlink may be uploaded: ' + str(path))
    if not path.is_file():
        continue
    relative = str(path.relative_to(DEST)).replace('\\', '/')
    data = path.read_bytes()
    if relative.startswith('build-text/'):
        data.decode('utf-8')
    elif relative.startswith('evidence/screenshots/') and path.suffix == '.png':
        if not data.startswith(b'\x89PNG\r\n\x1a\n') or len(data) > 20_000_000:
            raise RuntimeError('Invalid diagnostic PNG: ' + relative)
    elif relative.startswith('evidence/') and path.suffix in ('.json', '.log', '.txt'):
        if not path.name.startswith(allowed_reports):
            raise RuntimeError('Unlisted observer output: ' + relative)
        text = clean(data.decode('utf-8'))
        path.write_text(text, encoding='utf-8')
        data = path.read_bytes()
    else:
        raise RuntimeError('Unlisted public artifact: ' + relative)
    if b'PRIVATE KEY-----' in data or b'"gdb_stops"' in data:
        raise RuntimeError('Private material refused: ' + relative)
    manifest.append({'file': relative, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
(DEST / 'evidence-manifest.json').write_text(json.dumps({
    'run_id': os.environ.get('GITHUB_RUN_ID'), 'source_commit': os.environ.get('GITHUB_SHA'),
    'publication_scope': 'known build text, numerical runtime observations, rendered PNG only',
    'files': manifest,
}, indent=2) + '\n')
print(json.dumps({'staged_files': len(manifest), 'scope': 'text and rendered PNG; no kernel, disks, keys, or RAM'}))
