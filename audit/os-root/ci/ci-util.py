#!/usr/bin/env python3
"""Fixed UniXNU QEMU experiment setup; no physical-device commands."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tomllib
from urllib.parse import urlsplit

ROOT = Path(os.environ['GITHUB_WORKSPACE']).resolve()
AUDIT = ROOT / 'audit/os-root'
PRIVATE = ROOT / 'audit-runtime'
PRIVATE.mkdir(exist_ok=True)
DEVICE_PIN = '97b75b1f63c6b7e895cd7646029db741d5fe5488'

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def save(name, value):
    (PRIVATE / name).write_text(json.dumps(value, indent=2) + '\n')

def owned(path):
    path = path.resolve()
    if not path.is_relative_to(ROOT):
        raise RuntimeError('Path outside this experiment: ' + str(path))
    return path

def install(sync=False):
    if subprocess.check_output(['git', '-C', str(ROOT / 'device'), 'rev-parse', 'HEAD'], text=True).strip() != DEVICE_PIN:
        raise RuntimeError('Device source pin mismatch')
    if not sync:
        expected = {
            'scripts/unixnu/kernel.py': '65e52bcbda82817f504d3318ee49e1bfc3552a2d',
            'scripts/unixnu/config.py': '5e7f20aa885b4a1d3ebeab33c674cac0e3baa365',
            'scripts/build-owner-os-policy.py': 'd062ee1a0a895bcd6eb7bb1cf5c6c3793edd3cc4',
            'scripts/prepare-owner-data-fixture.py': 'a9dda5d4f6390c9e373b893359a8d124c16f49ad',
        }
        actual = {name: subprocess.check_output(['git', 'rev-parse', 'HEAD:' + name], cwd=ROOT, text=True).strip()
                  for name in expected}
        head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        if actual != expected or head != os.environ['GITHUB_SHA']:
            raise RuntimeError('Main build-source baseline or event commit differs')
        save('source-identity.json', {'main_experiment_commit': head, 'main_baseline_blobs': actual, 'device_commit': DEVICE_PIN})
    records = []
    for kind, destination in (('main', ROOT), ('device', ROOT / 'device')):
        for source in sorted((AUDIT / kind / 'scripts').glob('*.py')):
            targets = [destination / 'scripts' / source.name]
            if sync:
                targets.append(ROOT / 'out/qemu/tree/scripts' / source.name)
            for target in targets:
                target = owned(target)
                target.parent.mkdir(parents=True, exist_ok=True)
                old = sha(target) if target.is_file() else None
                shutil.copyfile(source, target)
                assert sha(target) == sha(source)
                records.append({'source': str(source.relative_to(ROOT)), 'target': str(target.relative_to(ROOT)),
                                'before_sha256': old, 'after_sha256': sha(target)})
    save('patch-install-' + ('tree' if sync else 'checkout') + '.json', records)

def resource(label):
    memory = int(subprocess.check_output(['sysctl', '-n', 'hw.memsize'], text=True))
    record = {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'label': label,
              'platform': platform.platform(), 'machine': platform.machine(),
              'memory_bytes': memory, 'disk_free_bytes': shutil.disk_usage(ROOT).free,
              'cpu_count': os.cpu_count(), 'uid': os.getuid()}
    save('resources-' + label + '.json', record)
    print(json.dumps(record), flush=True)
    if memory < 12 * 2**30:
        raise RuntimeError('This experiment requires a host with at least 12 GiB RAM')
    minimum_gib = 10 if label == 'after-os-prepare' else 30
    if record['disk_free_bytes'] < minimum_gib * 2**30:
        raise RuntimeError(f'Less than {minimum_gib} GiB free for the remaining experiment')

def download():
    config = tomllib.loads((ROOT / 'device/board.toml').read_text())['ipsw']
    url = config['url']
    host = urlsplit(url)
    if host.scheme != 'https' or host.hostname != 'updates.cdn-apple.com':
        raise RuntimeError('Expected the fixed official Apple IPSW origin')
    if (config['product'], config['version'], config['build']) != ('iPad7,1', '17.7.11', '21H461'):
        raise RuntimeError('Unexpected OS identity')
    directory = owned(ROOT / 'out/audit-ipsw')
    directory.mkdir(exist_ok=True)
    target = directory / 'iPad_Pro_HFR_17.7.11_21H461_Restore.ipsw'
    partial = target.with_suffix('.ipsw.partial')
    if target.exists():
        raise RuntimeError('Fresh job required: complete IPSW already exists')
    argv = ['curl', '--fail', '--location', '--retry', '4', '--connect-timeout', '30',
            '--max-time', '2400', '--continue-at', '-', '--output', str(partial), url]
    subprocess.run(argv, check=True)
    partial.rename(target)
    record = {'source': url, 'path': str(target), 'bytes': target.stat().st_size, 'sha256': sha(target),
              'identity': {key: config[key] for key in ('product', 'version', 'build', 'device_class')},
              'note': 'Source container digest recorded; pinned members are independently verified by the build scripts'}
    save('ipsw-input.json', record)
    print(json.dumps(record), flush=True)
    with Path(os.environ['GITHUB_ENV']).open('a') as stream:
        stream.write('UNIXNU_IPSW=' + str(target) + '\n')

parser = argparse.ArgumentParser()
parser.add_argument('stage', choices=('install', 'sync', 'resource', 'download'))
parser.add_argument('--label', default='initial')
args = parser.parse_args()
if args.stage in ('install', 'sync'):
    install(args.stage == 'sync')
elif args.stage == 'resource':
    resource(args.label)
else:
    download()
