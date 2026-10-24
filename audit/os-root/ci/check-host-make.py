#!/usr/bin/env python3
"""Require grouped-target GNU Make for the fixed EDK II host-tool build."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--require-active', action='store_true')
args = parser.parse_args()
root = Path(os.environ['GITHUB_WORKSPACE']).resolve()
prefix = Path(subprocess.check_output(['brew', '--prefix', 'make'], text=True).strip()).resolve()
selected = prefix / 'bin/gmake'
version = subprocess.check_output([selected, '--version'], text=True).splitlines()[0]
match = re.match(r'GNU Make (\d+)\.(\d+)', version)
if not match or tuple(map(int, match.groups())) < (4, 3):
    raise SystemExit('EDK II grouped targets require GNU Make >= 4.3')
active = Path(shutil.which('make')).resolve()
if args.require_active and active != selected.resolve():
    raise SystemExit('The package step did not select the verified GNU Make')
label = 'active' if args.require_active else 'installed'
directory = root / 'audit-runtime' / ('make-grouped-probe-' + label)
directory.mkdir(parents=True, exist_ok=False)
(directory / 'input').write_text('own fixture only\n')
(directory / 'recipe.py').write_text(
    "from pathlib import Path\n"
    "with Path('calls.txt').open('a') as out: out.write('once\\n')\n"
    "for name in ('a','b','c'): Path(name).write_text('complete\\n')\n")
(directory / 'Makefile').write_text(
    'all: a b c\n'
    'a b c &: input\n'
    '\t"' + sys.executable + '" recipe.py\n')
completed = subprocess.run([str(selected), '-j4', 'all'], cwd=directory,
                           capture_output=True, text=True, timeout=20, check=True)
if (directory / 'calls.txt').read_text().splitlines() != ['once']:
    raise SystemExit('Grouped output recipe executed more than once')
if any((directory / name).read_text() != 'complete\n' for name in ('a', 'b', 'c')):
    raise SystemExit('Grouped output probe was incomplete')
record = {'selected_make': str(selected.resolve()), 'selected_version': version,
          'active_make': str(active),
          'active_version': subprocess.check_output([active, '--version'], text=True).splitlines()[0],
          'active_required': args.require_active, 'grouped_recipe_invocations': 1,
          'parallel_jobs': 4, 'scope': 'synthetic grouped-output build only; no OS code',
          'makefile_sha256': hashlib.sha256((directory / 'Makefile').read_bytes()).hexdigest()}
(root / 'audit-runtime' / ('host-make-' + label + '.json')).write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record), flush=True)
