#!/usr/bin/env python3
"""Convert the pinned original UDIF into a new project regular raw file."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from project_image_policy import (OS_BYTES, OS_SHA256, conversion_receipt, file_sha256,
                                  original_source, project_path, regular_file)

ROOT = Path(__file__).resolve().parents[1]


def hdiutil_identity():
    """Identify the executable and host OS; hdiutil has no version verb."""
    executable = shutil.which('hdiutil')
    if executable is None:
        raise SystemExit('hdiutil executable not found')
    executable = Path(executable).resolve(strict=True)
    with executable.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    macos, errors = {}, {}
    for name, option in (('product_version', '-productVersion'), ('build_version', '-buildVersion')):
        try:
            macos[name] = subprocess.check_output(['sw_vers', option], text=True, stderr=subprocess.PIPE,
                                                 timeout=10).strip() or None
        except (OSError, subprocess.SubprocessError) as error:
            macos[name] = None
            errors[name] = type(error).__name__
    return dict(executable_path=str(executable), executable_sha256=digest,
                macos=macos, optional_os_metadata_errors=errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--check-tools', action='store_true',
                        help='print read-only executable/OS identity JSON; no IPSW/output needed')
    args = parser.parse_args()
    if args.check_tools:
        print(json.dumps(dict(scope='read-only tool identity; no image or device operation',
                              conversion_tool=hdiutil_identity()), indent=2))
        return
    if args.output is None:
        parser.error('--output is required unless --check-tools is used')
    source = original_source(ROOT)
    raw = project_path(ROOT, args.output)
    if raw.suffix != '.cdr':
        parser.error('Use an explicit .cdr output (hdiutil UDTO must not infer another filename)')
    receipt = project_path(ROOT, str(raw) + '.conversion.json')
    if raw.exists() or receipt.exists():
        conversion_receipt(ROOT, raw, source)  # no existence-only cache trust
        print(f'Validated existing complete conversion: {raw}')
        return
    raw.parent.mkdir(parents=True, exist_ok=True)
    command = ['hdiutil', 'convert', str(source), '-format', 'UDTO', '-o', str(raw)]
    identity = hdiutil_identity()
    # Keep the existing receipt's nonempty string contract without presenting
    # an unsupported CLI query or an OS release as the utility's own version.
    macos = identity['macos']
    version = ('macOS system component identity (not an hdiutil version): product=' +
               (macos['product_version'] or 'unavailable') + ', build=' +
               (macos['build_version'] or 'unavailable'))
    subprocess.run(command, check=True)
    regular_file(ROOT, raw, OS_BYTES)
    # Rehash the source after conversion; a valid receipt is never written for partial output.
    if file_sha256(ROOT, source) != OS_SHA256:
        raise SystemExit('Compressed source changed during conversion')
    record = dict(schema=1, source=dict(path=str(source), size=source.stat().st_size, sha256=OS_SHA256),
                  raw=dict(path=str(raw), size=OS_BYTES, sha256=file_sha256(ROOT, raw, OS_BYTES)),
                  conversion=dict(tool='hdiutil', format='UDTO', version=version,
                                  identity=identity, command=command),
                  source_format='UDIF', raw_format='raw', complete=True)
    with receipt.open('x') as stream:
        stream.write(json.dumps(record, indent=2) + '\n')
    print(f'Converted and hashed the complete regular image: {raw}')


if __name__ == '__main__':
    main()
