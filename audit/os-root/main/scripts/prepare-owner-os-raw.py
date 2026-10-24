#!/usr/bin/env python3
"""Convert the pinned original UDIF into a new project regular raw file."""
import argparse
import json
from pathlib import Path
import subprocess
from project_image_policy import (OS_BYTES, OS_SHA256, conversion_receipt, file_sha256,
                                  original_source, project_path, regular_file)

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
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
    version = subprocess.check_output(['hdiutil', 'version'], text=True).strip()
    if not version:
        raise SystemExit('Cannot record actual hdiutil version')
    subprocess.run(command, check=True)
    regular_file(ROOT, raw, OS_BYTES)
    # Rehash the source after conversion; a valid receipt is never written for partial output.
    if file_sha256(ROOT, source) != OS_SHA256:
        raise SystemExit('Compressed source changed during conversion')
    record = dict(schema=1, source=dict(path=str(source), size=source.stat().st_size, sha256=OS_SHA256),
                  raw=dict(path=str(raw), size=OS_BYTES, sha256=file_sha256(ROOT, raw, OS_BYTES)),
                  conversion=dict(tool='hdiutil', format='UDTO', version=version, command=command),
                  source_format='UDIF', raw_format='raw', complete=True)
    with receipt.open('x') as stream:
        stream.write(json.dumps(record, indent=2) + '\n')
    print(f'Converted and hashed the complete regular image: {raw}')


if __name__ == '__main__':
    main()
