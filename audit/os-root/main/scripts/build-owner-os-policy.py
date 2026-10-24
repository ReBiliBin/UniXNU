#!/usr/bin/env python3
"""Sign and verify every original OS block from an explicit project raw file."""
import argparse
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import uuid
from project_image_policy import (OS_BYTES, OS_SHA256, OS_UUID, conversion_receipt, original_source,
                                  readonly_os_mount, regular_file, regular_stream)

ROOT = Path(__file__).resolve().parents[1]


class View(ctypes.Structure):
    _fields_ = [('hashes', ctypes.c_void_p), ('image_bytes', ctypes.c_uint64), ('block_count', ctypes.c_uint64),
                ('generation', ctypes.c_uint64), ('volume_uuid', ctypes.c_uint8 * 16), ('image_sha256', ctypes.c_uint8 * 32)]


def verify_all(native, view, stream):
    """Consume every authenticated byte, including the exact final block length."""
    complete = hashlib.sha256()
    indices = sorted({0, 1, view.block_count // 2, view.block_count - 1})
    samples, lengths = [], []
    for index in range(view.block_count):
        expected = min(4096, view.image_bytes - index * 4096)
        block = stream.read(expected)
        if len(block) != expected or native.vr_host_block(ctypes.byref(view), index, block, len(block)) != 0:
            raise ValueError('Actual C block verification failed at ' + str(index))
        complete.update(block)
        if index in indices:
            samples.append(block.ljust(4096, b'\0'))
            lengths.append(len(block))
    if stream.read(1) or complete.digest() != bytes(view.image_sha256):
        raise ValueError('Complete original image differs from authenticated bounds/digest')
    return complete.hexdigest(), indices, samples, lengths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw-image', type=Path, required=True,
                        help='ordinary raw .cdr produced by prepare-owner-os-raw.py in this project')
    args = parser.parse_args()
    out = ROOT / 'build/verified-root-os'
    # A failed new attempt must not leave a previous success report available to consumers.
    (out / 'verification.json').unlink(missing_ok=True)
    disk = regular_file(ROOT, args.raw_image, OS_BYTES)
    source = original_source(ROOT)
    conversion = conversion_receipt(ROOT, disk, source)
    readonly_os_mount(ROOT, source)
    expected_uuid = uuid.UUID(OS_UUID)
    spec = importlib.util.spec_from_file_location('verified_manifest', ROOT / 'kits/VerifiedRoot/tools/manifest.py')
    manifest = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(manifest)
    keys = ROOT / 'build/verified-root-host/keys'
    with regular_stream(ROOT, disk, OS_BYTES) as stream:
        record = manifest.make(stream, OS_BYTES, keys / 'owner.pem', keys / 'owner-public.pem', expected_uuid, 1, out)
    native = ctypes.CDLL(str(ROOT / 'build/verified-root-host/verified-root.dylib'))
    native.vr_host_open.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_uint64, ctypes.POINTER(View)]
    native.vr_host_open.restype = ctypes.c_int
    native.vr_host_block.argtypes = [ctypes.POINTER(View), ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t]
    native.vr_host_block.restype = ctypes.c_int
    encoded = ctypes.create_string_buffer((out / 'manifest.bin').read_bytes())
    anchor_bytes = (out / 'trusted-key.bin').read_bytes()
    if len(anchor_bytes) != 395 or hashlib.sha256(anchor_bytes).hexdigest() != record['trusted_key_sha256']:
        raise SystemExit('Require the complete unchanged explicit trusted public anchor')
    anchor = ctypes.create_string_buffer(anchor_bytes)
    view = View()
    if (native.vr_host_open(encoded, len(encoded) - 1, anchor, 1, ctypes.byref(view)) or
            bytes(view.volume_uuid) != expected_uuid.bytes or view.generation != 1 or
            view.image_bytes != OS_BYTES or view.block_count != (OS_BYTES + 4095) // 4096):
        raise SystemExit('Real C signature/volume/length/generation authentication failed')
    with regular_stream(ROOT, disk, OS_BYTES) as stream:
        digest, indices, samples, lengths = verify_all(native, view, stream)
    if digest != record['image_sha256'] or digest != conversion['raw']['sha256']:
        raise SystemExit('Actual complete original OS digest differs from signed conversion')
    (out / 'original-samples.bin').write_bytes(b''.join(samples))
    report = dict(image_bytes=view.image_bytes, blocks_verified=view.block_count, image_sha256=digest,
                  volume_uuid=OS_UUID, generation=view.generation,
                  source_compressed_sha256=OS_SHA256, source_format='UDIF',
                  host_bus_protocol='Disk Image', host_media_writable=False,
                  trusted_key_sha256=record['trusted_key_sha256'], actual_sample_indices=indices,
                  actual_sample_lengths=lengths, real_c_signature_and_block_verification=True,
                  original_image_modified=False, host_only=True, boot_root_authenticated=False,
                  qemu_tested=False, hardware_tested=False,
                  audit_raw_image=dict(path=str(disk), size=OS_BYTES, sha256=digest,
                                       source_udif_sha256=OS_SHA256, source_udif_path=str(source)),
                  conversion=conversion['conversion'])
    temporary = out / 'verification.json.tmp'
    temporary.write_text(json.dumps(report, indent=2) + '\n')
    temporary.replace(out / 'verification.json')
    print('PASS: original OS signature and every', view.block_count, 'block verified by real C/RSA; file-only input')


if __name__ == '__main__':
    main()
