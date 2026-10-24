#!/usr/bin/env python3
"""File-only OS input checks; no function opens a host block/character device."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import plistlib
import stat
import subprocess

OS_BYTES = 6077580800
OS_SHA256 = '3f99b859c9728379110b66657c7b15285bcb1925ad8b5726542e2cdcf8b1028d'
OS_UUID = '04769D26-2CA0-4825-B443-E2E5F88300F2'


def project_path(root, value):
    root = Path(root).resolve(strict=True)
    boundary = Path(os.environ.get('UNIXNU_AUDIT_PROJECT_ROOT', root)).resolve(strict=True)
    if not root.is_relative_to(boundary):
        raise ValueError('Script tree must remain inside the explicit audit project root')
    path = Path(value)
    # Reject device spelling before resolving links, including Windows namespaces.
    spelling = str(path).replace('\\', '/')
    if spelling == '/dev' or spelling.startswith(('/dev/', '//./', '//?/')):
        raise ValueError('Device paths are forbidden')
    resolved = path.resolve()
    if not resolved.is_relative_to(boundary) or resolved == boundary:
        raise ValueError('Image/output must remain inside the project tree')
    return resolved


def regular_file(root, value, size=None):
    path = project_path(root, value)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('Require a project regular file')
    if size is not None and info.st_size != size:
        raise ValueError(f'Wrong image length: {info.st_size}, expected {size}')
    return path


@contextmanager
def regular_stream(root, value, size=None):
    path = regular_file(root, value, size)
    before = path.stat()
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb', buffering=1024 * 1024) as stream:
        current = os.fstat(stream.fileno())
        if (not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino, current.st_size) !=
                (before.st_dev, before.st_ino, before.st_size)):
            raise ValueError('Image identity changed while opening')
        yield stream
        after = os.fstat(stream.fileno())
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns):
            raise ValueError('Input changed while being read')


def file_sha256(root, value, size=None):
    digest = hashlib.sha256()
    with regular_stream(root, value, size) as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def original_source(root):
    source = regular_file(root, Path(root) / '.cache/firmware/target-volumes/044-76040-038.dmg')
    if file_sha256(root, source) != OS_SHA256:
        raise ValueError('Require the exact original iPad7,1 compressed OS member')
    with regular_stream(root, source) as stream:
        stream.seek(-512, 2)
        if stream.read(4) != b'koly':
            raise ValueError('Require the actual original UDIF trailer')
    return source


def conversion_receipt(root, raw, source):
    raw = regular_file(root, raw, OS_BYTES)
    source = regular_file(root, source)
    receipt_path = regular_file(root, str(raw) + '.conversion.json')
    record = json.loads(receipt_path.read_text())
    source_hash, raw_hash = file_sha256(root, source), file_sha256(root, raw, OS_BYTES)
    if (record.get('schema') != 1 or record.get('complete') is not True or
            record.get('source_format') != 'UDIF' or record.get('raw_format') != 'raw' or
            record.get('source') != dict(path=str(source), size=source.stat().st_size, sha256=OS_SHA256) or
            source_hash != OS_SHA256 or
            record.get('raw') != dict(path=str(raw), size=OS_BYTES, sha256=raw_hash) or
            record.get('conversion', {}).get('tool') != 'hdiutil' or
            record.get('conversion', {}).get('format') != 'UDTO' or
            not record.get('conversion', {}).get('version') or
            record.get('conversion', {}).get('command') !=
            ['hdiutil', 'convert', str(source), '-format', 'UDTO', '-o', str(raw)]):
        raise ValueError('Conversion provenance does not match actual complete source/raw files')
    return record


def readonly_os_mount(root, source):
    volume = project_path(root, Path(root) / '.cache/firmware/target-volumes/os-mount')
    images = plistlib.loads(subprocess.check_output(['hdiutil', 'info', '-plist']))['images']
    found = [i for i in images if Path(i['image-path']).resolve() == source and i.get('writeable') is False]
    if len(found) != 1:
        raise ValueError('Require one exact read-only original image attachment')
    entities = found[0]['system-entities']
    whole = [e['dev-entry'] for e in entities if e.get('content-hint') == 'GUID_partition_scheme']
    mounted = [e for e in entities if e.get('mount-point') == str(volume)]
    if len(whole) != 1 or len(mounted) != 1:
        raise ValueError('Require the exact original virtual-media mapping and mountpoint')
    info = plistlib.loads(subprocess.check_output(['diskutil', 'info', '-plist', whole[0]]))
    volume_info = plistlib.loads(subprocess.check_output(['diskutil', 'info', '-plist', str(volume)]))
    if (info.get('BusProtocol') != 'Disk Image' or info.get('Writable') is not False or
            info.get('DeviceNode') != whole[0] or info.get('TotalSize') != OS_BYTES or
            volume_info.get('VolumeUUID') != OS_UUID or volume_info.get('Writable') is not False or
            volume_info.get('DeviceNode') != mounted[0]['dev-entry'] or
            volume_info.get('MountPoint') != str(volume)):
        raise ValueError('Only the exact original read-only OS volume is accepted')
    return volume


def owned_attachment(root, image, attached, target):
    """Bind detach/write targets to the just-created project image, using metadata."""
    image = regular_file(root, image)
    target = project_path(root, target)
    images = plistlib.loads(subprocess.check_output(['hdiutil', 'info', '-plist']))['images']
    found = [i for i in images if Path(i['image-path']).resolve() == image]
    if len(found) != 1 or found[0].get('writeable') is not True:
        raise ValueError('Require exactly the project-created writable image attachment')
    entities = attached.get('system-entities', [])
    recorded = found[0].get('system-entities', [])
    ids = [e.get('dev-entry') for e in entities]
    if not ids or any(not value for value in ids) or set(ids) != {e.get('dev-entry') for e in recorded}:
        raise ValueError('Attachment metadata changed')
    volumes = [e for e in entities if e.get('mount-point') == str(target)]
    if len(volumes) != 1:
        raise ValueError('Require exactly the project mountpoint')
    # The first entity is the attachment's whole-media detach target, not an enumerated host disk.
    device = ids[0]
    info = plistlib.loads(subprocess.check_output(['diskutil', 'info', '-plist', device]))
    volume_info = plistlib.loads(subprocess.check_output(['diskutil', 'info', '-plist', volumes[0]['dev-entry']]))
    if (info.get('DeviceNode') != device or info.get('BusProtocol') != 'Disk Image' or
            info.get('Writable') is not True or volume_info.get('Writable') is not True or
            volume_info.get('DeviceNode') != volumes[0]['dev-entry'] or
            volume_info.get('MountPoint') != str(target)):
        raise ValueError('Scratch volume is not bound to the exact writable project image')
    return device, volume_info
