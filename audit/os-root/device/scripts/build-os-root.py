#!/usr/bin/env python3
"""Prepare fresh original-userland inputs using ordinary project raw files.

Adapted from xVanTuring/UniXNU-qemu@97b75b1f63c6b7e895cd7646029db741d5fe5488.
Run after the same job's package/kernel/payload baseline. This builds inputs;
it makes no claim about original-userland or UI runtime success.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
PROJECT = Path(os.environ.get('UNIXNU_AUDIT_PROJECT_ROOT', ROOT)).resolve()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--ipsw', type=Path, default=os.environ.get('UNIXNU_IPSW'))
parser.add_argument('--openssl-prefix', type=Path, required=True)
parser.add_argument('--os-raw-image', type=Path)
args = parser.parse_args()
volumes = (ROOT / '.cache/firmware/target-volumes').resolve()
data = (ROOT / '.cache/firmware/owner-data').resolve()
if not volumes.is_relative_to(PROJECT) or not data.is_relative_to(PROJECT):
    raise SystemExit('Firmware cache directories must remain inside the project')
commands_path = ROOT / 'build/os-root-preparation-commands.json'
commands = []


def ordinary(path, exists=True):
    path = Path(path)
    canonical = path.resolve(strict=exists)
    if path.is_symlink() or not canonical.is_relative_to(PROJECT):
        raise SystemExit(f'Expected a project regular file: {path}')
    if exists and not stat.S_ISREG(canonical.stat().st_mode):
        raise SystemExit(f'Expected a project regular file: {path}')
    if any(c in str(canonical) for c in ('\n', '\r', ',')):
        raise SystemExit('Unsafe image filename')
    return canonical


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(8 << 20), b''):
            value.update(chunk)
    return value.hexdigest()


def host(*command, capture=False):
    argv = [str(part) for part in command]
    print('==', ' '.join(argv), flush=True)
    item = dict(argv=argv, started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
    commands.append(item)
    start = time.monotonic()
    try:
        completed = subprocess.run(argv, cwd=ROOT, check=True, stdout=subprocess.PIPE if capture else None)
        item['exit_code'] = completed.returncode
        return completed.stdout if capture else None
    except subprocess.CalledProcessError as error:
        item['exit_code'] = error.returncode
        raise
    finally:
        item['elapsed_seconds'] = round(time.monotonic() - start, 3)
        commands_path.parent.mkdir(parents=True, exist_ok=True)
        commands_path.write_text(json.dumps(commands, indent=2) + '\n')


def step(script, *arguments):
    return host(sys.executable, ROOT / script, *arguments)


def attachment(image, read_only):
    # This is an identity check for a specifically named project-created image,
    # not selection of an arbitrary disk found by diskutil.
    image = ordinary(image)
    listing = plistlib.loads(host('hdiutil', 'info', '-plist', capture=True))
    matches = [entry for entry in listing.get('images', [])
               if Path(entry.get('image-path', '')).resolve() == image
               and entry.get('writeable') is (not read_only)]
    if len(matches) != 1:
        raise SystemExit(f'Expected exactly one matching image attachment: {image}')
    entities = matches[0]['system-entities']
    devices = [entry['dev-entry'] for entry in entities if re.fullmatch(r'/dev/disk\d+(s\d+)*', entry.get('dev-entry', ''))]
    if not devices:
        raise SystemExit('No disk-image entities in the matching project attachment')
    for device in devices:
        info = plistlib.loads(host('diskutil', 'info', '-plist', device, capture=True))
        if (info.get('BusProtocol') != 'Disk Image' or info.get('DeviceNode') != device or
                info.get('Writable') is not (not read_only)):
            raise SystemExit('Attachment entity is not the expected disk image / access mode')
    return entities, devices


def attach(image, *options, read_only=False):
    image = ordinary(image)
    listing = plistlib.loads(host('hdiutil', 'info', '-plist', capture=True))
    if any(Path(entry.get('image-path', '')).resolve() == image for entry in listing.get('images', [])):
        raise SystemExit('Refuse to reuse an already attached image')
    host('hdiutil', 'attach', *options, '-plist', image, capture=True)
    return attachment(image, read_only)


def attachment_whole(devices):
    # hdiutil lists the backing image's whole device before any synthesized
    # APFS container. Detach that exact whole attachment, never a partition.
    whole = next((device for device in devices if re.fullmatch(r'/dev/disk\d+', device)), None)
    if whole is None:
        raise SystemExit('No whole-device detach target in the verified image attachment')
    return whole


def data_mapping(image):
    _, devices = attachment(image, False)
    detach = attachment_whole(devices)
    listing = plistlib.loads(host('diskutil', 'apfs', 'list', '-plist', capture=True))
    candidates = []
    for entry in listing.get('Containers', []):
        stores = entry.get('PhysicalStores', [])
        if len(stores) != 1:
            continue
        identifier = stores[0].get('DeviceIdentifier', '')
        if re.fullmatch(r'disk\d+(s\d+)*', identifier) and '/dev/' + identifier in devices:
            candidates.append((entry, '/dev/' + identifier))
    if len(candidates) != 1:
        raise SystemExit('Expected a unique APFS container with one physical store from this exact project image')
    entry, store = candidates[0]
    container = entry.get('ContainerReference', '')
    if not re.fullmatch(r'disk\d+', container):
        raise SystemExit('Unexpected synthesized Data container identifier')
    info = plistlib.loads(host('diskutil', 'info', '-plist', store, capture=True))
    if (info.get('BusProtocol') != 'Disk Image' or info.get('DeviceNode') != store or
            info.get('Writable') is not True or
            (store != detach and info.get('ParentWholeDisk') != Path(detach).name)):
        raise SystemExit('The physical store does not belong to the exact backing image whole attachment')
    return dict(container=container, store=store, detach=detach)


if not args.ipsw:
    parser.error('--ipsw is required')
ipsw_input = ordinary(args.ipsw)
args.openssl_prefix = args.openssl_prefix.resolve(strict=True)
if not (args.openssl_prefix / 'include/openssl/evp.h').is_file():
    raise SystemExit('Missing explicit host OpenSSL development headers')
os.environ['UNIXNU_QEMU_ACCEL'] = 'tcg'

# The original existence-only cache may combine different keys, kernel ABIs and
# Data seeds. This experiment intentionally requires fresh owner outputs.
fresh = [ROOT / relative for relative in (
    'build/verified-root-host', 'build/verified-root-os', 'build/verified-root-systemos',
    'build/verified-root-os-xnu-bundle', 'build/native-virtio-block-verified-bundle',
    'build/native-ram-block', 'build/native-legacy-display', 'build/original-static-system-trust',
    '.cache/firmware/owner-data', 'build/os-root-inputs.json')]
if any(path.exists() for path in fresh):
    raise SystemExit('Owner preparation needs a fresh CI job; existing owner/seed outputs are not trusted caches')
volumes.mkdir(parents=True, exist_ok=True)
if not (ROOT / 'build/storage-abi/interface-audit.json').is_file():
    step('scripts/build-storage-abi.py')
inputs = {}
for component, member, expected in (
    ('OS', '044-76040-038.dmg', '3f99b859c9728379110b66657c7b15285bcb1925ad8b5726542e2cdcf8b1028d'),
    ('Cryptex1,SystemOS', '044-76034-038.dmg', 'b4908cde41d23e6bc05e6af51a2c9eeb00cf0f863a6a18b1600c96a3fd70414f')):
    image = volumes / member
    if not image.exists():
        step('scripts/extract-target-volume.py', component, '--ipsw', ipsw_input)
    image = ordinary(image)
    actual = digest(image)
    if actual != expected:
        raise SystemExit(f'Unexpected fixed IPSW member digest: {member}')
    inputs[component] = dict(path=str(image), size=image.stat().st_size, sha256=actual)

raw = ordinary(args.os_raw_image or volumes / 'os-virtual-media.cdr', exists=False)
step('scripts/prepare-owner-os-raw.py', '--output', raw)
raw = ordinary(raw)
if raw.stat().st_size != 6077580800:
    raise SystemExit('Decoded OS does not have the fixed virtual-media byte length')
raw_digest = digest(raw)
step('kits/VerifiedRoot/tests/check.py', '--output', ROOT / 'build/verified-root-host',
     '--openssl-prefix', args.openssl_prefix)
mount = volumes / 'os-mount'
mount.mkdir(exist_ok=True)
entities, devices = attach(volumes / '044-76040-038.dmg', '-readonly', '-nobrowse', '-noverify',
                           '-noautofsck', '-mountpoint', mount, read_only=True)
whole = [entry['dev-entry'] for entry in entities if entry.get('content-hint') == 'GUID_partition_scheme']
if len(whole) != 1:
    raise SystemExit('Expected a unique whole virtual OS disk image')
try:
    step('scripts/build-owner-os-policy.py', '--raw-image', raw)
    launchd_sha = digest(ordinary(mount / 'sbin/launchd'))
    if launchd_sha != '8cec9a3c44a443b08e977ccc5d577850316ad428c575dc01f09b018dbd5b6a25':
        raise SystemExit('Unexpected original launchd input in the verified read-only OS mount')
    step('scripts/prepare-owner-data-fixture.py', '--output', data)
finally:
    host('hdiutil', 'detach', whole[0])
step('scripts/build-owner-systemos-policy.py')
os_report = json.loads((ROOT / 'build/verified-root-os/verification.json').read_text())
system_report = json.loads((ROOT / 'build/verified-root-systemos/verification.json').read_text())
if (os_report.get('image_sha256') != raw_digest or os_report.get('image_bytes') != 6077580800 or
        os_report.get('blocks_verified') != 1483785 or
        os_report.get('real_c_signature_and_block_verification') is not True or
        system_report.get('blocks_verified') != 806400 or
        system_report.get('real_c_signature_and_block_verification') is not True or
        not os_report.get('trusted_key_sha256') or
        os_report['trusted_key_sha256'] != system_report.get('trusted_key_sha256')):
    raise SystemExit('OS/SystemOS complete policy verification or common owner anchor failed')
(ROOT / 'build/xnu/ios-obj/EXPORT_HDRS/libsa').mkdir(parents=True, exist_ok=True)
step('scripts/build-verified-root-probe.py', '--component', 'os', '--include-systemos')
step('scripts/build-arm-driver.py', 'NativeVirtioBlock', '--verified-root', '--verified-root-bundle')
step('scripts/build-native-virtio-bindings.py', '--component', 'NativeVirtioBlock',
     '--directory', ROOT / 'build/native-virtio-block-verified-bundle')
step('scripts/build-arm-driver.py', 'NativeRamBlock')
step('scripts/build-native-virtio-bindings.py', '--component', 'NativeRamBlock',
     '--directory', ROOT / 'build/native-ram-block')

# Grow only a newly created ordinary project file. Its APFS container must be
# discovered through that exact image's hdiutil attachment and PhysicalStores.
seed = data / 'owner-data-1g.dbr'
grown_raw = ordinary(data / 'owner-data-1g.raw', exists=False)
if grown_raw.exists():
    raise SystemExit('Refuse to overwrite a Data image')
with grown_raw.open('xb') as handle:
    handle.truncate(1 << 30)
    handle.write(ordinary(data / 'owner-data-32.cdr').read_bytes())
entities, devices = attach(grown_raw, '-imagekey', 'diskimage-class=CRawDiskImage', '-nomount', '-nobrowse')
detach_target = attachment_whole(devices)
try:
    mapping = data_mapping(grown_raw)
    # Re-read exact image identity AND PhysicalStores immediately before resize.
    if mapping != data_mapping(grown_raw) or mapping['detach'] != detach_target:
        raise SystemExit('Data attachment/container mapping changed before resize')
    host('diskutil', 'apfs', 'resizeContainer', mapping['container'], '0')
finally:
    host('hdiutil', 'detach', detach_target)
with grown_raw.open('rb') as handle:
    header = handle.read(4096)
blocks = int.from_bytes(header[40:48], 'little')
if (header[32:36] != b'NXSB' or int.from_bytes(header[36:40], 'little') != 4096 or
        not (1 << 30) - (64 << 20) <= blocks * 4096 <= 1 << 30):
    raise SystemExit('The grown project Data file is not a 1 GiB APFS container')
data_mount = data / 'mount'
data_mount.mkdir(exist_ok=True)
entities, devices = attach(grown_raw, '-imagekey', 'diskimage-class=CRawDiskImage',
                           '-nobrowse', '-owners', 'on', '-mountpoint', data_mount)
try:
    mounted = [entry for entry in entities if entry.get('mount-point') == str(data_mount)]
    if len(mounted) != 1 or mounted[0]['dev-entry'] not in devices:
        raise SystemExit('Expected exact mounted project Data volume')
    # GitHub's macOS runner UID is not assumed to be mobile's 501. Set ownership
    # only inside this verified new writable image, preserving OS input files.
    preferences = data_mount / 'mobile/Library/Preferences/com.apple.springboard.plist'
    if preferences.is_symlink() or not preferences.resolve().is_relative_to(data_mount.resolve()):
        raise SystemExit('Data preferences must remain inside the verified mounted project image')
    preferences.parent.mkdir(parents=True, exist_ok=True)
    values = plistlib.loads(preferences.read_bytes()) if preferences.exists() else {}
    values.update(SBDisableAutoDim=True, SBDontDimOrLockOnAC=True, SBDisableIdleSleep=True)
    # A temporary project file avoids writing as runner UID into mobile's path.
    preferences_input = data / 'springboard-preferences.plist'
    preferences_input.write_bytes(plistlib.dumps(values, fmt=plistlib.FMT_BINARY))
    host('sudo', '-n', 'chown', '-R', '-h', '-P', '501:501', data_mount)
    host('sudo', '-n', 'cp', preferences_input, preferences)
    host('sudo', '-n', 'chown', '501:501', preferences)
    host('sudo', '-n', 'chmod', '600', preferences)
    if host('sudo', '-n', 'stat', '-f', '%u', preferences, capture=True).strip() != b'501':
        raise SystemExit('New Data preferences are not owned by mobile 501')
    seed_uuid = json.loads((data / 'seed.json').read_text())['volume_uuid']
    info = plistlib.loads(host('diskutil', 'info', '-plist', mounted[0]['dev-entry'], capture=True))
    if info.get('VolumeUUID', '').upper() != seed_uuid.upper():
        raise SystemExit('Data volume UUID changed during resize')
finally:
    host('hdiutil', 'detach', attachment_whole(devices))
step('drivers/DarwinBoot/Test/packed_ramdisk.py', grown_raw, seed)
# Preserve the ordinary raw Data image privately in this job for diagnostics;
# the workflow uploads neither image nor DBRDISK1 bytes.
if not (ROOT / 'build/darwinboot-owner-hvf-mobile-graphics-legacy-class/gdb-stop.json').is_file():
    step('scripts/build-display-abi.py')
step('scripts/build-native-legacy-display.py')

static = volumes / 'static-trustcache.bin'
blob = ordinary(ROOT.parent.parent / 'ipsw/21H461/044-76040-038.dmg.trustcache').read_bytes()


def der(buffer, at):
    tag, size = buffer[at], buffer[at + 1]
    at += 2
    if size & 0x80:
        length = size & 0x7f
        size, at = int.from_bytes(buffer[at:at + length], 'big'), at + length
    return tag, buffer[at:at + size], at + size


_, sequence, _ = der(blob, 0)
fields, cursor = [], 0
while cursor < len(sequence):
    _, value, cursor = der(sequence, cursor)
    fields.append(value)
module = fields[3]
if fields[:2] != [b'IM4P', b'trst'] or hashlib.sha256(module).hexdigest() != 'da88460e6e513438d5307e5c526f76497a74754476a24da29f239f0c90120fc2':
    raise SystemExit('Unexpected original static trust-cache IM4P')
static.write_bytes(module)
refer_ipsw = ROOT / 'refer/iPad_Pro_HFR_17.7.11_21H461_Restore.ipsw'
refer_ipsw.parent.mkdir(exist_ok=True)
if refer_ipsw.exists() or refer_ipsw.is_symlink():
    if refer_ipsw.resolve() != ipsw_input:
        raise SystemExit('Existing IPSW reference points at a different input')
else:
    refer_ipsw.symlink_to(ipsw_input)
step('scripts/build-original-system-trust.py')
trust = ROOT / 'build/original-static-system-trust/original-static-system.bundle'
report = dict(schema=1, ready=True,
              scope='original-userland inputs prepared; runtime/UI untested',
              device_commit='97b75b1f63c6b7e895cd7646029db741d5fe5488',
              ipsw=dict(path=str(ipsw_input), size=ipsw_input.stat().st_size, sha256=digest(ipsw_input)),
              source_members=inputs, os_raw_image=dict(path=str(raw), size=raw.stat().st_size, sha256=raw_digest),
              original_launchd_sha256=launchd_sha, original_launchd_hash_verified=True,
              os_policy_sha256=digest(ROOT / 'build/verified-root-os/verification.json'),
              systemos_policy_sha256=digest(ROOT / 'build/verified-root-systemos/verification.json'),
              trusted_key_sha256=os_report['trusted_key_sha256'],
              data_volume_uuid=seed_uuid, data_ramdisk=dict(path=str(seed), size=seed.stat().st_size, sha256=digest(seed)),
              trust_bundle=dict(path=str(trust), size=trust.stat().st_size, sha256=digest(trust)),
              scripts={str(path.relative_to(ROOT)): digest(path) for path in (ROOT / 'scripts/build-os-root.py',
                       ROOT / 'scripts/run-qemu.py', ROOT / 'scripts/build-owner-os-policy.py',
                       ROOT / 'scripts/prepare-owner-os-raw.py', ROOT / 'scripts/prepare-owner-data-fixture.py')})
(ROOT / 'build/os-root-inputs.json').write_text(json.dumps(report, indent=2) + '\n')
print('OS-root inputs prepared; no runtime/UI success asserted.')
print(f'export XNU_OWNER_DATA_VOLUME_UUID={seed_uuid}')
print(f'OS_RAW_IMAGE={raw}')
print(f'TRUST_CACHE={trust}')
print(f'DATA_RAMDISK={seed}')
