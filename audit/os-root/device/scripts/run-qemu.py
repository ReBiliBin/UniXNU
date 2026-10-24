#!/usr/bin/env python3
"""Boot the qemu board's payload in QEMU virt (GICv3, Cortex-A710, 6 GiB, ramfb).

Run in the build tree (out/qemu/tree) after "unixnu build package kernel payload". The script stages an ESP from
UniXNU (as BOOTAA64.EFI), the files of the payload volume and DarwinBoot (scripts/build-darwinboot-efi.py), boots it,
keeps the serial log and takes a screenshot over QMP at a fixed interval. Output goes to out/qemu/run/<time>/.
"""
import argparse
import hashlib
import stat
import datetime
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import zlib

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT.parent
PROJECT = Path(os.environ.get('UNIXNU_AUDIT_PROJECT_ROOT', ROOT)).resolve()
MEMORY_MIB = 6144                    # [payload] dram_size of board.toml
SHARED_WINDOW = 0x40000000 + (MEMORY_MIB << 20)   # --shared-window: guest physical, after QEMU virt's RAM

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--seconds', type=int, default=300, help='stop QEMU after this long')
parser.add_argument('--every', type=int, default=20, help='seconds between screenshots')
parser.add_argument('--display', default='none', help='none, or cocoa for a window on this Mac')
parser.add_argument('--native-user', action='store_true',
                    help="boot UniXNU's static test process (build-native-user-fixture.py) as launchd from mockfs on md0 "
                         'and read its results before QEMU stops')
parser.add_argument('--os-root', action='store_true',
                    help='attach the OS disk image of the IPSW read-only as a VirtIO block device, the root of a kernel '
                         'built with qemu_root_defconfig (scripts/build-os-root.py)')
parser.add_argument('--os-raw-image', type=Path, help='project regular raw OS file signed by this build; required with --os-root')
parser.add_argument('--screen', default='1376x1024',
                    help='WIDTHxHEIGHT of the screen (package/QemuRamfbPkg switches ramfb before DarwinBoot), or '
                         '"firmware" for the firmware\'s 800x600. Keep WIDTH a multiple of 16 (rows of a multiple of '
                         '64 bytes): at 1366, the 12.9-inch iPad Pro\'s 1366x1024 points, every row of the picture '
                         'lands 2-3 bytes off. 1376x1024 is the nearest such size')
parser.add_argument('--shared-window', type=int, default=0, metavar='MIB',
                    help='add MIB of guest memory, shared with this Mac through RUN_DIR/shared.bin, as a second memory '
                         'node after the 6 GiB (guest physical 0x1c0000000); scripts/guest-ram.py maps it. The file '
                         'is removed when QEMU stops')
parser.add_argument('--shared-window-cache', choices=('wb', 'device'), default='wb',
                    help='how package/SharedWindow.cpp maps the window in the guest: write-back cacheable, as this '
                         'Mac maps the file, or device memory')
parser.add_argument('--metal', action='store_true',
                    help='give the guest a Metal device whose work runs on this Mac\'s GPU (package/QemuMetal): a 2 GiB '
                         'window unless --shared-window says otherwise, and qemu-metal-host serving it (build-qemu-metal.py '
                         'host), with its log in RUN_DIR/metal-host.log. The payload carries the plugin (build-qemu-metal.py guest)')
parser.add_argument('--metal-clients', default='iconservicesagent',
                    help='with --metal, the processes besides the render server that get a device, separated by commas (at most '
                         'eight at a time): the kernel grants each its connection, which its sandbox would refuse. Core Image '
                         'without Metal crashes the icon service, and Settings waits on it')
parser.add_argument('--metal-verbose', action='store_true',
                    help='with --metal, log every request and command of the processes besides the render server (qemu-metal-host '
                         '--verbose for slots 1-8)')
parser.add_argument('--accel', choices=('tcg', 'hvf'), default='tcg',
                    help='tcg emulates a Cortex-A710; hvf runs the guest on this Mac\'s CPU (Hypervisor.framework). The '
                         'payload must be built for the same accelerator: UNIXNU_QEMU_ACCEL=hvf for hvf')
args = parser.parse_args()
if args.native_user and args.os_root:
    parser.error('--native-user boots from md0; leave out --os-root')
if args.os_root and args.os_raw_image is None:
    parser.error('--os-root requires --os-raw-image; host-device attachment is disabled')
if args.os_raw_image is not None and not args.os_root:
    parser.error('--os-raw-image requires --os-root')
if args.os_root and (args.accel != 'tcg' or args.metal or args.shared_window or args.display != 'none'):
    parser.error('the audited OS-root route requires TCG, display none, and no shared window/Metal')
if not 1 <= args.seconds <= 1800 or not 1 <= args.every <= 3600:
    parser.error('--seconds must be 1..1800 and --every 1..3600')


def regular_project_file(path):
    path = Path(path)
    resolved = path.resolve(strict=True)
    if path.is_symlink() or not resolved.is_relative_to(PROJECT) or not stat.S_ISREG(resolved.stat().st_mode):
        raise SystemExit(f'Only a regular image inside the project build tree is allowed: {path}')
    if any(c in str(resolved) for c in ('\n', '\r', ',')):
        raise SystemExit('Image paths must not contain newlines or commas')
    return resolved


def digest_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


os_inputs = None
if args.os_root:
    # No hdiutil query/attach and no host-device fallback exist in this branch.
    image = regular_project_file(args.os_raw_image)
    os_report_path = regular_project_file(ROOT / 'build/verified-root-os/verification.json')
    os_report = json.loads(os_report_path.read_text())
    raw = os_report.get('audit_raw_image', {})
    raw_digest = digest_file(image)
    if (image.stat().st_size != 6077580800 or raw.get('path') != str(image) or
            raw.get('size') != 6077580800 or raw.get('sha256') != raw_digest or
            raw.get('source_udif_sha256') != '3f99b859c9728379110b66657c7b15285bcb1925ad8b5726542e2cdcf8b1028d' or
            os_report.get('image_bytes') != 6077580800 or os_report.get('image_sha256') != raw_digest or
            os_report.get('blocks_verified') != 1483785 or
            os_report.get('real_c_signature_and_block_verification') is not True):
        raise SystemExit('The regular OS file is not bound to this successful complete C/RSA policy verification')
    source = regular_project_file(raw.get('source_udif_path', ''))
    if digest_file(source) != raw['source_udif_sha256']:
        raise SystemExit('The original UDIF source no longer matches the OS policy')
    systemos = regular_project_file(ROOT / '.cache/firmware/target-volumes/044-76034-038.dmg')
    system_digest = digest_file(systemos)
    system_report_path = regular_project_file(ROOT / 'build/verified-root-systemos/verification.json')
    system_report = json.loads(system_report_path.read_text())
    if (system_digest != 'b4908cde41d23e6bc05e6af51a2c9eeb00cf0f863a6a18b1600c96a3fd70414f' or
            system_report.get('image_sha256') != system_digest or
            system_report.get('blocks_verified') != 806400 or
            system_report.get('real_c_signature_and_block_verification') is not True or
            not os_report.get('trusted_key_sha256') or
            os_report['trusted_key_sha256'] != system_report.get('trusted_key_sha256')):
        raise SystemExit('SystemOS or its complete C/RSA verification/key anchor differs')
    os_inputs = dict(os_raw_image=str(image), os_raw_sha256=raw_digest,
                     source_udif_sha256=raw['source_udif_sha256'], systemos_sha256=system_digest,
                     os_policy_sha256=digest_file(os_report_path),
                     systemos_policy_sha256=digest_file(system_report_path),
                     trusted_key_sha256=os_report['trusted_key_sha256'],
                     scope='input authentication only; no guest runtime success asserted')
if args.metal and not args.shared_window:
    args.shared_window = 2048
metal_host = ROOT / 'build/qemu-metal/qemu-metal-host'
if args.metal and not metal_host.is_file():
    raise SystemExit(f'{metal_host} missing (scripts/build-qemu-metal.py host)')

qemu = shutil.which('qemu-system-aarch64')
if not qemu:
    raise SystemExit('qemu-system-aarch64 not found (brew install qemu)')
code = Path(qemu).resolve().parents[1] / 'share/qemu/edk2-aarch64-code.fd'
payload = WORK / 'payload/payload.img'
unixnu = WORK / 'package/Build/Out/AARCH64-DEBUG/UniXNU.efi'
for path, step in ((code, 'brew install qemu'), (payload, 'unixnu build payload'), (unixnu, 'unixnu build package')):
    if not path.is_file():
        raise SystemExit(f'{path} missing ({step})')
darwinboot = ROOT / 'build/darwinboot-efi/DarwinBoot.efi'
if not darwinboot.is_file():
    subprocess.run(['python3', ROOT / 'scripts/build-darwinboot-efi.py'], check=True)

out = WORK / 'run' / datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
esp = out / 'esp'
esp.mkdir(parents=True)
subprocess.run(['mcopy', '-s', '-n', '-i', payload, '::/EFI', esp], check=True, env=dict(os.environ, MTOOLS_SKIP_CHECK='1'))
(esp / 'EFI/BOOT').mkdir(parents=True, exist_ok=True)
shutil.copyfile(unixnu, esp / 'EFI/BOOT/BOOTAA64.EFI')
config = (esp / 'EFI/UniXNU/unixnu.toml').read_text()
if 'Payloads/DarwinBoot.efi' not in config:
    raise SystemExit('the payload does not load DarwinBoot as a driver; board.toml [payload] loader must not be "firmware"')
shutil.copyfile(darwinboot, esp / 'EFI/UniXNU/Payloads/DarwinBoot.efi')
if args.screen != 'firmware':
    if not re.fullmatch(r'\d{3,4}x\d{3,4}', args.screen):
        parser.error('--screen takes WIDTHxHEIGHT or "firmware"')
    # Loaded before DarwinBoot, so UniXNU's menu and the kernel's frame buffer have the new size.
    ramfb = ROOT / 'build/qemu-ramfb-efi/QemuRamfb.efi'
    if not ramfb.is_file():
        subprocess.run(['python3', ROOT / 'scripts/build-qemu-ramfb-efi.py'], check=True)
    shutil.copyfile(ramfb, esp / 'EFI/UniXNU/Payloads/QemuRamfb.efi')
    config = config.replace('[[driver]]\npath = "Payloads/DarwinBoot.efi"',
                            '[[driver]]\npath = "Payloads/QemuRamfb.efi"\n\n[[driver]]\npath = "Payloads/DarwinBoot.efi"', 1)
    (esp / 'EFI/UniXNU/unixnu.toml').write_text(config)

spec = importlib.util.spec_from_file_location('make_qemu_adt', ROOT / 'scripts/make-qemu-adt.py')
adt_tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adt_tool)
adt = esp / 'EFI/UniXNU/Payloads/kernel.macho.adt'
tree, _ = adt_tool.parse(adt.read_bytes())


def node(entry, name):
    if entry[0] == name:
        return entry
    return next((found for child in entry[2] if (found := node(child, name))), None)


# The kernel's timer runs at the device tree's timebase: TCG's counter is 62.5 MHz, under HVF it is the host's.
timebase = struct.unpack('<I', dict(node(tree, 'cpu0')[1])['timebase-frequency'])[0]
expected = 62500000 if args.accel == 'tcg' else int(subprocess.check_output(['sysctl', '-n', 'hw.tbfrequency'], text=True))
if timebase != expected:
    raise SystemExit(f'the payload\'s device tree has a {timebase} Hz timebase, {args.accel} needs {expected} Hz: rebuild '
                     f'the payload with UNIXNU_QEMU_ACCEL={args.accel}')

fixture = ROOT / 'build/native-user-fixture'
if args.native_user:
    # The test process is the whole md0 image (a single Mach-O, which mockfs serves as /sbin/launchd); its own trust
    # cache admits it under the platform-only AMFI policy.
    if not (fixture / 'launchd.macho').is_file():
        subprocess.run(['python3', ROOT / 'scripts/build-native-user-fixture.py'], check=True)
    payloads = esp / 'EFI/UniXNU/Payloads'
    shutil.copyfile(fixture / 'launchd.macho', payloads / 'launchd.macho')
    shutil.copyfile(fixture / 'trustcache.bundle', payloads / 'kernel.macho.trustcache')
    if 'initrd = ' in config:
        raise SystemExit('the payload already has an initrd; build it without --data-ramdisk for --native-user')
    (esp / 'EFI/UniXNU/unixnu.toml').write_text(
        config.replace('args = "', 'initrd = "Payloads/launchd.macho"\nargs = "rd=md0 ', 1))
    chosen = adt_tool.child(tree, 'chosen')
    chosen[1] = [item for item in chosen[1] if item[0] != 'root-matching']   # a memory root, not a matched volume
    memory_map = adt_tool.child(chosen, 'memory-map')
    for key in ('RAMDisk', 'TrustCache'):                                      # DarwinBoot fills these placeholders
        adt_tool.put(memory_map, key, bytes(16))
    adt.write_bytes(adt_tool.serialize(tree))

# Keep even temporary firmware variables and the monitor inside this project.
# The short name leaves room under macOS's 104-byte Unix socket pathname limit.
temporary_root = PROJECT / '.q'
if temporary_root.is_symlink() or not temporary_root.resolve().is_relative_to(PROJECT):
    raise SystemExit('Project QMP temporary directory must not escape through a symlink')
temporary_root.mkdir(exist_ok=True)
work = Path(tempfile.mkdtemp(prefix='v-', dir=temporary_root))
variables = work / 'vars.fd'
with variables.open('wb') as f:
    f.truncate(code.stat().st_size)
sock = work / 'qmp.sock'
if len(os.fsencode(str(sock))) > 100:
    raise SystemExit(f'Project QMP socket pathname is too long: {sock}')
command = [qemu, '-M', 'virt,virtualization=off,secure=off,gic-version=3', '-accel', args.accel,
           '-cpu', 'cortex-a710' if args.accel == 'tcg' else 'host',
           '-m', str(MEMORY_MIB), '-smp', '1',
           '-drive', f'if=pflash,format=raw,readonly=on,file={code}', '-drive', f'if=pflash,format=raw,file={variables}',
           '-drive', f'if=none,id=esp,format=raw,readonly=on,file=fat:{esp}', '-device', 'virtio-blk-pci,drive=esp',
           '-device', 'ramfb', '-device', 'qemu-xhci', '-device', 'usb-kbd', '-nic', 'none',
           # A cocoa window scales the 800x600 frame buffer to its size (drag its corner, or View > Zoom To Fit) and
           # keeps the Mac pointer visible: with the absolute tablet QEMU would hide it, and iPadOS draws none for a
           # touch screen.
           '-display', args.display + (',zoom-to-fit=on,show-cursor=on' if args.display == 'cocoa' else ''), '-no-reboot',
           '-serial', f'file:{out / "serial.log"}', '-qmp', f'unix:{sock},server=on,wait=off']
if args.screen != 'firmware':
    command += ['-fw_cfg', f'name=opt/org.unixnu/ramfb-size,string={args.screen}']
shared_ram = out / 'shared.bin'
if args.shared_window:
    # Node 0 is the guest's ordinary memory; node 1 follows it and is this file, mapped shared by QEMU (and HVF).
    # Sharing all of the guest's memory instead stopped the userland at launchd, spinning. The kernel only manages
    # DarwinBoot's window, so it leaves node 1 to whoever maps it.
    at = command.index('-m')
    command[at + 1] = str(MEMORY_MIB + args.shared_window)
    command += ['-object', f'memory-backend-ram,id=ram0,size={MEMORY_MIB}M',
                '-object', f'memory-backend-file,id=ram1,size={args.shared_window}M,mem-path={shared_ram},share=on',
                '-numa', 'node,nodeid=0,cpus=0,memdev=ram0', '-numa', 'node,nodeid=1,memdev=ram1',
                # package/SharedWindow.cpp finds the window here: BASE:SIZE:MODE in hexadecimal.
                '-fw_cfg', f'name=opt/org.unixnu/shared-window,string={SHARED_WINDOW:x}:{args.shared_window << 20:x}:'
                           f'{args.shared_window_cache}']
    if args.metal and args.metal_clients:
        # package/QemuMetal/QemuMetalPublish.cpp publishes a grant for each.
        command += ['-fw_cfg', f'name=opt/org.unixnu/metal-clients,string={args.metal_clients}']
if args.os_root:
    # Both immutable VirtIO backends are ordinary project files. Their complete
    # contents were checked above against the successful owner policy reports.
    command += ['-global', 'virtio-mmio.force-legacy=false', '-blockdev', json.dumps({
                    'driver': 'raw', 'node-name': 'os', 'read-only': True,
                    'file': {'driver': 'file', 'filename': str(image), 'read-only': True,
                             'locking': 'off'}}),
                '-device', 'virtio-blk-device,drive=os',
                '-blockdev', json.dumps({'driver': 'raw', 'node-name': 'systemos', 'read-only': True,
                                         'file': {'driver': 'file', 'filename': str(systemos), 'read-only': True,
                                                  'locking': 'off'}}),
                '-device', 'virtio-blk-device,drive=systemos',
                '-device', 'virtio-tablet-device', '-device', 'virtio-keyboard-device']
    (out / 'os-root-inputs.json').write_text(json.dumps(os_inputs, indent=2) + '\n')
(out / 'command.txt').write_text(' '.join(str(part) for part in command) + '\n')
hosts = []
if args.metal:
    # The window file exists before QEMU starts, so the hosts map the same file QEMU then backs the window with: one host for each slot
    # (package/QemuMetal/QemuMetalWire.h), each the device of one guest process.
    with shared_ram.open('wb') as handle:
        handle.truncate(args.shared_window << 20)
    hosts = [subprocess.Popen([str(metal_host), '--window', str(shared_ram), '--slot', str(slot), '--log', str(out / 'metal-host.log')]
                              + (['--verbose'] if args.metal_verbose and slot else []))
             for slot in range(9)]
process = subprocess.Popen([str(part) for part in command], stdout=open(out / 'qemu.log', 'w'), stderr=subprocess.STDOUT)


def png(ppm, target):
    data = ppm.read_bytes()
    fields, at = [], 0
    while len(fields) < 4:
        while data[at:at + 1].isspace():
            at += 1
        end = at
        while not data[end:end + 1].isspace():
            end += 1
        fields.append(data[at:end])
        at = end
    width, height = int(fields[1]), int(fields[2])
    pixels = data[at + 1:]
    rows = b''.join(b'\0' + pixels[y * width * 3:(y + 1) * width * 3] for y in range(height))

    def chunk(tag, body):
        return struct.pack('>I', len(body)) + tag + body + struct.pack('>I', zlib.crc32(tag + body) & 0xffffffff)
    target.write_bytes(b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)) +
                       chunk(b'IDAT', zlib.compress(rows, 6)) + chunk(b'IEND', b''))


def qmp(name, *, _deadline=None, **arguments):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        def limit():
            remaining = 10 if _deadline is None else _deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('native checkpoint observation budget exhausted')
            s.settimeout(remaining)

        limit()
        s.connect(str(sock))
        stream = s.makefile('rwb', buffering=0)
        limit()
        stream.readline()
        for request in ({'execute': 'qmp_capabilities'}, {'execute': name, 'arguments': arguments}):
            limit()
            stream.write((json.dumps(request) + '\n').encode())
            while True:
                limit()
                reply = json.loads(stream.readline())
                if 'return' in reply or 'error' in reply:
                    break
        return reply


def native_checkpoint_samples(addresses):
    """Bounded native-fixture snapshots; each five-part check uses one paused VM."""
    started = time.monotonic()
    deadline = started + 10
    samples, raw = [], ''

    def command(name, **arguments):
        reply = qmp(name, _deadline=deadline, **arguments)
        if time.monotonic() > deadline:
            raise TimeoutError('native checkpoint observation budget exhausted')
        if 'error' in reply or 'return' not in reply:
            raise RuntimeError('native checkpoint QMP command failed')
        return reply['return']

    for attempt in range(1, 31):
        if time.monotonic() >= deadline:
            break
        sample = dict(attempt=attempt, initially_running=False, paused_confirmed=False, pc=None,
                      checkpoint=int(addresses['_checkpoint']), el=None, getpid=None,
                      sysctl_status=None, hw_pagesize=None, accepted=False)
        parts, failed, stopped_by_observer = [], False, False
        try:
            original = command('query-status')
            initial_status = original.get('status')
            sample['initial_status'] = initial_status if initial_status in {
                'running', 'paused', 'guest-panicked', 'internal-error'} else 'other'
            if original.get('status') != 'running' or original.get('running') is not True:
                raise RuntimeError('native checkpoint VM was not running before observation')
            sample['initially_running'] = True
            stopped_by_observer = True
            command('stop')
            status = command('query-status')
            if status.get('status') != 'paused' or status.get('running') is not False:
                raise RuntimeError('native checkpoint VM pause was not confirmed')
            sample['paused_confirmed'] = True
            for line in ('info registers', f'x /4gx {addresses["_results"]:#x}',
                         f'x /1gx {addresses["_user_page_size"]:#x}'):
                text = command('human-monitor-command', **{'command-line': line})
                if not isinstance(text, str):
                    raise ValueError('native checkpoint monitor output was not text')
                parts.append(text)
            registers, results, page = parts
            pc = re.search(r'\bPC=([0-9a-fA-F]+)', registers)
            level = re.search(r'\bEL(\d)[th]\b', registers)
            words = [int(value, 16) for value in re.findall(r'0x([0-9a-fA-F]{16})', results)]
            size = re.findall(r'0x([0-9a-fA-F]{16})', page)
            sample.update(pc=int(pc[1], 16) if pc else None, el=int(level[1]) if level else None,
                          getpid=words[0] if words else None,
                          sysctl_status=words[1] if len(words) > 1 else None,
                          hw_pagesize=int(size[0], 16) if size else None)
            sample['conditions'] = dict(
                pc_matches_fixture_checkpoint=sample['pc'] == sample['checkpoint'],
                user_exception_level=sample['el'] == 0, pid_one=sample['getpid'] == 1,
                sysctl_success=sample['sysctl_status'] == 0, four_kib_pages=sample['hw_pagesize'] == 4096)
            sample['within_deadline'] = time.monotonic() <= deadline
            sample['accepted'] = all(sample['conditions'].values()) and sample['within_deadline']
        except Exception as error:
            # Raw QMP/monitor replies remain private; generated JSON carries only
            # numerical observations, booleans and a fixed Python error type.
            sample['error_type'] = type(error).__name__
            failed = True
        finally:
            raw = '\n'.join(parts)
            if time.monotonic() > deadline:
                sample['within_deadline'] = False
                sample['accepted'] = False
            sample['elapsed_seconds'] = round(time.monotonic() - started, 3)
            samples.append(sample)
        if sample['accepted']:
            break  # Keep this exact state frozen until the existing quit below.
        if stopped_by_observer and time.monotonic() < deadline:
            try:
                command('cont')
                sample['resumed'] = True
            except Exception as error:
                sample['resume_error_type'] = type(error).__name__
                break  # The caller still performs the normal owned-VM quit.
        if failed or time.monotonic() >= deadline:
            break
        time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    finished = time.monotonic()
    if samples and finished > deadline:
        samples[-1]['within_deadline'] = False
        samples[-1]['accepted'] = False
    return dict(schema=1, budget_seconds=10, maximum_attempts=30,
                elapsed_seconds=round(finished - started, 3),
                accepted=bool(samples and samples[-1]['accepted']), samples=samples), raw


def native_quit_and_reap(child):
    """Quit the owned native-test Popen child; kill and reap on any failure."""
    result = dict(quit_attempted=False, kill_requested=False, reaped=False, failed=False)

    def kill_owned_child():
        if child.poll() is None:
            result['kill_requested'] = True
            try:
                child.kill()
            except Exception as error:
                result['kill_error_type'] = type(error).__name__
                result['failed'] = True

    if child.poll() is None:
        result['quit_attempted'] = True
        try:
            reply = qmp('quit')
            if 'error' in reply or 'return' not in reply:
                raise RuntimeError('native checkpoint QMP quit failed')
        except Exception as error:
            result['quit_error_type'] = type(error).__name__
            result['failed'] = True
            kill_owned_child()
    try:
        child.wait(timeout=30)
        result['reaped'] = True
    except Exception as error:
        result['wait_error_type'] = type(error).__name__
        result['failed'] = True
        kill_owned_child()
        try:
            child.wait(timeout=5)
            result['reaped'] = True
        except Exception as reap_error:
            result['reap_error_type'] = type(reap_error).__name__
    result['exit_code'] = child.returncode
    if child.returncode != 0 or not result['reaped']:
        result['failed'] = True
    return result


start, shots = time.time(), []
while time.time() - start < args.seconds and process.poll() is None:
    time.sleep(args.every)
    if process.poll() is not None:
        break
    ppm = work / 'screen.ppm'
    try:
        if 'error' not in qmp('screendump', filename=str(ppm)):
            shots.append(out / f'screen-{int(time.time() - start):03d}s.png')
            png(ppm, shots[-1])
    except OSError as error:
        print('screendump failed:', error)
native_observation = None
if args.native_user and process.poll() is None:
    # A single terminal live-PC sample may land in the kernel. Retry only within
    # this fixed native-fixture window; all original checkpoint criteria remain.
    addresses = json.loads((fixture / 'addresses.json').read_text())
    observation, raw = native_checkpoint_samples(addresses)
    native_observation = observation
    (out / 'native-checkpoint-samples.json').write_text(json.dumps(observation, indent=2) + '\n')
    (out / 'native-user.txt').write_text(raw)
    last = observation['samples'][-1] if observation['samples'] else {}
    pc = f'{last["pc"]:x}' if last.get('pc') is not None else '?'
    observed = lambda name: last.get(name) if last.get(name) is not None else '?'
    print(f'native user: PC {pc} (checkpoint {addresses["_checkpoint"]:x}), '
          f'EL{observed("el")}, getpid {observed("getpid")}, '
          f'sysctl status {observed("sysctl_status")}, hw.pagesize {observed("hw_pagesize")}')
if args.native_user:
    native_termination = native_quit_and_reap(process)
    native_observation = native_observation or dict(schema=1, accepted=False, samples=[])
    native_observation['termination'] = native_termination
    if native_termination['failed']:
        native_observation['accepted'] = False
    (out / 'native-checkpoint-samples.json').write_text(json.dumps(native_observation, indent=2) + '\n')
    print('native checkpoint accepted: ' + str(native_observation['accepted']).lower())
else:
    if process.poll() is None:
        try:
            qmp('quit')
        except OSError:
            process.kill()
    process.wait(timeout=30)
shutil.rmtree(work, ignore_errors=True)
for host in hosts:
    host.terminate()
for host in hosts:
    host.wait(timeout=30)
shared_ram.unlink(missing_ok=True)
log = (out / 'serial.log').read_bytes().decode('utf-8', 'replace')
for line in [line for line in log.splitlines() if line.startswith(('UNIXNU:', 'DARWINBOOT:'))][-4:]:
    print(line)
print(f'qemu exit {process.returncode}; {len(shots)} screenshots in {out}')
if shots:
    print(f'last screen: {shots[-1]}')
(out / 'run-result.json').write_text(json.dumps(dict(
    qemu_exit=process.returncode, screenshots=[str(path) for path in shots],
    elapsed_seconds=round(time.time() - start, 3), requested_seconds=args.seconds,
    scope='QEMU lifecycle only; original-userland/UI acceptance requires separate live observations'), indent=2) + '\n')
if args.native_user and native_termination['failed']:
    raise SystemExit(1)
if process.returncode != 0:
    raise SystemExit(process.returncode if 0 < process.returncode < 256 else 1)

