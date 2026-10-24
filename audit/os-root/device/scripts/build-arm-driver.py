#!/usr/bin/env python3
"""Compile the generic platform expert against the actual source-kernel ABI."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('component', choices=['ArmVirtPlatform', 'ArmDTPlatform', 'ArmCpu', 'NativeAES', 'NativeVirtioBlock', 'NativeRamBlock', 'NativeMobileDisplay', 'NativeVirtioConsole', 'NativeLegacyDisplay', 'NativeGOPPresenter', 'NativeOfflineGPU', 'NativeOfflineAccelerator', 'NativeIOGPUProviderProbe', 'NativeUfs', 'NativeHidInput', 'NativeKeyStoreEvents', 'NativeAdreno'])
parser.add_argument('--negative-aes-kat', action='store_true', help='Isolated own-source wrong-answer refusal control; never changes original inputs')
parser.add_argument('--verified-root', action='store_true', help='Authenticate all actual disk reads against an independently signed immutable policy')
parser.add_argument('--verified-root-bundle', action='store_true', help='Select exactly one capacity-matching policy per device, then independently authenticate it')
parser.add_argument('--negative-verified-block', action='store_true', help='Negative own-buffer control: corrupt only the completed DMA snapshot')
parser.add_argument('--without-physical-buttons', action='store_true',
                    help='QEMU NativeHidInput only: compile out the optional physical Power/Volume provider calls')
args = parser.parse_args()
if args.without_physical_buttons and args.component != 'NativeHidInput':
    parser.error('--without-physical-buttons applies only to NativeHidInput')
if args.verified_root_bundle and not args.verified_root:
    parser.error('A policy bundle requires verified block mode')
if args.verified_root_bundle and args.negative_verified_block:
    parser.error('Select either bundle policy qualification or the isolated DMA snapshot fault')
if (args.verified_root or args.negative_verified_block) and args.component != 'NativeVirtioBlock':
    parser.error('Verified block mode requires the concrete read-only block transport')
if args.negative_verified_block and not args.verified_root:
    parser.error('The isolated input fault requires verified block mode')
component = args.component
recipe = ROOT / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json'
record = json.loads(recipe.read_text().strip().rstrip(','))
source = ROOT / 'drivers' / ('NativeMobileDisplay' if component in ('NativeLegacyDisplay','NativeGOPPresenter') else 'NativeMetal' if component in ('NativeOfflineGPU','NativeOfflineAccelerator','NativeIOGPUProviderProbe') else component) / {'NativeAdreno':'NativeAdrenoService.cpp'}.get(component, component + '.cpp')
out = ROOT / 'build' / {'ArmVirtPlatform': 'armvirt-platform', 'ArmDTPlatform': 'armdt-platform', 'ArmCpu': 'armcpu', 'NativeAES': 'native-aes',
                        'NativeVirtioBlock': 'native-virtio-block', 'NativeRamBlock': 'native-ram-block',
                        'NativeMobileDisplay': 'native-mobile-display', 'NativeVirtioConsole': 'native-virtio-console',
                        'NativeLegacyDisplay': 'native-legacy-display', 'NativeGOPPresenter': 'native-gop-presenter', 'NativeOfflineGPU':'native-offline-gpu','NativeOfflineAccelerator':'native-offline-accelerator','NativeIOGPUProviderProbe':'native-original-provider', 'NativeUfs':'native-ufs', 'NativeHidInput':'native-hid-input', 'NativeKeyStoreEvents':'native-keystore-events', 'NativeAdreno':'native-adreno'}[component]
if args.verified_root:
    out = ROOT / ('build/native-virtio-block-verified-fault' if args.negative_verified_block else 'build/native-virtio-block-verified')
    if args.verified_root_bundle:
        out = ROOT / 'build/native-virtio-block-verified-bundle'
out.mkdir(parents=True, exist_ok=True)
if args.negative_aes_kat:
    if component != 'NativeAES':
        parser.error('The own-source KAT control requires NativeAES')
    out = ROOT / 'build/native-aes-kat-negative'
    out.mkdir(parents=True, exist_ok=True)
    text = source.read_text()
    marker = '0x76,0x49,0xab,0xac'
    if text.count(marker) != 1:
        raise SystemExit('The exact own-source NIST answer was not uniquely identified')
    (out / 'OriginalAESABI.h').write_bytes(source.with_name('OriginalAESABI.h').read_bytes())
    source = out / 'NativeAES.cpp'
    source.write_text(text.replace(marker, '0x77,0x49,0xab,0xac'))
destination = out / (component + '.o')
button_configuration = None
if args.without_physical_buttons:
    original_source = source
    original_bytes = source.read_bytes()
    if hashlib.sha256(original_bytes).hexdigest() != '0445e5f451ffcc827bdd603e822180444d998427fa3a6d63559b1a7b8f850998':
        raise SystemExit('The no-physical-buttons configuration requires the exact pinned owned NativeHidInput source')
    staged = original_bytes.decode('utf-8')
    callsites = (
        '        if(!touchOnly && &native_buttons_set_sink)native_buttons_set_sink(&NativeHidInput::buttonsNotify,this);',
        '        if(!touchOnly && &native_buttons_set_sink)native_buttons_set_sink(nullptr,nullptr);')
    for callsite in callsites:
        if staged.count(callsite) != 1:
            raise SystemExit('Expected one exact optional physical-button registration/unregistration callsite')
        staged = staged.replace(callsite, '#if NATIVE_HID_PHYSICAL_BUTTONS_PROVIDER\n' + callsite + '\n#endif')
    staged = '#ifndef NATIVE_HID_PHYSICAL_BUTTONS_PROVIDER\n#define NATIVE_HID_PHYSICAL_BUTTONS_PROVIDER 1\n#endif\n' + staged
    directory = out / 'no-physical-buttons'
    directory.mkdir(exist_ok=True)
    source = directory / 'NativeHidInput.cpp'  # preserve the static-initializer basename
    source.write_text(staged)
    button_configuration = dict(schema=1, physical_buttons_provider=False,
        macro='NATIVE_HID_PHYSICAL_BUTTONS_PROVIDER', macro_value=0,
        original_source=str(original_source.relative_to(ROOT)),
        original_source_sha256=hashlib.sha256(original_bytes).hexdigest(),
        compiled_source=str(source.relative_to(ROOT)), compiled_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        build_arm_driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        guarded_callsites=2, home_transport='unchanged QEMU Home/F1 command mailbox',
        touch_transport='unchanged QEMU tablet/touch publication',
        scope='physical Power/Volume provider absent; no claim of complete button support')


def object_symbol(blob, wanted):
    if struct.unpack_from('<I', blob)[0] != 0xfeedfacf:
        raise SystemExit('Expected an actual Mach-O64 object for the optional-button audit')
    offset = 32
    for _ in range(struct.unpack_from('<I', blob, 16)[0]):
        command_id, length = struct.unpack_from('<II', blob, offset)
        if command_id == 2:
            table, count, strings, _ = struct.unpack_from('<4I', blob, offset + 8)
            for i in range(count):
                index, kind, section, descriptor, value = struct.unpack_from('<IBBHQ', blob, table + i * 16)
                name = blob[strings + index:blob.index(b'\0', strings + index)].decode()
                if name == wanted:
                    return dict(type=kind, section=section, descriptor=descriptor, value=value)
            return None
        offset += length
    raise SystemExit('Missing Mach-O symbol table in optional-button audit')


arguments = record['arguments']
command = []
index = 0
while index < len(arguments):
    value = arguments[index]
    if value == record['file']:
        command.append(str(source))
    elif value == '-o':
        command.extend(['-o', str(destination)])
        index += 1
    elif value == '-Xclang' and arguments[index + 1].startswith('-W'):
        index += 1
    elif not value.startswith('-W'):
        command.append(value)
    index += 1
command.extend(['-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                '-Wno-c99-designator', '-Wno-reorder-init-list', '-Wno-deprecated-enum-enum-conversion',
                '-Wno-unnecessary-virtual-specifier', '-I', str(ROOT / '.cache/xnu-work/osfmk')])
if component in ('NativeVirtioBlock', 'NativeRamBlock', 'NativeUfs'):
    command += ['-I', str(ROOT / 'build/storage-abi/include')]
    if args.verified_root:
        command += ['-I', str(ROOT / 'kits/VerifiedRoot/include'), '-DNATIVE_VERIFIED_BLOCK=1']
    if args.negative_verified_block:
        command += ['-DNATIVE_VERIFIED_BLOCK_INJECT_FAULT=1']
    if args.verified_root_bundle:
        command += ['-DNATIVE_VERIFIED_BLOCK_MULTI_POLICY=1']
if component == 'NativeUfs':
    command += ['-I', str(ROOT / 'kits/VerifiedRoot/include'), '-I', str(ROOT / 'drivers/NativeVirtioBlock'),
                '-DNATIVE_VERIFIED_BLOCK=1', '-DNATIVE_VERIFIED_BLOCK_MULTI_POLICY=1', '-mgeneral-regs-only']
if component=='NativeOfflineGPU':
    command += ['-I',str(ROOT/'drivers/NativeVirtioConsole')]
if component in ('NativeLegacyDisplay','NativeHidInput'):
    command += ['-I', str(out)]
if component == 'NativeAdreno':
    command += ['-I', str(ROOT / 'kits/ArmSmmu4K'), '-I', str(ROOT / 'kits/AdrenoPM4'),
                '-I', str(ROOT / 'kits/sheng'), '-I', str(ROOT / 'kits/AdrenoFirmware'),
                '-I', str(ROOT / 'build/sheng-gmu')]
if button_configuration:
    # Compile the unchanged source under the actual same-kernel flags first,
    # proving that this one provider reference really is optional/weak.
    enabled_object = out / 'NativeHidInput.provider-enabled.o'
    enabled_command = [str(original_source) if value == str(source) else str(enabled_object)
                       if value == str(destination) else value for value in command]
    enabled = subprocess.run(enabled_command, cwd=record['directory'], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True)
    (out / 'provider-enabled-compile.log').write_text(enabled.stdout)
    if enabled.returncode:
        raise SystemExit(enabled.stdout[-3500:])
    symbol = object_symbol(enabled_object.read_bytes(), '_native_buttons_set_sink')
    if not symbol or symbol['type'] != 1 or symbol['section'] != 0 or symbol['value'] != 0 or not symbol['descriptor'] & 0x40:
        raise SystemExit('The exact optional button provider was not an actual undefined N_WEAK_REF symbol')
    button_configuration['original_optional_symbol'] = symbol
    button_configuration['provider_enabled_object_sha256'] = hashlib.sha256(enabled_object.read_bytes()).hexdigest()
    command += ['-DNATIVE_HID_PHYSICAL_BUTTONS_PROVIDER=0']
(out / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n')
result = subprocess.run(command, cwd=record['directory'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
(out / 'compile.log').write_text(result.stdout)
if result.returncode:
    raise SystemExit(result.stdout[-3500:])
data = destination.read_bytes()
if button_configuration:
    if object_symbol(data, '_native_buttons_set_sink') is not None:
        raise SystemExit('Disabled physical-button configuration still references the optional provider')
    button_configuration.update(disabled_provider_symbol_absent=True,
        compiled_object_sha256=hashlib.sha256(data).hexdigest(),
        compile_command_sha256=hashlib.sha256((out / 'compile-command.json').read_bytes()).hexdigest())
    (out / 'button-provider-audit.json').write_text(json.dumps(button_configuration, indent=2) + '\n')
magic, cpu, subtype, kind, count, size = struct.unpack_from('<6I', data)
if (magic, cpu, subtype, kind) != (0xfeedfacf, 0x100000c, 0, 1):
    raise SystemExit('Unexpected platform object architecture')
offset = 32
deployment = None
for _ in range(count):
    cmd, length = struct.unpack_from('<II', data, offset)
    if cmd == 0x32:
        deployment = struct.unpack_from('<II', data, offset + 8)
    offset += length
if deployment != (2, 0x110000):
    raise SystemExit(f'Unexpected platform deployment {deployment}')
archive = out / ('lib' + component + '.a')
archive.unlink(missing_ok=True)
subprocess.run(['xcrun', 'ar', 'rcs', archive, destination], check=True)
print(f'{component}: -Werror build and actual ARM64/iOS 17 object audit passed')
