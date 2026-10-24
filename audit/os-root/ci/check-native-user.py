#!/usr/bin/env python3
"""Verify native-user observations; run from the UniXNU cloud checkout root.

Reads existing text observations only; never starts QEMU or contacts a device.
"""
import json
from pathlib import Path
import re
log = Path("out/qemu/logs/native-user-run.log").read_text()
pattern = r"native user: PC ([0-9a-fA-F]+) \(checkpoint ([0-9a-fA-F]+)\), EL(\d+), getpid (\d+), sysctl status (-?\d+), hw.pagesize (\d+)"
match = re.search(pattern, log)
if not match:
    raise SystemExit("FAIL: no native-user register/syscall observation was produced")
pc, checkpoint = (int(value, 16) for value in match.group(1, 2))
el, pid, status, page_size = (int(value) for value in match.group(3, 4, 5, 6))
addresses = json.loads(Path("out/qemu/tree/build/native-user-fixture/addresses.json").read_text())
expected = int(addresses["_checkpoint"])
markers = re.findall(r"^native checkpoint accepted: (.*)$", log, flags=re.M)
conditions = {
    "pc_matches_fixture_checkpoint": pc == checkpoint == expected,
    "user_exception_level": el == 0,
    "pid_one": pid == 1,
    "sysctl_success": status == 0,
    "four_kib_pages": page_size == 4096,
    "coherent_bounded_snapshot": markers == ["true"],
}
record = {
    "result": "PASS" if all(conditions.values()) else "FAIL",
    "pc": hex(pc), "checkpoint": hex(checkpoint), "fixture_checkpoint": hex(expected),
    "el": el, "getpid": pid, "sysctl_status": status, "hw_pagesize": page_size,
    "conditions": conditions,
    "scope": "Actual XNU mockfs static user process; no original iPadOS userland or UI",
}
Path("out/qemu/logs/native-user-check.log").write_text(json.dumps(record, indent=2) + "\n")
print(json.dumps(record, indent=2))
if not all(conditions.values()):
    raise SystemExit("FAIL: native-user checkpoint requirements were not met")
