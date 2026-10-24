#!/usr/bin/env python3
"""Bound the existing OS observer, without changing its verdicts.

The child observer still receives --seconds 900. A separate host deadline uses
the larger of wall and monotonic elapsed time, including preflight and cleanup.
Only watchdog-summary JSON is public; all child stdout/stderr stays private.
No artifact upload or real-device operation is performed by this script.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time


class Clock:
    monotonic = staticmethod(time.monotonic)
    wall = staticmethod(time.time)
    sleep = staticmethod(time.sleep)


def process_snapshot(timeout=2):
    # lstart + unchanged command protect descendant records against PID reuse.
    text = subprocess.check_output(
        ["ps", "-ww", "-axo", "pid=,ppid=,pgid=,lstart=,command="], text=True,
        timeout=timeout, env=dict(os.environ, LC_ALL="C"))
    result = {}
    for line in text.splitlines():
        match = re.fullmatch(r"\s*(\d+)\s+(\d+)\s+(\d+)\s+"
                             r"(\w{3}\s+\w{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d\s+\d{4})\s+(.*)", line)
        if match:
            pid, parent, group = (int(match[i]) for i in (1, 2, 3))
            result[pid] = (pid, parent, group, match[4], match[5])
    return result


def same_process(old, new):
    # PPID can change after an owned parent exits; identity must not.
    return old[0] == new[0] and old[3:] == new[3:]


class OwnedTree:
    """Track only the observer we started and its verified descendants.

    The original observer starts another session for run-qemu. Thus killing only
    the observer's own PGID would leave that session behind on a forced stop.
    Unknown or mixed groups are never signalled.
    """
    def __init__(self, process, snapshot=process_snapshot):
        self.process, self.snapshot = process, snapshot
        self.known, self.rows = {}, {}
        self.approved_groups = {process.pid}
        self.errors = []

    def refresh(self, timeout=2):
        try:
            rows = self.snapshot(timeout)
        except Exception as error:
            self.errors.append(type(error).__name__)
            return False
        seeds = {pid for pid, old in self.known.items() if pid in rows and same_process(old, rows[pid])}
        if self.process.poll() is None and self.process.pid in rows:
            row = rows[self.process.pid]
            if row[2] != self.process.pid:
                self.errors.append("UnexpectedObserverGroup")
                return False
            seeds.add(self.process.pid)
        selected = set(seeds)
        while True:
            children = {pid for pid, row in rows.items() if row[1] in selected}
            if children <= selected:
                break
            selected.update(children)
        for pid in selected:
            self.known[pid] = rows[pid]
            # Approve a new group only after observing its owned group leader.
            if rows[pid][0] == rows[pid][2]:
                self.approved_groups.add(rows[pid][2])
        self.rows = rows
        return True

    def alive(self):
        return {pid for pid, old in self.known.items()
                if pid in self.rows and same_process(old, self.rows[pid])}

    def signal_groups(self, signum):
        alive = self.alive()
        groups = {self.rows[pid][2] for pid in alive} & self.approved_groups
        # Our unreaped direct child cannot have had its PID reused. This root
        # group remains safe even if the optional ps snapshot failed.
        root_alive = self.process.poll() is None
        if root_alive:
            groups.add(self.process.pid)
        records = []
        for group in sorted(groups):
            members = {pid for pid, row in self.rows.items() if row[2] == group}
            if not (group == self.process.pid and root_alive) and (not members or not members <= alive):
                self.errors.append("UnconfirmedGroupNotSignalled")
                continue
            try:
                os.killpg(group, signum)
                records.append({"pgid": group, "signal": signal.Signals(signum).name})
            except ProcessLookupError:
                pass
            except OSError as error:
                self.errors.append(type(error).__name__)
        return records


def supervise(process, owner, wall_seconds, grace_seconds, emit, cancellation, clock=Clock,
              started=None, wall_started=None):
    """Bounded controller; dependency injection permits deterministic fixtures."""
    started = clock.monotonic() if started is None else started
    wall_started = clock.wall() if wall_started is None else wall_started
    report = {"schema": "unixnu-os-root-watchdog-v1", "state": "running",
              "observer_pid": process.pid, "observer_pgid": process.pid,
              "wall_budget_seconds": wall_seconds, "grace_seconds": grace_seconds,
              "guest_observation_seconds": 900, "runtime_verdict": "not_assessed",
              "budget_basis": "max(monotonic_elapsed_seconds, wall_elapsed_seconds)",
              "timeout_is_guest_failure": False, "signals": [], "errors": [],
              "started_utc": datetime.datetime.fromtimestamp(wall_started, datetime.timezone.utc).isoformat()}

    def publish():
        elapsed = clock.monotonic() - started
        wall_elapsed = clock.wall() - wall_started
        report.update(monotonic_elapsed_seconds=round(elapsed, 3),
                      wall_elapsed_seconds=round(wall_elapsed, 3),
                      budget_elapsed_seconds=round(max(elapsed, wall_elapsed), 3),
                      wall_minus_monotonic_seconds=round(wall_elapsed - elapsed, 3))
        emit(report)

    def remaining():
        return max(0, wall_seconds - max(clock.monotonic() - started, clock.wall() - wall_started))

    def total_remaining():
        return max(0, wall_seconds + grace_seconds
                   - max(clock.monotonic() - started, clock.wall() - wall_started))

    def requested_stop():
        if cancellation.get("signal") is not None:
            report["external_signal"] = int(cancellation["signal"])
            return "external_signal"
        if remaining() <= 0:
            return "wall_budget_exceeded"
        return None

    def refresh_within(seconds):
        # A snapshot or reap must not add a fixed delay after the total budget.
        if seconds > 0:
            return owner.refresh(timeout=min(2, seconds))
        return False

    next_refresh, next_publish = started, started
    reason = "observer_exit"
    publish()
    while True:
        # Polling first can turn a child exit during sleep/ps into success even
        # when the same interval exhausted the budget or received cancellation.
        reason = requested_stop() or "observer_exit"
        if reason != "observer_exit":
            break
        if process.poll() is not None:
            reason = requested_stop() or "observer_exit"
            break
        now = clock.monotonic()
        if now >= next_refresh:
            refresh_within(remaining())
            next_refresh = clock.monotonic() + 5
            reason = requested_stop() or "observer_exit"
            if reason != "observer_exit":
                break
        if now >= next_publish:
            publish()
            next_publish = clock.monotonic() + 15
        clock.sleep(min(0.25, remaining()))

    # On a deadline stop, signal the owned root immediately. Refreshing its
    # descendant snapshot must not postpone that first interrupt.
    stop_started = None
    if reason in {"wall_budget_exceeded", "external_signal"}:
        stop_started = clock.monotonic(), clock.wall()
        report["signals"].extend(owner.signal_groups(signal.SIGINT))
    refresh_within(total_remaining())
    if reason == "observer_exit":
        reason = requested_stop() or reason
    # Even an ordinary observer exit must not leave a tracked VM session behind.
    residual = bool(owner.alive())
    if reason == "observer_exit" and residual:
        reason = "owned_descendants_remained_after_observer_exit"
    report["termination_reason"] = reason
    must_stop = reason != "observer_exit"
    if must_stop:
        report["state"] = "interrupting_owned_processes"
        if stop_started is None:
            stop_started = clock.monotonic(), clock.wall()
            report["signals"].extend(owner.signal_groups(signal.SIGINT))
        report["stop_started_monotonic_seconds"] = round(stop_started[0] - started, 3)
        publish()
        grace_started, grace_wall_started = stop_started
        def grace_remaining():
            return min(total_remaining(), max(0, grace_seconds
                       - max(clock.monotonic() - grace_started, clock.wall() - grace_wall_started)))
        while grace_remaining() > 0:
            refresh_within(grace_remaining())
            if process.poll() is not None and not owner.alive():
                break
            clock.sleep(min(0.25, grace_remaining()))
        refresh_within(total_remaining())
        if process.poll() is None or owner.alive():
            report["state"] = "killing_owned_processes"
            report["signals"].extend(owner.signal_groups(signal.SIGKILL))
            publish()
        try:
            process.wait(timeout=min(5, total_remaining()))
        except subprocess.TimeoutExpired:
            report["errors"].append("ObserverDidNotReapAfterKill")
        refresh_within(total_remaining())

    report["observer_exit_code"] = process.poll()
    if reason == "observer_exit":
        reason = requested_stop() or reason
    report["termination_reason"] = reason
    report["remaining_owned_pids"] = sorted(owner.alive())
    report["ownership_check_errors"] = owner.errors[-20:]
    report["state"] = "finished"
    if reason == "wall_budget_exceeded":
        code = 124
    elif reason == "external_signal":
        code = 128 + report["external_signal"]
    elif reason != "observer_exit" or report["observer_exit_code"] != 0 or report["remaining_owned_pids"]:
        code = 2
    else:
        code = 0
    report["supervisor_exit_code"] = code
    report["finished_utc"] = datetime.datetime.fromtimestamp(clock.wall(), datetime.timezone.utc).isoformat()
    publish()
    # A signal or deadline reached while writing the final summary must not be
    # swallowed by an otherwise ordinary exit. No owned process remains here.
    late_reason = requested_stop() if reason == "observer_exit" else None
    if late_reason is not None:
        reason = late_reason
        code = 124 if reason == "wall_budget_exceeded" else 128 + report["external_signal"]
        report.update(termination_reason=reason, supervisor_exit_code=code,
                      finished_utc=datetime.datetime.fromtimestamp(clock.wall(), datetime.timezone.utc).isoformat())
        publish()
    return code, report


def project_path(project, path, *, regular=False):
    path = Path(path).resolve(strict=regular)
    if project not in path.parents or (regular and not stat.S_ISREG(path.stat().st_mode)):
        raise ValueError("expected a dedicated-project path")
    return path


def main():
    started, wall_started = Clock.monotonic(), Clock.wall()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--observer", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--wall-seconds", type=int, default=1800)
    parser.add_argument("--grace-seconds", type=int, default=60)
    parser.add_argument("observer_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("the owned-session supervisor requires POSIX")
    if not 60 <= args.wall_seconds <= 7200 or not 1 <= args.grace_seconds <= 120:
        parser.error("wall budget 60..7200 s and grace 1..120 s required")
    project = args.project_root.resolve(strict=True)
    observer = project_path(project, args.observer, regular=True)
    summary = project_path(project, args.summary)
    if summary.exists():
        parser.error("summary must be a new project file")
    child_args = args.observer_args[1:] if args.observer_args[:1] == ["--"] else args.observer_args
    if child_args.count("--seconds") != 1 or child_args[child_args.index("--seconds") + 1:][:1] != ["900"]:
        parser.error("pass the unchanged --seconds 900 to the original observer")
    child_parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    for name in ("project-root", "tree", "os-raw-image", "public-dir"):
        child_parser.add_argument("--" + name, required=True, type=Path)
    child_parser.add_argument("--seconds", required=True, type=int)
    child_parser.add_argument("--every", type=int, default=60)
    child_parser.add_argument("--sample-timeout", type=int, default=30)
    child = child_parser.parse_args(child_args)
    if child.seconds != 900 or child.project_root.resolve(strict=True) != project:
        parser.error("the original 900-second observer must use this project")
    project_path(project, child.tree, regular=False)
    project_path(project, child.os_raw_image, regular=True)
    project_path(project, child.public_dir, regular=False)
    if observer.name != "observe-os-root.py" or observer.stat().st_size > 1024 * 1024:
        parser.error("use the existing bounded observe-os-root.py")
    summary.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    private = project / "work/os-root-supervisor" / (stamp + f"-{os.getpid()}")
    private.mkdir(mode=0o700, parents=True, exist_ok=False)
    raw = private / "observer-console.raw.log"
    command = [sys.executable, str(observer), *child_args]
    command_sha = hashlib.sha256(json.dumps(command).encode()).hexdigest()
    observer_sha = hashlib.sha256(observer.read_bytes()).hexdigest()
    cancellation = {"signal": None}

    def handle_signal(signum, _):
        # Do not raise from signal handlers, including while cleaning up.
        cancellation.setdefault("first_signal", signum)
        cancellation["signal"] = cancellation["first_signal"]

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, handle_signal)

    def emit(report):
        public = dict(report, observer_argv_sha256=command_sha,
                      observer_source_sha256=observer_sha,
                      private_output_relative_path=str(raw.relative_to(project)))
        temporary = summary.with_suffix(summary.suffix + ".tmp")
        temporary.write_text(json.dumps(public, sort_keys=True, indent=2) + "\n")
        temporary.replace(summary)

    process, owner = None, None
    try:
        with raw.open("xb") as output:
            os.fchmod(output.fileno(), 0o600)
            process = subprocess.Popen(command, cwd=project, stdout=output,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            owner = OwnedTree(process)
            code, report = supervise(process, owner, args.wall_seconds, args.grace_seconds, emit, cancellation,
                                     started=started, wall_started=wall_started)
    except BaseException as error:
        # Best-effort owned cleanup if the controller itself failed. No raw
        # exception content or command output is put in the public report.
        signals = []
        if owner is not None:
            signals = owner.signal_groups(signal.SIGKILL)
            remaining = max(0, args.wall_seconds + args.grace_seconds
                            - max(Clock.monotonic() - started, Clock.wall() - wall_started))
            if remaining > 0:
                owner.refresh(timeout=min(2, remaining))
                signals.extend(owner.signal_groups(signal.SIGKILL))
        if process is not None:
            try:
                remaining = max(0, args.wall_seconds + args.grace_seconds
                                - max(Clock.monotonic() - started, Clock.wall() - wall_started))
                process.wait(timeout=min(5, remaining))
            except subprocess.TimeoutExpired:
                pass
        code = 125
        report = {"schema": "unixnu-os-root-watchdog-v1", "state": "supervisor_error",
                  "error_type": type(error).__name__, "supervisor_exit_code": code,
                  "runtime_verdict": "not_assessed", "timeout_is_guest_failure": False,
                  "budget_basis": "max(monotonic_elapsed_seconds, wall_elapsed_seconds)",
                  "signals": signals}
        elapsed, wall_elapsed = Clock.monotonic() - started, Clock.wall() - wall_started
        report.update(monotonic_elapsed_seconds=round(elapsed, 3), wall_elapsed_seconds=round(wall_elapsed, 3),
                      budget_elapsed_seconds=round(max(elapsed, wall_elapsed), 3),
                      wall_minus_monotonic_seconds=round(wall_elapsed - elapsed, 3))
        emit(report)
    print(json.dumps({"supervisor_exit_code": code, "runtime_verdict": "not_assessed",
                      "timeout_is_guest_failure": False}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
