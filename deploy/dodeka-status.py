#!/usr/bin/env python3
# /// script
# requires-python = ">=3.14"
# dependencies = []
# ///
"""Interactive deployment status report for Dodeka."""

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


RESTIC_REPO = "/mnt/backup/restic"
RESTIC_PW_FILE = "/mnt/backup/.restic-password"
BACKUP_LOG = Path("/home/backend/log/backup.log")
LOGROTATE_CONFIG = Path("/etc/logrotate.d/dodeka-backup")
MAX_BACKUP_AGE_MINUTES = 30

ENVIRONMENTS = ("production", "demo")
SERVICES = (
    "dodeka-auth-production",
    "dodeka-backend-production",
    "dodeka-auth-demo",
    "dodeka-backend-demo",
)


@dataclass
class CommandResult:
    ok: bool
    stdout: str
    stderr: str


def run(command: list[str], timeout: int = 10) -> CommandResult:
    env = os.environ.copy()
    env["PATH"] = f"/home/backend/.local/bin:{env.get('PATH', '')}"

    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            env=env,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        return CommandResult(False, "", str(exc))
    except subprocess.TimeoutExpired:
        return CommandResult(False, "", f"timed out after {timeout}s")

    return CommandResult(result.returncode == 0, result.stdout.strip(), result.stderr.strip())


def status_line(state: str, label: str, detail: str = "") -> bool:
    print(f"[{state}] {label}{': ' + detail if detail else ''}")
    return state == "OK"


def section(title: str) -> None:
    print()
    print(title)
    print("-" * len(title))


def parse_systemctl_value(output: str, key: str) -> str:
    prefix = f"{key}="
    for line in output.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :]
    return ""


def check_services() -> bool:
    section("Services")
    all_ok = True

    for service in SERVICES:
        result = run(
            [
                "systemctl",
                "show",
                service,
                "--property=LoadState,ActiveState,SubState,UnitFileState",
                "--no-pager",
            ]
        )
        if not result.ok:
            all_ok &= status_line("FAIL", service, result.stderr or "systemctl failed")
            continue

        load_state = parse_systemctl_value(result.stdout, "LoadState")
        active_state = parse_systemctl_value(result.stdout, "ActiveState")
        sub_state = parse_systemctl_value(result.stdout, "SubState")
        unit_file_state = parse_systemctl_value(result.stdout, "UnitFileState")

        if load_state != "loaded":
            state = "FAIL"
        elif active_state == "active":
            state = "OK"
        else:
            state = "FAIL"

        detail = f"{active_state}/{sub_state}, enabled={unit_file_state}"
        all_ok &= status_line(state, service, detail)

    return all_ok


def check_cron() -> bool:
    section("Cron")
    result = run(["crontab", "-l"])
    if not result.ok:
        return status_line("FAIL", "backup crontab", result.stderr or "crontab -l failed")

    expected = {
        "production": "/home/backend/dodeka/deploy/dodeka-db-cron.sh production",
        "demo": "/home/backend/dodeka/deploy/dodeka-db-cron.sh demo",
    }
    all_ok = True
    for env, needle in expected.items():
        all_ok &= status_line(
            "OK" if needle in result.stdout else "FAIL",
            f"{env} backup schedule",
            "installed" if needle in result.stdout else "missing from crontab",
        )

    if BACKUP_LOG.exists():
        all_ok &= status_line("OK", "backup log", str(BACKUP_LOG))
    else:
        all_ok &= status_line("WARN", "backup log", f"{BACKUP_LOG} does not exist yet")

    if LOGROTATE_CONFIG.exists():
        all_ok &= status_line("OK", "backup logrotate", str(LOGROTATE_CONFIG))
    else:
        all_ok &= status_line("WARN", "backup logrotate", f"{LOGROTATE_CONFIG} missing")

    return all_ok


def parse_restic_time(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    value = re.sub(r"(\.\d{6})\d+", r"\1", value)
    return datetime.fromisoformat(value).astimezone(timezone.utc)


def check_backups() -> bool:
    section("Backups")
    all_ok = True

    if not Path(RESTIC_REPO).exists():
        all_ok &= status_line("FAIL", "restic repository", f"{RESTIC_REPO} missing")
    else:
        all_ok &= status_line("OK", "restic repository", RESTIC_REPO)

    if not Path(RESTIC_PW_FILE).exists():
        all_ok &= status_line("FAIL", "restic password file", f"{RESTIC_PW_FILE} missing")
    else:
        all_ok &= status_line("OK", "restic password file", RESTIC_PW_FILE)

    restic_version = run(["restic", "version"])
    if not restic_version.ok:
        all_ok &= status_line("FAIL", "restic command", restic_version.stderr or "not found")
        return all_ok

    all_ok &= status_line("OK", "restic command", restic_version.stdout)

    now = datetime.now(timezone.utc)
    for env in ENVIRONMENTS:
        result = run(
            [
                "restic",
                "-r",
                RESTIC_REPO,
                "--password-file",
                RESTIC_PW_FILE,
                "snapshots",
                "--json",
                "--tag",
                f"db_dodeka,env_{env}",
            ],
            timeout=30,
        )
        if not result.ok:
            all_ok &= status_line("FAIL", f"{env} snapshots", result.stderr or "restic failed")
            continue

        try:
            snapshots = json.loads(result.stdout or "[]")
        except json.JSONDecodeError as exc:
            all_ok &= status_line("FAIL", f"{env} snapshots", f"invalid JSON: {exc}")
            continue

        if not snapshots:
            all_ok &= status_line("FAIL", f"{env} latest backup", "no snapshots found")
            continue

        snapshots.sort(key=lambda snapshot: snapshot.get("time", ""))
        latest = snapshots[-1]
        latest_time = parse_restic_time(latest["time"])
        age_minutes = int((now - latest_time).total_seconds() // 60)
        state = "OK" if age_minutes <= MAX_BACKUP_AGE_MINUTES else "FAIL"
        detail = (
            f"{latest_time.isoformat()} UTC, {age_minutes} minutes old, "
            f"{len(snapshots)} snapshots"
        )
        all_ok &= status_line(state, f"{env} latest backup", detail)

    return all_ok


def main() -> int:
    print("Dodeka deployment status")
    print(f"Checked at {datetime.now(timezone.utc).isoformat()} UTC")

    checks = [
        check_services(),
        check_cron(),
        check_backups(),
    ]

    section("Summary")
    if all(checks):
        status_line("OK", "deployment status", "no problems detected")
        return 0

    status_line("FAIL", "deployment status", "one or more checks need attention")
    return 1


if __name__ == "__main__":
    sys.exit(main())
