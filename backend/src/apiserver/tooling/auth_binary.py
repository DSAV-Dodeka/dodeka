"""
Download the auth binary from GitHub releases using the gh CLI.
Vibe code level: HIGH (don't try to modify this yourself, you can just observe the
results)
"""

import hashlib

import platform
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from apiserver.resources import project_path

GITHUB_REPO = "DSAV-Dodeka/dodeka"
CHECKSUM_FILE = "auth-binary.sum"

# Map (sys.platform, machine) to release asset name
ARTIFACT_MAP: dict[tuple[str, str], str] = {
    ("linux", "x86_64"): "auth-linux-amd64",
    ("darwin", "arm64"): "auth-darwin-arm64",
    ("win32", "AMD64"): "auth-windows-amd64.exe",
}


def artifact_name_for_platform() -> str:
    key = (sys.platform, platform.machine())
    name = ARTIFACT_MAP.get(key)
    if name is None:
        msg = f"Unsupported platform: {sys.platform}/{platform.machine()}"
        raise RuntimeError(msg)
    return name


def auth_dir() -> Path:
    return project_path / "auth"


def get_auth_binary_path() -> Path:
    name = "auth.exe" if sys.platform == "win32" else "auth"
    return auth_dir() / name


def checksum_file_path() -> Path:
    return auth_dir() / CHECKSUM_FILE


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def has_gh() -> bool:
    return shutil.which("gh") is not None


def gh(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["gh", *args],
        capture_output=True,
        text=True,
        check=True,
    )


def read_checksums() -> tuple[str | None, dict[str, str]]:
    """Read auth-binary.sum. Returns (release_tag, {artifact_name: hash}).

    Returns (None, {}) if the file doesn't exist."""
    path = checksum_file_path()
    if not path.exists():
        return None, {}
    tag = None
    checksums: dict[str, str] = {}
    for raw_line in path.read_text().splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("# tag="):
            tag = stripped[6:]
        elif stripped and not stripped.startswith("#"):
            hash_val, _, name = stripped.partition("  ")
            if name:
                checksums[name] = hash_val
    return tag, checksums


def write_checksums(tag: str, checksums: dict[str, str]) -> None:
    """Write auth-binary.sum."""
    path = checksum_file_path()
    lines = [f"# tag={tag}"]
    for name in sorted(checksums):
        lines.append(f"{checksums[name]}  {name}")
    lines.append("")
    path.write_text("\n".join(lines))


def download_release_asset(tag: str, pattern: str, dest: str) -> bool:
    """Download release assets matching a glob pattern into dest directory."""
    try:
        gh(
            "release",
            "download",
            tag,
            "--repo",
            GITHUB_REPO,
            "--pattern",
            pattern,
            "-D",
            dest,
        )
    except subprocess.CalledProcessError as e:
        print(f"Failed to download '{pattern}' from release {tag}: {e.stderr.strip()}")
        return False
    return True


def download_auth_binary(*, force: bool = False) -> bool:
    """Download the auth binary from the GitHub release pinned in auth-binary.sum.

    When force=False, skips if the binary already exists and hash matches.
    When force=True, always re-downloads (still verifies hash after download).

    Requires auth-binary.sum to exist with a pinned release tag.

    Returns True if a binary was downloaded, False if skipped.
    """
    binary_path = get_auth_binary_path()
    name = artifact_name_for_platform()
    pinned_tag, checksums = read_checksums()
    expected_hash = checksums.get(name)

    if pinned_tag is None or expected_hash is None:
        print(
            "No pinned auth binary version found.\n"
            "Run 'uv run update-auth <tag>' to pin a release first."
        )
        return False

    if binary_path.exists() and not force:
        if sha256_file(binary_path) == expected_hash:
            return False

    if not has_gh():
        print(
            "The 'gh' CLI is required to download the auth binary.\n"
            "Install it from https://cli.github.com/ and then run"
            " 'gh auth login' to authenticate."
        )
        return False

    print(f"Downloading auth binary ({name}) from release {pinned_tag}...")

    with tempfile.TemporaryDirectory() as tmpdir:
        if not download_release_asset(pinned_tag, name, tmpdir):
            return False

        downloaded = Path(tmpdir) / name
        if not downloaded.exists():
            print(f"Expected file {name} not found in download.")
            return False

        actual_hash = sha256_file(downloaded)
        if actual_hash != expected_hash:
            print(
                f"Hash mismatch! Expected {expected_hash[:16]}...,"
                f" got {actual_hash[:16]}..."
            )
            print("Run 'uv run update-auth <tag>' to refresh the pinned checksums.")
            return False
        print(f"Checksum verified ({actual_hash[:16]}...)")

        binary_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(downloaded), str(binary_path))

    # Make executable on Unix
    if sys.platform != "win32":
        binary_path.chmod(binary_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)

    print(f"Auth binary saved to {binary_path}")
    return True


def ensure_auth_binary() -> None:
    """Check for the auth binary and download if missing or outdated."""
    binary_path = get_auth_binary_path()
    name = artifact_name_for_platform()
    pinned_tag, checksums = read_checksums()
    expected_hash = checksums.get(name)

    if pinned_tag is None or expected_hash is None:
        if binary_path.exists():
            return
        print(
            "Auth binary not found and no version is pinned.\n"
            "Run 'uv run update-auth <tag>' to pin a release,"
            " then re-run."
        )
        return

    if binary_path.exists():
        if sha256_file(binary_path) == expected_hash:
            print(f"Auth binary matches pinned version ({expected_hash[:16]}...)")
            return
        print("Auth binary does not match pinned version, re-downloading...")
    else:
        print("Auth binary not found, attempting to download...")

    download_auth_binary(force=True)


def update_auth() -> None:
    """Entry point for `uv run update-auth`.

    Downloads all binaries from a release, computes their SHA256 hashes,
    and writes auth-binary.sum.

    Usage:
        uv run update-auth auth/v1.0.0
    """
    args = sys.argv[1:]
    if not args:
        print("Usage: uv run update-auth <release-tag>")
        print("Example: uv run update-auth auth/v1.0.0")
        return

    tag = args[0]

    if not has_gh():
        print(
            "The 'gh' CLI is required.\n"
            "Install from https://cli.github.com/ and run 'gh auth login'."
        )
        return

    print(f"Downloading binaries from release {tag} to compute checksums...")

    checksums: dict[str, str] = {}
    with tempfile.TemporaryDirectory() as tmpdir:
        if not download_release_asset(tag, "auth-*", tmpdir):
            print("Failed to download binaries from release.")
            return

        for artifact_name in ARTIFACT_MAP.values():
            binary_path = Path(tmpdir) / artifact_name
            if binary_path.exists():
                checksums[artifact_name] = sha256_file(binary_path)
                print(f"  {artifact_name}: {checksums[artifact_name][:16]}...")
            else:
                print(f"  {artifact_name}: not found in release")

    if not checksums:
        print("No binaries found in release.")
        return

    write_checksums(tag, checksums)
    path = checksum_file_path()
    print(f"\nUpdated {path}")
    print(f"Commit this file to pin auth binary to release {tag}.")
