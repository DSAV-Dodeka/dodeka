"""
Download the auth binary from GitHub Actions artifacts using the gh CLI.
Vibe code level: HIGH (don't try to modify this yourself, you can just observe the
results)
"""

import hashlib
import json
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from apiserver.resources import project_path

GITHUB_REPO = "DSAV-Dodeka/dodeka"
WORKFLOW_FILE = "ci.yml"

# Map (sys.platform, machine) to CI artifact name
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


def find_latest_run() -> dict[str, str | int] | None:
    """Find the latest successful CI workflow run. Returns dict with keys
    databaseId, headSha, number, or None if no runs found."""
    result = gh(
        "run",
        "list",
        "--repo",
        GITHUB_REPO,
        "--workflow",
        WORKFLOW_FILE,
        "--status",
        "success",
        "--limit",
        "1",
        "--json",
        "databaseId,headSha,number",
    )
    runs = json.loads(result.stdout)
    if not runs:
        return None
    return runs[0]


def download_artifact(run_id: str, artifact_name: str, dest: str) -> bool:
    """Download a single artifact from a run into dest directory."""
    try:
        gh(
            "run",
            "download",
            run_id,
            "--repo",
            GITHUB_REPO,
            "-n",
            artifact_name,
            "-D",
            dest,
        )
    except subprocess.CalledProcessError as e:
        print(f"Failed to download artifact '{artifact_name}': {e.stderr.strip()}")
        return False
    return True


def find_downloaded_file(tmpdir: Path, expected_name: str) -> Path | None:
    """Find the downloaded file in a temp directory."""
    path = tmpdir / expected_name
    if path.exists():
        return path
    # gh may extract with a different structure
    files = list(tmpdir.iterdir())
    if len(files) == 1:
        return files[0]
    print(f"Unexpected artifact contents: {[f.name for f in files]}")
    return None


def download_auth_binary(*, force: bool = False) -> bool:
    """Download the auth binary from the latest successful CI run.

    When force=False, skips if the binary already exists.
    When force=True, downloads the remote checksum first and skips only if
    the local binary already matches.

    Returns True if a binary was downloaded, False if skipped.
    """
    binary_path = get_auth_binary_path()

    if not force and binary_path.exists():
        return False

    if not has_gh():
        print(
            "The 'gh' CLI is required to download the auth binary.\n"
            "Install it from https://cli.github.com/ and then run"
            " 'gh auth login' to authenticate."
        )
        return False

    name = artifact_name_for_platform()

    # Find latest successful CI run
    run = find_latest_run()
    if run is None:
        print("No successful CI runs found.")
        return False

    run_id = str(run["databaseId"])
    head_sha = str(run["headSha"])
    print(f"Found CI run #{run['number']} (commit {head_sha[:8]})")

    # Download checksum artifact first to check if update is needed
    checksum_artifact = f"{name}.sha256"
    with tempfile.TemporaryDirectory() as tmpdir:
        if download_artifact(run_id, checksum_artifact, tmpdir):
            hash_file = find_downloaded_file(Path(tmpdir), f"{name}.sha256")
            if hash_file is not None:
                remote_hash = hash_file.read_text().strip()

                if binary_path.exists():
                    local_hash = sha256_file(binary_path)
                    if local_hash == remote_hash:
                        print("Auth binary is up to date.")
                        return False

    # Download the binary
    print(f"Downloading auth binary ({name})...")
    with tempfile.TemporaryDirectory() as tmpdir:
        if not download_artifact(run_id, name, tmpdir):
            return False

        downloaded = find_downloaded_file(Path(tmpdir), name)
        if downloaded is None:
            return False

        binary_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(downloaded), str(binary_path))

    # Make executable on Unix
    if sys.platform != "win32":
        binary_path.chmod(binary_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)

    print(f"Auth binary saved to {binary_path}")
    return True


def ensure_auth_binary() -> None:
    """Check for the auth binary and download if missing."""
    binary_path = get_auth_binary_path()
    if binary_path.exists():
        return
    print("Auth binary not found, attempting to download...")
    download_auth_binary()


def update_auth() -> None:
    """Entry point for `uv run update-auth`. Force-downloads the latest binary."""
    download_auth_binary(force=True)
