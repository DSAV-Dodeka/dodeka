from dirgh import find_download
from dirgh.cli_helper import find_token


def download_migration_env(version: str = "v0.2.0"):
    token = find_token("dodeka_", True)
    find_download("DSAV-Dodeka", "backend", "src/schema", "migrate", ref=f"tags/{version}", token=token, overwrite=True)
