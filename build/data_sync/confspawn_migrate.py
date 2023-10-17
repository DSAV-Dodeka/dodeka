from functools import partial
from dirgh import find_download, run_sync
from dirgh.cli_helper import find_token


def download_migration_env(version: str = "v2.0.0"):
    token = find_token("dodeka_", True)

    download = partial(find_download,
                       "DSAV-Dodeka",
                       "backend",
                       "src/schema",
                       "migrate",
                       ref=f"tags/{version}",
                       token=token,
                       overwrite=True)

    run_sync(download)
