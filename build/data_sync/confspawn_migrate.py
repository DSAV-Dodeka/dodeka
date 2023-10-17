from functools import partial
from dirgh import find_download, run_sync
from dirgh.cli_helper import find_token


def download_migration_env(version: str = "HEAD"):
    token = find_token("dodeka_", True)

    download = partial(find_download,
                       "DSAV-Dodeka",
                       "backend",
                       "src/schema",
                       "migrate",
                       ref=f"{version}",
                       token=token,
                       overwrite=True)

    run_sync(download)
