#!/bin/sh
poetry run python -c "from use.data_sync.migrate import download_migration_env; download_migration_env('v2.3.0')" || exit 1
cp use/data_sync/connect.json migrate/connect.json