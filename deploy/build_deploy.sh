#!/bin/sh
uv run confrecipe -r build/deploy/dev/dev.toml -e localdev
uv run confrecipe -r build/deploy/staging/staging.toml -e staging
uv run confrecipe -r build/deploy/production/production.toml -e production
uv run confrecipe -r build/data_sync/data_sync.toml -e production