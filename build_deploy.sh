#!/bin/sh
poetry run confrecipe -r build/deploy/staging/staging.toml -e staging
poetry run confrecipe -r build/deploy/production/production.toml -e production
poetry run confrecipe -r build/deploy/dev/dev.toml -e localdev