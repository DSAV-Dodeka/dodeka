#!/bin/sh
poetry run confrecipe -r build/deploy/staging/staging.toml -e staging
poetry run confrecipe -r build/deploy/dev/dev.toml -e localdev