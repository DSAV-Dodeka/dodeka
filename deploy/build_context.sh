#!/bin/sh
poetry run confspawn -c config.toml -s ./build/container/kv -t ./context/kv -e localdev