#!/bin/bash
# metaconfig
# 'configged' is the directory in which the built config values are put
poetry run python -c "from spawn_kv import spawn_librejson; spawn_librejson('configged')"
./kv/librejson/configged/download_source.sh