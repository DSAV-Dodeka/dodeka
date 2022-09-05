#!/bin/bash
# metaconfig
# 'configged' is the directory in which the built config values are put
poetry run confspawn -c config.toml -s ./kv/librejson -t ./kv/librejson/configged
./kv/librejson/configged/build_librejson.sh