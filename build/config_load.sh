#!/bin/sh
# $1 is the first argument, use the environment from the config.toml
# $2 is the second argument, use the required variable
# It will print the variable value to stdout
poetry run python -c "from config import print_config_var; print_config_var('$1', '$2')"
# Example to capture as env variable in shell:
# export REJSON_VERSION=$(./config_load.sh 'default.kv' 'redisjson_version')