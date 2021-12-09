#!/bin/sh
poetry run python -c "from config import print_config_var; print_config_var('$1', '$2')"