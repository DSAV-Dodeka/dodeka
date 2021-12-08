#!/bin/sh
# This file is only for local development, in reality it will be built using GitHub Actions
# metaconfig
# 'configged' is the directory in which the built config values are put
poetry run python -c "from spawn_db import spawn_build; spawn_build('configged')"
# metaconfig
# db/configged should correspond to the directory of the built config
# docker build --tag 'ghcr.io/dsav-dodeka/postgres' db/configged
poetry run python -c "from spawn_db import spawn_deploy; spawn_deploy()"