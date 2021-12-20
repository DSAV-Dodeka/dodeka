#!/bin/sh
# This file is only for local development
poetry run python -c "from spawn_sync import spawn_test_sync; spawn_test_sync()"