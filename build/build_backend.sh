#!/bin/sh
# This file is only for local development
poetry run python -c "from spawn_back import spawn_backend; spawn_backend()"