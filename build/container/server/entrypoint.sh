#!/bin/bash
export GUNICORN_CMD_ARGS="--bind=0.0.0.0:4241 --workers=2"
poetry run gunicorn dodekaserver.app:app -w 2 -k uvicorn.workers.UvicornWorker