#!/bin/bash
export GUNICORN_CMD_ARGS="--bind=0.0.0.0:4241 --workers=3"
/dodeka/server/bin/gunicorn apiserver.app:app -w 3 -k uvicorn.workers.UvicornWorker