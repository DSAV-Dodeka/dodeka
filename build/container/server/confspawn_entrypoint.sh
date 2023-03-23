#!/bin/bash
export GUNICORN_CMD_ARGS="--bind=0.0.0.0:{{ server.container_port }} --workers=3"
/dodeka/server/bin/gunicorn apiserver.app_inst:apiserver_app -w 3 -k uvicorn.workers.UvicornWorker