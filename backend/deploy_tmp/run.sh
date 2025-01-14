export GUNICORN_CMD_ARGS="--bind=0.0.0.0:4241 --workers=3"

../.venv/bin/gunicorn apiserver.app_inst:apiserver_app -w 3 -k uvicorn.workers.UvicornWorker