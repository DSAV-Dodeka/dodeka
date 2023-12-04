#!/bin/bash

# Define function to stop the server gracefully
stop_server() {
    echo "Stopping the server..."
    kill $server_pid
    exit 0
}

# Trap SIGTERM signal and run stop_server function
trap 'stop_server' SIGTERM

export GUNICORN_CMD_ARGS="--bind=0.0.0.0:{{ server.container_port }} --workers=3"

/dodeka/server/bin/gunicorn apiserver.app_inst:apiserver_app -w 3 -k uvicorn.workers.UvicornWorker &
server_pid=$!  # Save the PID of  server process

wait "$server_pid"  # Wait for server