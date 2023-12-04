#!/bin/bash

# Define function to stop Redis gracefully
stop_redis() {
    echo "Stopping Redis server..."
    redis-cli shutdown
    0
}

# Trap SIGTERM signal and run stop_redis function
trap stop_redis SIGTERM

# Check if the $REDIS_PASSWORD variable is set
if [ -n "$REDIS_PASSWORD" ]; then
  echo "Starting redis...."
  redis-server {{ kv.redis_conf_dir }} --requirepass "$REDIS_PASSWORD" &
  redis_pid=$!  # Save the PID of Redis server process
  wait "$redis_pid"  # Wait for Redis
else
  echo "Error: \$REDIS_PASSWORD must be set!"
  exit 1
fi