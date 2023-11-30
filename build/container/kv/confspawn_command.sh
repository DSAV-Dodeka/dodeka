#/bin/sh

# Check if the $REDIS_PASSWORD variable is set
if [ -n "$REDIS_PASSWORD" ]; then
  echo "Starting redis...."
  redis-server {{ kv.redis_conf_dir }} --requirepass "$REDIS_PASSWORD"
else
  echo "Error: \$REDIS_PASSWORD must be set!"
  exit 1
fi