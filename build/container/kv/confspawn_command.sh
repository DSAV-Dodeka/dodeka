#/bin/sh

# Check if the $HI variable is set
if [ -n "$REDIS_PASSWORD" ]; then
  redis-server {{ kv.redis_conf_dir }} --requirepass "$REDIS_PASSWORD"
else
  echo "Error: \$REDIS_PASSWORD must be set!"
  exit 1
fi