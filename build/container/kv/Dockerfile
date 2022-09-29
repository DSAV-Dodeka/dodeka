# Base redis
FROM redis:6.2-bullseye
# loadmodule in conf is done on startup
COPY librejson.so /rejson/librejson.so
CMD [ "redis-server", "/usr/local/etc/redis/redis.conf" ]