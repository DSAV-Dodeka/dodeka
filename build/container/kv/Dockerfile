# Base redis
FROM redis:7.2-bookworm
ADD redis_base.conf /usr/local/etc/redis/redis.conf
# loadmodule in conf is done on startup
COPY librejson.so /rejson/librejson.so
CMD [ "redis-server", "/usr/local/etc/redis/redis.conf" ]