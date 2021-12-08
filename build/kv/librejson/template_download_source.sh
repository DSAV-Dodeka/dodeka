#!/bin/bash
# Exit when a command fails
set -e
# Download release archive
gh release --repo RedisJSON/RedisJSON download ~spwn@redisjson_version@~ --archive tar.gz --dir kv/librejson
tar -xf kv/librejson/*RedisJSON*.tar.gz -C kv/librejson
# Remove archive so only dir will be copied
rm kv/librejson/*RedisJSON*.tar.gz
# Copy Dockerfile to extracted dir
cp kv/librejson/Dockerfile kv/librejson/*RedisJSON*
# Build the Dockerfile which will build the librejson.so
docker build --tag rejsonbuild kv/librejson/*RedisJSON*
# Remove any previous container
docker rm rejsonbuilder
# Run container so it can be extracted
docker run --name rejsonbuilder rejsonbuild
docker cp rejsonbuilder:/build/RedisJSON/target/release/librejson.so kv/librejson.so
# Clean up container
docker rm rejsonbuilder