#!/bin/bash
# Exit when a command fails
set -e
# Download release archive
gh release --repo RedisJSON/RedisJSON download {{ kv.redisjson_version }} --archive tar.gz --dir contextlibrejson
tar -xf contextlibrejson/*RedisJSON*.tar.gz -C contextlibrejson
# Remove archive so only dir will be copied
rm contextlibrejson/*RedisJSON*.tar.gz
# Copy Dockerfile to extracted dir
cp contextlibrejson/Dockerfile contextlibrejson/*RedisJSON*
# Build the Dockerfile which will build the librejson.so
docker build --tag rejsonbuild contextlibrejson/*RedisJSON*
# Run container so it can be extracted
docker run --name rejsonbuilder rejsonbuild
docker cp rejsonbuilder:/build/RedisJSON/target/release/librejson.so context/librejson.so