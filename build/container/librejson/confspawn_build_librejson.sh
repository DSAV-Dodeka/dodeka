#!/bin/bash
# Exit when a command fails
set -e
# Download release archive
gh release --repo RedisJSON/RedisJSON download {{ kv.redisjson_version }} --archive tar.gz --dir context/librejson
tar -xf context/librejson/*RedisJSON*.tar.gz -C context/librejson
# Remove archive so only dir will be copied
rm context/librejson/*RedisJSON*.tar.gz
# Copy Dockerfile to extracted dir
cp context/librejson/Dockerfile context/librejson/*RedisJSON*
# Build the Dockerfile which will build the librejson.so
docker build --tag rejsonbuild context/librejson/*RedisJSON*
# Run container so it can be extracted
docker run --name rejsonbuilder rejsonbuild
docker cp rejsonbuilder:/build/RedisJSON/target/release/librejson.so context/librejson.so