#!/bin/sh
# This file is only for local development, in reality it will be built using GitHub Actions
./build_librejson.sh
# docker build --tag 'ghcr.io/dsav-dodeka/redis' kv