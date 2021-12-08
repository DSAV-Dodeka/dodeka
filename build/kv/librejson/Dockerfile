FROM rust:slim-bullseye
RUN apt-get update
RUN apt-get install git build-essential llvm libclang1 libclang-dev -y
COPY . /build/RedisJSON
WORKDIR /build/RedisJSON
RUN cargo build --release
CMD ["bash"]