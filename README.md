# dodeka

Everything is deployed from this repository. It also contains the "source" for the database (PostgreSQL) and key-value store (Redis).

The most important file is `/build/config.toml`, which contains all practical configuration. In the `build`-folder you can find the source for all deploy scripts. Using the `confspawn` tool worden the actual scripts are built from these templates. The results you can find i `dev`, `deploydb`, etc. in the root directory.

//TODO barman source

## Running

In order to run the scripts, there are a few requirements.

First of all, you need to have a Unix-like command line with a bash-compatible shell: i.e. Linux or macOS. See the Notion for instructions on Windows Subsystem for Linux (WSL), which allows you to install Linux inside Windows.

Then, you need a number of tools installed:

* [Docker Engine](https://docs.docker.com/engine/install/)
* [Docker Compose V2](https://docs.docker.com/compose/cli-command/)

If you're on Windows, installing Docker Desktop after you've installed WSL will make these available inside WSL if Docker Desktop is running.

### Dev

To be able to run everything, you need to have configured access to the containers. To do that, run:

```shell
docker login ghcr.io
```

Enter your GitHub username. For the password, don't use your GitHub password, but a Personal Access Token (Settings -> Developer settings) with at least read:packages and write:packages permissions. Be sure to save the token somewhere safe!

In `/dev` you can find `devdeploy.sh` and `down.sh`. By running `./devdeploy.sh` you start both the database and key-value store.

## Building the scripts and containers
* [Poetry](https://python-poetry.org/docs/master/)
    * Once installed, run `poetry update` inside the main directory. This will install the other requirements.

### Scripts


Building the deploy scripts is easy, look for the `build_*.sh` files inside `/build` and run the `poetry` commands inside them _from within the `/build` directory_.

```shell
poetry run python -c "from spawn_db import spawn_deploy; spawn_deploy()"
poetry run python -c "from spawn_kv import spawn_deploy; spawn_deploy()"
poetry run python -c "from spawn_dev import spawn_dev; spawn_dev()"
```

### Containers

The containers have dedicated GitHub Actions workflows to build them, so in general you should never have to build them locally.

#### db

The database is easy to build. Ensure the build config is generated (again, run from inside the `/build` folder):

```shell
poetry run python -c "from spawn_db import spawn_build; spawn_build('configged')"
```

Then, build the Docker container:

```shell
docker build --tag 'ghcr.io/dsav-dodeka/postgres' db/configged
```

#### kv

Building the Redis container is, unfortunately, a lot harder as you need to manually load in the librejson.so library, which allows Redis to store JSON files. However, they do not freely publish librejson.so, you need to build it yourself or download it via an Enterprise account. Since the latter is not practical, we build it ourselves from their latest release.

##### Building librejson.so

First, build the config from the `/build` directory:

```shell
poetry run python -c "from spawn_kv import spawn_librejson; spawn_librejson('configged')"
```

For the next step, you need to have [GitHub CLI](https://github.com/cli/cli) installed. It is used for downloading the librejson source.
Again from the `/build` directory:

```shell
./kv/librejson/configged/build_librejson.sh
```

This script will download the `RedisJSON/RedisJSON` GitHub project, which contains the source. It will untar it and then build a Docker container with Rust installed. The file will then be built from that container, after which it is copied from the container.

##### Redis container

Once you have the `librejson.so` in your `/build/kv` directory, building the Redis container is  easy:

```shell
docker build --tag 'ghcr.io/dsav-dodeka/redis' kv
```