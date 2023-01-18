# dodeka

Everything is deployed from this repository. It also contains the "source" for the database (PostgreSQL) and key-value store (Redis).

The most important file is `config.toml`, which contains all practical configuration. In the `build`-folder you can find the source for all deploy scripts (`build/deploy`) and container build files (`build/container`). Using the `confspawn` tool the actual scripts are built from these templates. The results you can find in the various folders in the `use` directory.

## Running

In order to run the scripts, there are a few requirements.

First of all, you need to have a Unix-like command line with a bash-compatible shell: i.e. Linux or macOS. See the Notion for instructions on Windows Subsystem for Linux (**WSL**), which allows you to install Linux inside Windows.

Then, you need a number of tools installed, which you can install from the links below if you're not on Windows:

* [Docker Engine](https://docs.docker.com/engine/install/)

If you're on Windows, installing [Docker Desktop](https://www.docker.com/products/docker-desktop) after you've installed WSL will make these available inside WSL if Docker Desktop is running.

### Dev

To be able to run everything, you need to have configured access to the containers. To do that, run:

```shell
docker login ghcr.io
```

Enter your GitHub username. For the password, don't use your GitHub password, but a Personal Access Token (Settings -> Developer settings) with at least read:packages and write:packages permissions. Be sure to save the token somewhere safe, you'll probably have to reuse it and you can't view it in GitHub after creation!

Now, you will need to be able to access the scripts in this repository. If you're using Windows, **do not** copy the files from Windows to Linux, this leads to some weird formatting problems in the scripts that cause them to fail. Instead, clone this repository directly from WSL, by running:

`git clone https://github.com/DSAV-Dodeka/dodeka.git`

You will again need to enter your GitHub username and the Personal Access Token.

You will now have a `dodeka` folder containing all the necessary folders.

In `/dev` you can find `devdeploy.sh` and `down.sh`. By running `./devdeploy.sh` you start both the database and key-value store.


### Staging and production

For a complete setup including backend, first ensure the containers are built using GitHub Actions for the environment you want to deploy. Then, SSH into the cloud server you want to deploy it to. First, ensure Python, Docker (including Compose), gpg, GitHub CLI and bash are installed on the target server. Next, log into GitHub CLI with an account with access to this repository and the `dodekasecrets` repository.

To deploy, simply clone this repository and enter the main directory. Make sure you have updated the repository recently with the newest deploy script versions. Then, run `./deploy.sh production` for production. If you replace "production" with "staging", by default it will reset the database, so be careful! To deploy the staging version without reset, run `./deploy.sh staging update`.

It will ask you for the passphrase of `dodekasecrets`. Paste it in and press enter, the rest will then happen automatically!

That's it!


#### Syncing the test database

A number of test databases are stored inside the `DSAV-Dodeka/backend` repository. Running the commands above creates an empty database. To populate it with the latest test values, run:

```shell
poetry run python -c "from data.cli import run; run()"
```

You will probably need to set the GHMOTEQLYNC_DODEKA_GH_TOKEN as an environment variable for access. The safest way to set this is to add it to a file like `sync.env`:

```shell
export GHMOTEQLYNC_DODEKA_GH_TOKEN="GitHub Personal Access Token"
```

Here you should replace "GitHub Personal Access Token" with the value of your token, which will need `repo` scope. You can then run `. sync.env` before running the script to sync the database.

Ensure you are in the main `dodeka` directory, not in a subfolder.

To create a backup, run:
```shell
poetry run psqlsync --config data/test.toml --action backup
```

## Backup recovery using barman

Enter the barman container using i.e.:

```shell
docker exec -it b-dodeka-backup-1 /bin/bash
```

You can check the latest backup with this command:

```shell
barman show-backup d-dodeka-db-1 latest
```

Here it will display something like:

```
Backup 20230118T124531:
  Server Name            : d-dodeka-db-1
 
  ...

  Base backup information:
    ...
    Begin time           : 2023-01-18 12:45:31.095524+00:00
    End time             : 2023-01-18 12:45:31.341450+00:00
    ...

  ...

  Catalog information:
    ...
    Previous Backup      : 20230118T120301
    ...

```

Be sure to find a backup made before something went wrong!

For the target time you can use some time after the end time until the next backup (best to just use end time) and for the Backup ID use the ID displayed after 'Backup' in the first line.

```shell
barman recover --target-time "<End time>" d-dodeka-db-1 <Backup ID> /dodeka_recover
barman recover --target-time "2023-01-18 12:45:31.341450+00:00" d-dodeka-db-1 20230118T124531 /dodeka_recover
```

Be sure to turn the database off!

Then switch to the root user. BE CAREFUL IN THIS STEP.

```shell
rm -rf /var/lib/docker/volumes/d-dodeka-db-volume-production/_data
cp -R /var/lib/docker/volumes/b-dodeka-backup-volume-recover-production/_data /var/lib/docker/volumes/d-dodeka-db-volume-production/
```

Then restart everything. Note that there might be issues if there weren't enough transactions. 

## Building the scripts and containers

* [Poetry](https://python-poetry.org/docs/master/)
    * Once installed, run `poetry update` inside the main directory. This will install the other requirements.

### Deploy scripts

Building the deployment scripts is easy, simply run `build_deploy.sh` in the main directory.

### Containers

The containers have dedicated GitHub Actions workflows to build them, so in general you should never have to build them locally. Take a look at the workflows to see how they are built.