This repository builds Docker containers (the `build/container` directory) and builds the scripts for deploying them (`build/deploy`). Both are differentiated based on the "environment" or "mode" of deployment. We distinguish the following:

* 'production' mode
* 'staging' mode
* 'test' mode
* 'localdev' mode

The DB and KV are designed to vary very little depending on their mode, accepting simple configuration options and allowing to be wrapped by simple scripts to handle different modes.

The Server and Pages have more significant differences between modes.

In general, modes are pre-selected for deploy builds, but for container builds they are selected at build time (in CI). Furthermore, deploy builds can generally be run locally, while container builds are run in CI.