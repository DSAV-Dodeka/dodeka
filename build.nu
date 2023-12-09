#!/usr/bin/env nu

use root.nu
# This allows use to also run this file from different subdirectories as long as you are in the same git repository
let deploy_dir = root deploy_dir

def build_deploy [] {
    cd $deploy_dir
    poetry run confrecipe -r build/deploy/dev/dev.toml -e localdev
    poetry run confrecipe -r build/deploy/staging/staging.toml -e staging
    poetry run confrecipe -r build/deploy/production/production.toml -e production
    poetry run confrecipe -r build/data_sync/data_sync.toml -e production
}

# Generate deployment configuration using confspawn for all environments
def "main deploy" [] {
    print "Generating configuration files using confspawn..."
    build_deploy
}

# important for the command to be exposed to the outside

def main [] {}