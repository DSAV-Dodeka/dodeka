#!/usr/bin/env nu

use root.nu
# This allows use to also run this file from different subdirectories as long as you are in the same git repository
let deploy_dir = root deploy_dir
let backend_dir = root backend_dir

def pull [envnmt: string, env_file: string, profile: string] {
    docker compose -f $"($deploy_dir)/use/($envnmt)/docker-compose.yml" --env-file $"($deploy_dir)/use/($envnmt)/($env_file).env" --profile $profile pull
}

def up [envnmt: string, env_file: string, profile: string] {
    # pull $envnmt $env_file $profile
    docker compose -f $"($deploy_dir)/use/($envnmt)/docker-compose.yml" --env-file $"($deploy_dir)/use/($envnmt)/($env_file).env" --profile $profile up -d
}

def down [envnmt: string, env_file: string, profile: string] {
    let deploy_dir = root deploy_dir
    docker compose -f $"($deploy_dir)/use/($envnmt)/docker-compose.yml" --env-file $"($deploy_dir)/use/($envnmt)/($env_file).env" --profile $profile down
}

# "main" means it runs when calling the script
# "main updev" means updev is a subcommand of the main script

# Start development databases when running Docker directly in your OS (i.e. not WSL)
def "main up" [] {
    print "Starting databases for development (if using WSL, use `upp`)..."
    up dev dev data
}

# Shutdown databases
def "main down" [] {
    print "Shutting down databases for development..."
    down dev dev data
}

# Start development databases when not running Docker directly in your OS (i.e. WSL)
def "main upp" [] {
    print "Starting databases for development (WSL port mode)..."
    up dev dev_port data
}

# Start development databases when not running Docker directly in your OS (i.e. WSL)
def "main backend" [] {
    cd $backend_dir
    uv run backend
}

# important for the command to be exposed to the outside

# Useful development commands for starting and stopping databases
def main [] {}
