#!/usr/bin/env nu

use root.nu
# This allows use to also run this file from different subdirectories as long as you are in the same git repository
let backend_dir = root backend_dir

def pytest_backend [] {
    cd $backend_dir
    poetry run pytest
}

def check_backend [] {
    cd $backend_dir
    poetry run black src tests
    poetry run ruff src tests
    poetry run mypy
}

# Run pyest and run the formatter, linter and type checker
def "main backend" [] {
    print "Testing and checking backend..."
    pytest_backend
    check_backend
}

# Run pytest on the backend
def "main pytest" [] {
    print "Testing backend..."
    pytest_backend
}


# important for the command to be exposed to the outside

def main [] {}