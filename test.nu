#!/usr/bin/env nu

use root.nu
# This allows use to also run this file from different subdirectories as long as you are in the same git repository
let backend_dir = root backend_dir

def pytest_backend [] {
    cd $backend_dir
    uv run pytest
}

def check_backend [] {
    cd $backend_dir
    uv run black src tests
    uv run ruff check src tests
    print "Running mypy, this could take a while..."
    uv run mypy
}

def lint_fix [] {
    cd $backend_dir
    uv run ruff check src tests --fix
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

# Run pytest on the backend
def "main lint:fix" [] {
    print "Linting and fixing issues..."
    lint_fix
}


# important for the command to be exposed to the outside

def main [] {}