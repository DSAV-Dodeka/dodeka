#!/usr/bin/env nu

use root.nu
# This allows use to also run this file from different subdirectories as long as you are in the same git repository
let backend_dir = root backend_dir

def main [action: string] {
    cd $backend_dir
    uv run python actions/actions.py $action
}