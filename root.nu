
# get git root directory and trim the newline
export def git_root_dir [] {
    git rev-parse --show-toplevel | str trim
}

# get deploy subdirectory of project
export def deploy_dir [] {
    let root_dir = git_root_dir
    $"($root_dir)/deploy"
}

# get backend subdirectory of project
export def backend_dir [] {
    let root_dir = git_root_dir
    $"($root_dir)/backend"
}