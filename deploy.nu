#!/usr/bin/env nu

# Deploy using tidploy, which will pull and (re)create the Docker Compose environment for the specified environment and (Git) tag
def "main create" [envnmt: string, tag: string = "latest"] {
    tidploy deploy $envnmt $tag
}

# Shutdown (ensure any periods '.' have been replaced by underscores '_')
def "main down" [envnmt: string, tag_repl: string] {
    docker compose -p $"dodeka-($envnmt)-($tag_repl))" down
}

# Start development databases when running Docker directly in your OS (i.e. not WSL)
def "main up" [] {
    print "Starting databases for development (if using WSL, use `upp`)..."
    up dev dev data
}

# important for the command to be exposed to the outside

# Commands to deploy and shutdown production-like environments (so production or staging)
def main [] {}