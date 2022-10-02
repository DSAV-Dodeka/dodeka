The staging mode is designed to operate on a copy of the primary database, also running in the cloud.

By default, running the deploy script will remove the previous DB volume and recreate it from scratch. Supplying 'update' will prevent this.

Running this script requires being logged in to Docker with proper ghcr.io credentials.