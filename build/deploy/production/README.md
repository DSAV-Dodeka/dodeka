The production mode is designed for deployment into production.

By default, running the deploy script will keep the database intact. Supplying 'recreate' will remove the previous DB volume and recreate it from scratch. 

Running this script requires being logged in to Docker with proper ghcr.io credentials.