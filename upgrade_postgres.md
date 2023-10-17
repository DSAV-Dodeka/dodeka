First, prepare the new image with the new version of Postgres. Then, get both containers to run on the same machine. 

For this, deploy using `use/repl`, ensuring that all the settings are what you want the new database to have. The password can be set at every start, so that doesn't matter. Later, we will change the volume name before running it the normal way.

Next log into the old database, e.g. using `docker exec -it -w /dodeka-db d-dodeka-db-1 /bin/bash`. Here 'd-dodeka-db-1' is the container name of the old database and '-w /dodeka-db' means we enter the main DB directory.

Then, use `pg_dumpall`, where '3141' is the local port it's running on and 'dodeka' is the main db user:

```shell
pg_dumpall -p 3141 -U dodeka > ./upgrade_dump.sql
```

Ensure that after this dump is made, no more changes are made to the db, as these will be lost. Best is to shut off any external access (e.g. by shutting down the webserver for a short moment).

Now, you must get the file `upgrade_dump.sql` to the new database, which you should already have initialized.
If you leave the container, you can use `docker cp`, for example like this:

```shell
docker cp d-dodeka-db-1:/dodeka-db/upgrade_dump.sql ./upgrade_dump.sql
```

Here we again assume the old container is named 'd-dodeka-db-1', the dump file path is '/dodeka-db/upgrade_dump.sql' inside the container and you want to copy it to your local folder. Now, we copy it to the new container:

```shell
docker cp ./upgrade_dump.sql d-dodeka_repl-db-1:/dodeka-db/upgrade_dump.sql
```

Notice the other container's name is 'd-dodeka_repl-db-1'.

Finally, we need to replace the old container's Docker volume by the new one. There are no great solutions for this, but what you can do is run this:

```shell
# Deletes the old container's volume and recreates it
docker volume rm d-dodeka-db-volume-localdev
docker volume create --name d-dodeka-db-volume-localdev
# Copies from your new db's volume to the old one
docker run --rm -it -v d-dodeka_repl-db-volume-localdev:/from -v d-dodeka-db-volume-localdev:/to alpine ash -c "cd /from ; cp -av . /to"
# Since our old volume name now contains the new one's data, we can delete the new one and reuse the old one
docker volume rm d-dodeka_repl-db-volume-localdev
```

Now, ensure your old deployment uses the new image and restart it. Everything should work then.

### Recap

```shell
# Update dodeka repo on server

# Deploy repl database
cd use/repl
./repldeploy.sh

# Turn off database access (shut down apiserver)

# Enter database
docker exec -it d-dodeka-db-1 /bin/bash

# Dump all
pg_dumpall -p 3141 -U dodeka > upgrade_dump.sql

# Copy from old database to repl database
docker cp d-dodeka-db-1:/dodeka-db/upgrade_dump.sql d-dodeka_repl-db-1:/dodeka-db/upgrade_dump.sql

#
```