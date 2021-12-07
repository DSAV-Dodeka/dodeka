FROM postgres:14-bullseye
ADD postgresql.conf /dodeka_conf/postgresql.conf
ADD pg_hba.conf /dodeka_conf/pg_hba.conf
ADD barman.sh docker-entrypoint-initdb.d/barman.sh
ADD barman.sql /dodeka_init/barman.sql
