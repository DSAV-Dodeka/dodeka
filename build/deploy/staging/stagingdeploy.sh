# by default it will recreate the database
if [ "$1" = "update" ]
then
  export RECREATE=no
else
  export RECREATE=yes
fi

docker compose --env-file staging.env --profile all pull
docker compose --env-file staging.env --profile all up -d