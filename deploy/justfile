pull env env_file profile:
    docker compose -f use/{{env}}/docker-compose.yml --env-file use/{{env}}/{{env_file}}.env --profile {{profile}} pull

up env env_file profile: (pull env env_file profile)
    docker compose -f use/{{env}}/docker-compose.yml --env-file use/{{env}}/{{env_file}}.env --profile {{profile}} up -d

down env env_file profile:
    docker compose -f use/{{env}}/docker-compose.yml --env-file use/{{env}}/{{env_file}}.env --profile {{profile}} down

updevp: (up "dev" "dev_port" "data")

downdevp: (down "dev" "dev_port" "data")

updev: (up "dev" "dev" "data")

downdev: (down "dev" "dev" "data")

deploy env tag:
    tidploy deploy {{env}} {{tag}}

deploydown env tag_repl:
    docker compose -p dodeka-{{env}}-{{tag_repl}} down