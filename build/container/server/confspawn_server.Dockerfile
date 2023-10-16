FROM python:3.11-slim-bookworm AS poetry
RUN python3 -m venv /opt/poetry
RUN /opt/poetry/bin/pip install poetry==1.6.1

FROM python:3.11-slim-bookworm AS poetry-install
COPY --from=poetry /opt/poetry /opt/poetry
ENV PATH="/opt/poetry/bin:${PATH}"
WORKDIR /dodeka/server
COPY poetry.lock .
COPY pyproject.toml .
RUN poetry install --only main --no-root
COPY ./src ./src
RUN poetry install --only-root
RUN rm ./src/apiserver/resources/static/.gitignore
COPY ./define.toml ./src/apiserver/resources/define.toml
COPY ./env.toml ./src/apiserver/resources/env.toml
RUN poetry build

FROM python:3.11-slim-bookworm AS runtime
ARG SERVER_ENV=/dodeka/server
ARG INSTALL_ENV=/dodeka/server
RUN python3 -m venv $SERVER_ENV
WORKDIR $SERVER_ENV
COPY --from=poetry-install $INSTALL_ENV/dist/apiserver-*.whl $SERVER_ENV/
RUN $SERVER_ENV/bin/pip install apiserver-*
COPY entrypoint.sh .
ENTRYPOINT ["./entrypoint.sh"]