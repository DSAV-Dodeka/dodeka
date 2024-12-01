FROM python:3.12-slim-bookworm AS uv
RUN python3 -m venv /opt/uv
RUN /opt/uv/bin/pip install uv==0.5.5

FROM python:3.12-slim-bookworm AS uv-install
COPY --from=uv /opt/uv /opt/uv
ENV PATH="/opt/uv/bin:${PATH}"
WORKDIR /dodeka/server
COPY uv.lock .
COPY pyproject.toml .
RUN uv sync --no-dev --frozen --no-install-project
COPY ./src ./src
# FIXME check if this actually achieves anything, we would want to only install the current project here
RUN uv sync --no-dev --frozen --no-editable
RUN rm ./src/apiserver/resources/static/.gitignore
COPY ./define.toml ./src/apiserver/resources/define.toml
COPY ./env.toml ./src/apiserver/resources/env.toml
RUN uv build --wheel

FROM python:3.12-slim-bookworm AS runtime
ARG SERVER_ENV=/dodeka/server
ARG INSTALL_ENV=/dodeka/server
RUN python3 -m venv $SERVER_ENV
WORKDIR $SERVER_ENV
COPY --from=uv-install $INSTALL_ENV/dist/apiserver-*.whl $SERVER_ENV/
RUN $SERVER_ENV/bin/pip install apiserver-*
COPY entrypoint.sh .
ENTRYPOINT ["./entrypoint.sh"]