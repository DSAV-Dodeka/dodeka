# confspawn is only run during actual deployment to account for different image version
FROM {{ server.deps_image_name }}:{{ server.version }} AS install
COPY ./src ./src
RUN poetry install

FROM install as runtime
COPY ./entrypoint.sh .
ENTRYPOINT ["./entrypoint.sh"]