# confspawn is only run during actual deployment to account for different image version
FROM ~spwn@deps_image_name@~:latest AS install
COPY ./src ./src
RUN poetry install

FROM install as runtime
COPY ./entrypoint.sh .
ENTRYPOINT ["./entrypoint.sh"]