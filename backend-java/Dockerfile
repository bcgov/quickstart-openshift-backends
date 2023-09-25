FROM quay.io/quarkus/ubi-quarkus-graalvmce-builder-image:22.3.3-java17 AS build

USER quarkus
WORKDIR /code
COPY --chown=quarkus:quarkus mvnw pom.xml ./
COPY --chown=quarkus:quarkus .mvn /code/.mvn
COPY src /code/src

RUN ./mvnw -B org.apache.maven.plugins:maven-dependency-plugin:3.1.2:go-offline && \
    ./mvnw package -Pnative -DskipTests

###
FROM quay.io/quarkus/quarkus-micro-image:2.0
WORKDIR /work/
RUN chown 1001 /work \
    && chmod "g+rwX" /work \
    && chown 1001:root /work
COPY --chown=1001:root --from=build /code/target/*-runner /work/application

EXPOSE 3000
USER 1001
HEALTHCHECK --interval=300s --timeout=3s CMD curl -f http://localhost:3000/ || exit 1
CMD ["./application", "-Dquarkus.http.host=0.0.0.0"]
