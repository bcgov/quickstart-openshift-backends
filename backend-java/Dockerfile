# Quarkus Images
# https://github.com/quarkusio/quarkus-images

# "Provides the native-image executable. Used by the Maven and Gradle plugin from Quarkus to build linux64 executables"
FROM quay.io/quarkus/ubi-quarkus-graalvmce-builder-image:jdk-23 AS build

# Image defaults to /project; copy controlled by .dockerignore
COPY --chown=quarkus:quarkus . ./
RUN ./mvnw package -Pnative -DskipTests

# "A base image to run Quarkus native application using UBI Micro"
FROM quay.io/quarkus/quarkus-micro-image:2.0@sha256:ec55f7e85b02c74a152a7474105e142a4c719184bf79aa19f743aec10e2b6cc1

# Port and health check
EXPOSE 3000
HEALTHCHECK --interval=300s --timeout=3s CMD curl -f http://localhost:3000/ || exit 1

# Startup
COPY --chown=1001:root --from=build /project/target/*-runner /app
USER 1001
CMD ["/app", "-Dquarkus.http.host=0.0.0.0"]
