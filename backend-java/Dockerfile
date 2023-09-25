# Build Quarkus native image
FROM quay.io/quarkus/ubi-quarkus-graalvmce-builder-image:22.3.3-java17 AS build

WORKDIR /code
COPY --chown=quarkus:quarkus mvnw pom.xml ./
COPY --chown=quarkus:quarkus .mvn .mvn
COPY src src
RUN ./mvnw package -Pnative -DskipTests

# Copy into Quarkus runner
FROM quay.io/quarkus/quarkus-micro-image:2.0

# Default destination
COPY --chown=1001:root --from=build /code/target/*-runner /work/application

# Port and health check
EXPOSE 3000
HEALTHCHECK --interval=300s --timeout=3s CMD curl -f http://localhost:3000/ || exit 1

# Startup
USER 1001
CMD ["./application", "-Dquarkus.http.host=0.0.0.0"]
