

# "Provides the native-image executable. Used by the Maven and Gradle plugin from Quarkus to build linux64 executables"
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /app
# Image defaults to /project; copy controlled by .dockerignore
COPY --chown=quarkus:quarkus . ./
RUN ./mvnw package -DskipTests
RUN ls -R


FROM eclipse-temurin:21-jdk AS deploy

ENV LANGUAGE='en_US:en'

RUN mkdir /deployments


# We make four distinct layers so if there are application changes the library layers can be re-used
COPY --chown=185 --from=build /app/target/quarkus-app/app/quickstart-openshift-backends-1.0.0-SNAPSHOT.jar /deployments/quickstart-openshift-backends-1.0.0-SNAPSHOT.jar
COPY --chown=185 --from=build /app/target/quarkus-app/lib/ /deployments/lib/
COPY --chown=185 --from=build /app/target/quarkus-app/app/ /deployments/app/
COPY --chown=185 --from=build /app/target/quarkus-app/quarkus/ /deployments/quarkus/

EXPOSE 3000
HEALTHCHECK --interval=300s --timeout=3s CMD curl -f http://localhost:3000/ || exit 1
USER 185
ENV JAVA_OPTS_APPEND="-Dquarkus.http.host=0.0.0.0 -Djava.util.logging.manager=org.jboss.logmanager.LogManager"
CMD ["java", "-jar", "/deployments/quickstart-openshift-backends-1.0.0-SNAPSHOT.jar"]
