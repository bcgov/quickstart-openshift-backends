FROM flyway/flyway:11-alpine@sha256:e5c941be8cda7f641cdd80f267bc45297fb6d04ea9275f60d408cd4ba4f52354

# Non-root user
RUN adduser -D app
USER app

# Copy migrations
COPY ./migrations /flyway/sql
HEALTHCHECK --interval=300s --timeout=30s CMD info || exit 1
# Startup
CMD ["info","migrate","info"]
