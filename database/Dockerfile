FROM ghcr.io/bcgov/nr-containers/postgres:15.5

# Health check and non-privileged user
HEALTHCHECK --interval=15s --timeout=5s --retries=3 CMD [ "pg_isready" ]
USER postgres
