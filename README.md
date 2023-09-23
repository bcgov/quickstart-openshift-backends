[![MIT License](https://img.shields.io/github/license/bcgov/quickstart-openshift-backends.svg)](/LICENSE.md)
[![Lifecycle](https://img.shields.io/badge/Lifecycle-Experimental-339999)](https://github.com/bcgov/repomountie/blob/master/doc/lifecycle-badges.md)
[![Merge](https://github.com/bcgov/quickstart-openshift-backends/actions/workflows/merge.yml/badge.svg)](https://github.com/bcgov/quickstart-openshift/actions/workflows/merge.yml)
[![Analysis](https://github.com/bcgov/quickstart-openshift-backends/actions/workflows/analysis.yml/badge.svg)](https://github.com/bcgov/quickstart-openshift/actions/workflows/analysis.yml)

# QuickStart: Pluggable Backends

## OpenShift, Go, Java, Python

These are pluggable backends intended for use with the [QuickStart for Openshift](https://github.com/bcgov/quickstart-openshift-backends), which defaults to JavaScript/TypeScripts.  They follow the same patterns and can be copied over.

* Pluggable backends:
    * Backend: Java, Quarkus, Cloud Native
    * Backend: Go, Fiber
    * Backend: Python, FastAPI

# Sample Application

The starter stack includes a (React, MUI, Vite, Caddy) frontend, Pluggable backend(Nest/Node, Quarkus/Java On Native, FastAPI/Python, Fiber/Golang) and postgres database.  See subfolder for source, including Dockerfiles and OpenShift templates.

Features:
* [TypeScript](https://www.typescriptlang.org/) strong-typing for JavaScript
* [NestJS](https://docs.nestjs.com) Nest/Node backend
* [Quarkus](https://quarkus.io/) Quarkus/Java On Native backend
* [FastAPI](https://fastapi.tiangolo.com/) FastAPI/Python backend
* [Fiber](https://gofiber.io/) Fiber/Golang backend
* [Postgres](https://www.postgresql.org/) or [PostGIS](https://postgis.net/) database
* [backup-container](https://github.com/BCDevOps/backup-container) provided by BCDevOps

# Acknowledgements

This Action is provided courtesy of the Forestry Suite of Applications, part of the Government of British Columbia.
