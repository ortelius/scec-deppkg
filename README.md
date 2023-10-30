# Ortelius v11 Package Microservice
RestAPI for the package Object
![Release](https://img.shields.io/github/v/release/ortelius/scec-deppkg?sort=semver)
![license](https://img.shields.io/github/license/ortelius/scec-deppkg)

![Build](https://img.shields.io/github/actions/workflow/status/ortelius/scec-deppkg/build-push-chart.yml)
[![MegaLinter](https://github.com/ortelius/scec-deppkg/workflows/MegaLinter/badge.svg?branch=main)](https://github.com/ortelius/scec-deppkg/actions?query=workflow%3AMegaLinter+branch%3Amain)
![CodeQL](https://github.com/ortelius/scec-deppkg/workflows/CodeQL/badge.svg)
[![OpenSSF-Scorecard](https://api.securityscorecards.dev/projects/github.com/ortelius/scec-deppkg/badge)](https://api.securityscorecards.dev/projects/github.com/ortelius/scec-deppkg)

![Discord](https://img.shields.io/discord/722468819091849316)

## Version: 11.0.0

### Terms of service
<http://swagger.io/terms/>

**Contact information:**
Ortelius Google Group
ortelius-dev@googlegroups.com

**License:** [Apache 2.0](http://www.apache.org/licenses/LICENSE-2.0.html)

---
### /msapi/package

#### GET
##### Summary

Get a List of Packages

##### Description

Get a list of Packages.

##### Responses

| Code | Description |
|------|-------------|
| 200  | OK          |

---
### /msapi/package/:key

#### GET
##### Summary

Get a Package

##### Description

Get a package based on the _key or name.

##### Responses

| Code | Description |
|------|-------------|
| 200  | OK          |

---
### /msapi/sbom

#### POST
##### Summary

Upload an SBOM

##### Description

Create a new SBOM and persist it

##### Responses

| Code | Description |
|------|-------------|
| 200  | OK          |
