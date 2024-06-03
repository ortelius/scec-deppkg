# Ortelius v11 Package Microservice

> Version 11.0.0

RestAPI for the package Object
![Release](https://img.shields.io/github/v/release/ortelius/scec-deppkg?sort=semver)
![license](https://img.shields.io/github/license/ortelius/.github)

![Build](https://img.shields.io/github/actions/workflow/status/ortelius/scec-deppkg/build-push-chart.yml)
[![MegaLinter](https://github.com/ortelius/scec-deppkg/workflows/MegaLinter/badge.svg?branch=main)](https://github.com/ortelius/scec-deppkg/actions?query=workflow%3AMegaLinter+branch%3Amain)
![CodeQL](https://github.com/ortelius/scec-deppkg/workflows/CodeQL/badge.svg)
[![OpenSSF-Scorecard](https://api.securityscorecards.dev/projects/github.com/ortelius/scec-deppkg/badge)](https://api.securityscorecards.dev/projects/github.com/ortelius/scec-deppkg)

![Discord](https://img.shields.io/discord/722468819091849316)

## Path Table

| Method | Path                                       | Description            |
|--------|--------------------------------------------|------------------------|
| GET    | [/msapi/package](#getmsapipackage)         | Get a List of Packages |
| GET    | [/msapi/package/:key](#getmsapipackagekey) | Get a Package          |
| POST   | [/msapi/provenance](#postmsapiprovenance)  | Upload Provenance JSON |
| POST   | [/msapi/sbom](#postmsapisbom)              | Upload an SBOM         |

## Reference Table

| Name | Path | Description |
| --- | --- | --- |

## Path Details

***

### [GET]/msapi/package

- Summary
Get a List of Packages

- Description
Get a list of Packages.

#### Responses

- 200 OK

***

### [GET]/msapi/package/:key

- Summary
Get a Package

- Description
Get a package based on the _key or name.

#### Responses

- 200 OK

***

### [POST]/msapi/provenance

- Summary
Upload Provenance JSON

- Description
Create a new Provenance and persist it

#### Responses

- 200 OK

***

### [POST]/msapi/sbom

- Summary
Upload an SBOM

- Description
Create a new SBOM and persist it

#### Responses

- 200 OK

## References
