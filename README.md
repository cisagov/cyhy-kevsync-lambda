# cyhy-kevsync-lambda #

[![GitHub Build Status](https://github.com/cisagov/cyhy-kevsync-lambda/workflows/build/badge.svg)](https://github.com/cisagov/cyhy-kevsync-lambda/actions)
[![License](https://img.shields.io/github/license/cisagov/cyhy-kevsync-lambda)](https://spdx.org/licenses/)
[![CodeQL](https://github.com/cisagov/cyhy-kevsync-lambda/workflows/CodeQL/badge.svg)](https://github.com/cisagov/cyhy-kevsync-lambda/actions/workflows/codeql-analysis.yml)

This Lambda is designed to retrieve the [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
[JSON version](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json)
and import the CVE IDs into a MongoDB collection.

## Lambda configuration ##

This Lambda supports the following Lambda environment variables in its
deployment configuration:

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | -------- |
| `CYHY_CONFIG_PATH` | The path to the configuration file. | `string` | The default search behavior is used if this variable is not provided. | no |
| `CYHY_CONFIG_SSM_PATH` | The AWS SSM Parameter Store key that contains the configuration file. | `string` | SSM will not be accessed if this variable is not provided. | no |
| `CYHY_LOG_LEVEL` | The logging level for the Lambda. | `string` | `INFO` | no |

## Building the base Lambda image ##

The base Lambda image can be built with the following command:

```console
docker compose build
```

This base image is used both to build a deployment package and to run the
Lambda locally.

## Building a deployment package ##

You can build a deployment zip file to use when creating a new AWS Lambda
function with the following command:

```console
docker compose up build_deployment_package
```

This will output the deployment zip file in the root directory.

## Testing the Lambda locally ##

Create a configuration file named `cyhy-mine.toml` in the repository root with
the following content:

```toml
[kevsync]
db_auth_uri = "mongodb://username:password@host.docker.internal:27018/cyhy"
db_name = "cyhy"
json_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
log_level = "DEBUG"
schema_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json"
```

Start the Lambda locally with the following command:

```console
docker compose up run_lambda_locally
```

The Lambda can be invoked by sending a POST request to the local endpoint:

```console
curl "http://localhost:9000/2015-03-31/functions/function/invocations" \
     --data '{}'
```

## How to update Python dependencies ##

The Lambda's Python dependencies are maintained using a [Pipenv](https://github.com/pypa/pipenv)
configuration. Changes to requirements should be made to the `Pipfile` located at
`build/Pipfile`. More information about the `Pipfile` format can be found in the
[`pipenv` documentation](https://pipenv.pypa.io/en/latest/pipfile.html#example-pipfile).
The accompanying `Pipfile.lock` file contains the specific dependency versions
that will be installed. This file is updated automatically like so:

```console
cd build
pipenv lock
```

## Contributing ##

We welcome contributions!  Please see [`CONTRIBUTING.md`](CONTRIBUTING.md) for
details.

## License ##

This project is in the worldwide [public domain](LICENSE).

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain
dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
dedication. By submitting a pull request, you are agreeing to comply
with this waiver of copyright interest.
