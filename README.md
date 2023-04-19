# cyhy-kevsync-lambda #

[![GitHub Build Status](https://github.com/cisagov/cyhy-kevsync-lambda/workflows/build/badge.svg)](https://github.com/cisagov/cyhy-kevsync-lambda/actions)

This Lambda is designed to retrieve the [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
[JSON version](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json)
and import the CVE IDs into a MongoDB collection.

## Lambda configuration ##

This Lambda supports the following Lambda environment variables in its
deployment configuration:

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | -------- |
| json\_url | The URL for the JSON to be processed. | `string` | `"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"` | no |
| log\_level | The logging level for the Lambda. | `string` | `"INFO"` | no |
| ssm\_db\_authdb | The AWS SSM Parameter Store key that contains the authorization database to use for the MongoDB connection. | `string` | n/a | yes |
| ssm\_db\_collection | The AWS SSM Parameter Store key that contains the MongoDB collection to write to in the MongoDB database. | `string` | The default collection is used if this variable is not provided. | no |
| ssm\_db\_host | The AWS SSM Parameter Store key that contains the hostname for the database to use for the MongoDB connection. | `string` | n/a | yes |
| ssm\_db\_pass | The AWS SSM Parameter Store key that contains the password for authenticating to the database to use for the MongoDB connection. | `string` | n/a | yes |
| ssm\_db\_port | The AWS SSM Parameter Store key that contains the port for the database to use for the MongoDB connection. | `string` | n/a | yes |
| ssm\_db\_user | The AWS SSM Parameter Store key that contains the username for authenticating to the database to use for the MongoDB connection. | `string` | n/a | yes |
| ssm\_db\_writedb | The AWS SSM Parameter Store key that contains the logical database to write to on the database. | `string` | The value of the `ssm_db_authdb` variable. | no |

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

## Running the Lambda locally ##

The configuration in this repository allows you run the Lambda locally for
testing as long as you do not need explicit permissions for other AWS
services. This can be done with the following command:

```console
docker compose up --detach run_lambda_locally
```

You can then invoke the Lambda using the following:

```console
 curl -XPOST "http://localhost:9000/2015-03-31/functions/function/invocations" -d '{}'
```

The `{}` in the command is the invocation event payload to send to the Lambda
and would be the value given as the `event` argument to the handler.

Once you are finished you can stop the detached container with the following command:

```console
docker compose down
```

## How to update Python dependencies ##

The Python dependencies are maintained using a [Pipenv](https://github.com/pypa/pipenv)
configuration for each supported Python version. Changes to requirements
should be made to the respective `src/py<Python version>/Pipfile`. More
information about the `Pipfile` format can be found [here](https://pipenv.pypa.io/en/latest/basics/#example-pipfile-pipfile-lock).
The accompanying `Pipfile.lock` files contain the specific dependency versions
that will be installed. These files can be updated like so (using the Python
3.9 configuration as an example):

```console
cd src/py3.9
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
