![DMARC Analyser logo](https://gitlab.dylanw.dev/uploads/-/system/group/avatar/14/dmarc-analyser-256px.png?width=96)

# DMARC Analyser API

[![Pipeline status](https://gitlab.dylanw.dev/dmarc-analyser/api/badges/main/pipeline.svg)](https://gitlab.dylanw.dev/dmarc-analyser/api/-/commits/main)

DMARC Analyser is an AWS Lambda-based DMARC report ingestion pipeline.  The API is a FastAPI application served via
Lambda and API Gateway, available at [api.dmarc.dylanw.net](https://api.dmarc.dylanw.net).

It exposes endpoints to query the DMARC reports and records stored in DynamoDB, and is protected by a Lambda authorizer
that validates GitLab OAuth tokens.

## Development

### API Handler

The following environment variables are required:

| Variable         | Description                      |
|------------------|----------------------------------|
| `DYNAMODB_TABLE` | The name of the DynamoDB table   |

Install the dependencies:

```bash
pip install -r api_handler/requirements.txt
```

### GitLab Authorizer

The following environment variables are required:

| Variable      | Description              |
|---------------|--------------------------|
| `GITLAB_URL`  | The base URL of GitLab   |

Install the dependencies:

```bash
pip install -r gitlab_authorizer/requirements.txt
```

## Deployment

This project uses the `python-lambda-build` and `python-lambda-upload` CI/CD components from
[cdk-deployment-base](https://gitlab.dylanw.dev/infrastructure/cdk-deployment-base) to build and upload the Lambda
function artifacts.  On the `main` branch, a deployment of the
[dmarc-analyser/cdk](https://gitlab.dylanw.dev/dmarc-analyser/cdk) project is triggered to apply any infrastructure
changes.

## License

This application is licensed under the GNU General Public License v3.0 or later.

```
DMARC Analyser - A Lambda-based DMARC report ingestion pipeline.
Copyright (C) 2026  Dylan Wilson

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```
