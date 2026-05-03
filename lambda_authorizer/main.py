import json
import os
import urllib.error
import urllib.request

GITLAB_URL = os.environ['GITLAB_URL']

def handler(event, context):
    token = event.get('authorizationToken', '')
    if token.lower().startswith('bearer '):
        token = token[7:]
    arn = event['methodArn']

    # Build a wildcard ARN covering all resources on this API
    # methodArn format: arn:aws:execute-api:region:account:api-id/stage/method/resource
    arn_parts = arn.split(':')
    api_gateway_arn = arn_parts[5]
    api_id, stage = api_gateway_arn.split('/')[:2]
    wildcard_arn = f"arn:aws:execute-api:{arn_parts[3]}:{arn_parts[4]}:{api_id}/{stage}/*/*"

    try:
        req = urllib.request.Request(
            f'{GITLAB_URL}/oauth/userinfo',
            headers={'Authorization': f'Bearer {token}'}
        )
        with urllib.request.urlopen(req) as r:
            principal = json.loads(r.read()).get('sub', 'user')
        effect = 'Allow'
    except Exception:
        principal = 'unauthorized'
        effect = 'Deny'
        wildcard_arn = arn
    return {
        'principalId': principal,
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [{'Action': 'execute-api:Invoke', 'Effect': effect, 'Resource': wildcard_arn}]
        },
        'context': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Authorization,Content-Type',
        }
    }
