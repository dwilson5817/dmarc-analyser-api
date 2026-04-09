import base64
import json
import os
from decimal import Decimal
from typing import Literal, Optional

import boto3
from boto3.dynamodb.conditions import Attr, Key
from fastapi import FastAPI, HTTPException, Query
from mangum import Mangum
from pydantic import BaseModel
from starlette.middleware.cors import CORSMiddleware


# --- Response models ---

class PingResponse(BaseModel):
    message: str


class DomainsResponse(BaseModel):
    domains: list[str]


class Report(BaseModel):
    report_id: str
    org_name: str
    org_email: str
    begin_date: int
    end_date: int
    policy: Literal["reject", "quarantine", "none"]
    adkim: Literal["r", "s"]
    aspf: Literal["r", "s"]
    subdomain_policy: Optional[Literal["reject", "quarantine", "none"]] = None
    pct: int


class ReportsResponse(BaseModel):
    items: list[Report]
    next_cursor: Optional[str] = None


class AuthResult(BaseModel):
    type: Literal["dkim", "spf"]
    result: Literal["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"]
    domain: str


class Record(BaseModel):
    source_ip: str
    count: int
    disposition: Literal["none", "quarantine", "reject"]
    dkim_aligned: Literal["pass", "fail"]
    spf_aligned: Literal["pass", "fail"]
    header_from: str
    auth_results: list[AuthResult]


class RecordsResponse(BaseModel):
    items: list[Record]

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://dmarc.dylanw.net",
        "http://localhost:5173"
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

_table = None


def get_table():
    global _table
    if _table is None:
        _table = boto3.resource('dynamodb').Table(os.environ['DYNAMODB_TABLE'])
    return _table


def convert_decimals(obj):
    if isinstance(obj, list):
        return [convert_decimals(i) for i in obj]
    elif isinstance(obj, dict):
        return {k: convert_decimals(v) for k, v in obj.items()}
    elif isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    return obj


def strip_keys(item: dict) -> dict:
    return {k: v for k, v in item.items() if k not in ('PK', 'SK')}


def encode_cursor(last_evaluated_key: dict) -> str:
    return base64.b64encode(json.dumps(last_evaluated_key).encode()).decode()


def decode_cursor(cursor: str) -> dict:
    try:
        return json.loads(base64.b64decode(cursor).decode())
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid cursor")


@app.get("/ping", response_model=PingResponse)
def ping():
    return {"message": "Pong!"}


@app.get("/domains", response_model=DomainsResponse)
def list_domains():
    table = get_table()
    response = table.get_item(Key={'PK': 'META', 'SK': 'DOMAINS'})
    item = response.get('Item')
    domains = sorted(item['domains']) if item else []
    return {'domains': domains}


@app.get("/domains/{domain}/reports", response_model=ReportsResponse)
def list_reports(
    domain: str,
    from_date: Optional[int] = Query(None, alias="from"),
    to_date: Optional[int] = Query(None, alias="to"),
    limit: int = Query(50, le=100),
    cursor: Optional[str] = None,
):
    table = get_table()
    kwargs = {
        'KeyConditionExpression': Key('PK').eq(f'DOMAIN#{domain}') & Key('SK').begins_with('REPORT#'),
        'Limit': limit,
        'ScanIndexForward': False,
    }

    filter_parts = []
    if from_date is not None:
        filter_parts.append(Attr('begin_date').gte(from_date))
    if to_date is not None:
        filter_parts.append(Attr('begin_date').lte(to_date))
    if filter_parts:
        fe = filter_parts[0]
        for part in filter_parts[1:]:
            fe = fe & part
        kwargs['FilterExpression'] = fe

    if cursor:
        kwargs['ExclusiveStartKey'] = decode_cursor(cursor)

    response = table.query(**kwargs)
    result = {'items': [strip_keys(convert_decimals(item)) for item in response['Items']]}
    if 'LastEvaluatedKey' in response:
        result['next_cursor'] = encode_cursor(response['LastEvaluatedKey'])
    return result


@app.get("/domains/{domain}/reports/{report_id}", response_model=Report)
def get_report(domain: str, report_id: str):
    table = get_table()
    kwargs = {
        'KeyConditionExpression': Key('PK').eq(f'DOMAIN#{domain}') & Key('SK').begins_with('REPORT#'),
        'FilterExpression': Attr('report_id').eq(report_id),
    }
    while True:
        response = table.query(**kwargs)
        if response['Items']:
            return strip_keys(convert_decimals(response['Items'][0]))
        if 'LastEvaluatedKey' not in response:
            break
        kwargs['ExclusiveStartKey'] = response['LastEvaluatedKey']
    raise HTTPException(status_code=404, detail="Report not found")


@app.get("/domains/{domain}/reports/{report_id}/records", response_model=RecordsResponse)
def list_records(domain: str, report_id: str):
    table = get_table()
    response = table.query(
        KeyConditionExpression=Key('PK').eq(f'REPORT#{report_id}') & Key('SK').begins_with('RECORD#'),
    )
    return {'items': [strip_keys(convert_decimals(item)) for item in response['Items']]}


handler = Mangum(app)
