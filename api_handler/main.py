import base64
import json
import os
from decimal import Decimal
from datetime import datetime
from typing import Literal, Optional

import boto3
from boto3.dynamodb.conditions import Key
from fastapi import FastAPI, HTTPException, Query
from mangum import Mangum
from pydantic import BaseModel
from starlette.middleware.cors import CORSMiddleware


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
    next_cursor: Optional[str] = None


class StatsByDate(BaseModel):
    date: str
    passed: int
    failed: int


class StatsByDomain(BaseModel):
    domain: str
    reports: int


class StatsResponse(BaseModel):
    by_date: list[StatsByDate]
    by_domain: list[StatsByDomain]


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
    from_date: Optional[datetime] = Query(None, alias="from"),
    to_date: Optional[datetime] = Query(None, alias="to"),
    limit: int = Query(50, le=100),
    cursor: Optional[str] = None,
):
    table = get_table()
    from_ts = int(from_date.timestamp()) if from_date is not None else None
    to_ts = int(to_date.timestamp()) if to_date is not None else None

    if from_ts is not None and to_ts is not None:
        sk_condition = Key('SK').between(f'REPORT#{from_ts}', f'REPORT#{to_ts}#~')
    elif from_ts is not None:
        sk_condition = Key('SK').gte(f'REPORT#{from_ts}')
    elif to_ts is not None:
        sk_condition = Key('SK').between('REPORT#', f'REPORT#{to_ts}#~')
    else:
        sk_condition = Key('SK').begins_with('REPORT#')

    kwargs = {
        'KeyConditionExpression': Key('PK').eq(f'DOMAIN#{domain}') & sk_condition,
        'Limit': limit,
        'ScanIndexForward': False,
    }

    if cursor:
        kwargs['ExclusiveStartKey'] = decode_cursor(cursor)

    response = table.query(**kwargs)
    result = {'items': [strip_keys(convert_decimals(item)) for item in response['Items']]}
    if 'LastEvaluatedKey' in response:
        result['next_cursor'] = encode_cursor(response['LastEvaluatedKey'])
    return result


@app.get("/domains/{domain}/reports/{org_name}/{begin_date}/{report_id}", response_model=Report)
def get_report(domain: str, org_name: str, begin_date: int, report_id: str):
    table = get_table()
    response = table.get_item(
        Key={'PK': f'DOMAIN#{domain}', 'SK': f'REPORT#{begin_date}#{org_name}#{report_id}'}
    )
    item = response.get('Item')
    if item is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return strip_keys(convert_decimals(item))


@app.get("/domains/{domain}/reports/{org_name}/{begin_date}/{report_id}/records", response_model=RecordsResponse)
def list_records(domain: str, org_name: str, begin_date: int, report_id: str, limit: int = Query(50, le=100), cursor: Optional[str] = None):
    table = get_table()
    kwargs = {
        'KeyConditionExpression': Key('PK').eq(f'REPORT#{begin_date}#{org_name}#{report_id}') & Key('SK').begins_with('RECORD#'),
        'Limit': limit,
    }
    if cursor:
        kwargs['ExclusiveStartKey'] = decode_cursor(cursor)
    response = table.query(**kwargs)
    result = {'items': [strip_keys(convert_decimals(item)) for item in response['Items']]}
    if 'LastEvaluatedKey' in response:
        result['next_cursor'] = encode_cursor(response['LastEvaluatedKey'])
    return result


@app.get("/stats", response_model=StatsResponse)
def get_stats(
    from_date: Optional[datetime] = Query(None, alias="from"),
    to_date: Optional[datetime] = Query(None, alias="to"),
):
    table = get_table()

    meta = table.get_item(Key={'PK': 'META', 'SK': 'DOMAINS'})
    domains = sorted(meta.get('Item', {}).get('domains', []))

    from_ts = int(from_date.timestamp()) if from_date is not None else None
    to_ts = int(to_date.timestamp()) if to_date is not None else None

    if from_ts is not None and to_ts is not None:
        sk_condition = Key('SK').between(f'REPORT#{from_ts}', f'REPORT#{to_ts}#~')
    elif from_ts is not None:
        sk_condition = Key('SK').gte(f'REPORT#{from_ts}')
    elif to_ts is not None:
        sk_condition = Key('SK').between('REPORT#', f'REPORT#{to_ts}#~')
    else:
        sk_condition = Key('SK').begins_with('REPORT#')

    by_date: dict[str, dict[str, int]] = {}
    by_domain_counts: list[dict] = []

    for domain in domains:
        reports: list[dict] = []
        kwargs: dict = {
            'KeyConditionExpression': Key('PK').eq(f'DOMAIN#{domain}') & sk_condition,
        }
        while True:
            resp = table.query(**kwargs)
            reports.extend(convert_decimals(resp['Items']))
            if 'LastEvaluatedKey' not in resp:
                break
            kwargs['ExclusiveStartKey'] = resp['LastEvaluatedKey']

        by_domain_counts.append({'domain': domain, 'reports': len(reports)})

        for report in reports:
            begin_date = report['begin_date']
            org_name = report['org_name']
            report_id = report['report_id']
            date_str = datetime.utcfromtimestamp(begin_date).strftime('%Y-%m-%d')

            if date_str not in by_date:
                by_date[date_str] = {'passed': 0, 'failed': 0}

            rec_kwargs: dict = {
                'KeyConditionExpression': Key('PK').eq(f'REPORT#{begin_date}#{org_name}#{report_id}') & Key('SK').begins_with('RECORD#'),
            }
            while True:
                rec_resp = table.query(**rec_kwargs)
                for rec in convert_decimals(rec_resp['Items']):
                    if rec['dkim_aligned'] == 'pass' or rec['spf_aligned'] == 'pass':
                        by_date[date_str]['passed'] += rec['count']
                    else:
                        by_date[date_str]['failed'] += rec['count']
                if 'LastEvaluatedKey' not in rec_resp:
                    break
                rec_kwargs['ExclusiveStartKey'] = rec_resp['LastEvaluatedKey']

    by_date_list = [
        {'date': date, 'passed': counts['passed'], 'failed': counts['failed']}
        for date, counts in sorted(by_date.items())
    ]
    by_domain_list = sorted(
        [d for d in by_domain_counts if d['reports'] > 0],
        key=lambda x: x['reports'],
        reverse=True,
    )

    return {'by_date': by_date_list, 'by_domain': by_domain_list}


handler = Mangum(app)
