# -*- coding: utf-8 -*-
"""
Copyright (c) 2024 beyond-blockchain.org.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import base64
import bbclib
import binascii
import hashlib
import json
import os
import requests
import string
import sys
import time
from bbc2.lib.support_lib import BYTELEN_BIT256
from datetime import datetime, timedelta, timezone
from flask import Blueprint, render_template, request, session, abort, jsonify

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from recorder_tool import LIST_KEY_TYPES, Record
from recorder_tool import get_digest, get_document, get_record_dict


# Put API host names here.
PREFIX_CERTIFY_API = 'http://localhost:9000/certify-api'
PREFIX_EVI_API = 'http://localhost:5000/evi-api'
PREFIX_REC_API = 'http://localhost:5000/rec-api'


HEADERS = {'Content-Type': 'application/json'}


# Put your timezone here.
ISO_TIMEZONE = ':00+09:00'


files = Blueprint('files', __name__, template_folder='templates',
        static_folder='./static')


def get_signed_16bit_value(x):
    if x > 0x7fff:
        x = ~(x ^ 0xffff)
    return x


def make_400_error(s):
    return {'error': {
        'code': 400,
        'name': 'Bad Request',
        'description': s,
    }}


@files.route('/')
def index():
    return render_template('files/index.html')


@files.route('/search', methods=['GET'])
def search_records():
    timeFrom = request.args.get('timefrom')
    timeTo = request.args.get('timeto')

    print('timeFrom: {0}'.format(timeFrom))
    print('timeTo: {0}'.format(timeTo))

    if len(timeFrom) <= 0 or len(timeTo) <= 0:
        return render_template('files/error.html',
                message='From and/or To is not specified.')

    dt = datetime.fromisoformat(timeFrom + ISO_TIMEZONE)
    lTimeFrom = int(dt.timestamp())
    dt = datetime.fromisoformat(timeTo + ISO_TIMEZONE)
    lTimeTo = int(dt.timestamp())

    dParam = {
        'timefrom': lTimeFrom,
        'timeto': lTimeTo
    }

    r = requests.get(PREFIX_REC_API + '/records', headers=HEADERS,
            data=json.dumps(dParam, indent=2))
    res = r.json()

    if r.status_code != 200:
        return render_template('files/error.html',
                message=json.dumps(res, indent=2))

    aRecord = []
    for record in res['records']:
        record['signature-algorithm'] = LIST_KEY_TYPES[record['algo']]
        record['date-time'] = str(datetime.fromtimestamp(
                record['timestamp']))

        aRecord.append((record['timestamp'], json.dumps(record, indent=2)))

    return render_template('files/records.html', records=aRecord)


@files.route('/verify', methods=['GET'])
def verify():
    verifying = request.args.get('verifying')

    dic = json.loads(verifying)

    if 'record' in request.args:
        record = Record.from_dict(dic)
        dVer = get_record_dict(record)
        lTimeSigned = dic['timestamp']

    elif 'certificate' in request.args:
        lTime = int(request.args.get('time'))

        dParam = {
            'public_key': dic['pubkey'],
            'time': lTime
        }

        r = requests.get(PREFIX_REC_API + '/certificate', headers=HEADERS,
                data=json.dumps(dParam, indent=2))
        res = r.json()

        if r.status_code != 200:
            return render_template('files/error.html',
                    message=json.dumps(res, indent=2))

        dVer = res
        lTimeSigned = res['issued_at']

    else:
        return render_template('files/error.html',
                message='button name is not recognized.')

    document = get_document(dVer)
    dParam = {
        'digest': bbclib.convert_id_to_string(get_digest(document),
                bytelen=BYTELEN_BIT256)
    }

    r = requests.get(PREFIX_EVI_API + '/proof', headers=HEADERS,
        data=json.dumps(dParam, indent=2))
    res = r.json()

    if r.status_code != 200:
        return render_template('files/error.html',
                message=json.dumps(res, indent=2))

    dVer['proof'] = res['proof']

    r = requests.get(PREFIX_CERTIFY_API + '/verify', headers=HEADERS,
            data=json.dumps(dVer, indent=2))
    res =r.json()

    if r.status_code != 200:
        return render_template('files/error.html',
                message=json.dumps(res, indent=2))

    return render_template('files/results.html',
            evidence=json.dumps(dVer, indent=2),
            results=json.dumps(res, indent=2), signed_time=lTimeSigned,
            time='Evidence Stored At: {0}'.format(datetime.fromtimestamp(
            res['time'])))


# end of files/views.py
