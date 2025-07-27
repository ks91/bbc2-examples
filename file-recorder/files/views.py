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
        algo = record.get('algo')
        if isinstance(algo, int) and 0 <= algo < len(LIST_KEY_TYPES):
            record['signature-algorithm'] = LIST_KEY_TYPES[algo]
        record['date-time'] = str(datetime.fromtimestamp(
                record['timestamp']))

        aRecord.append((record['timestamp'], json.dumps(record, indent=2)))

    return render_template('files/records.html', records=aRecord)


@files.route('/verify', methods=['GET', 'POST'])
def verify():
    verifying = request.args.get('verifying') or request.form.get('verifying')
    if not verifying:
        return render_template('files/error.html', message='No record specified for verification.')
    dic = json.loads(verifying)

    dVer = None
    lTimeSigned = None
    # Use button name to distinguish certificate vs record verification
    if 'certificate' in request.args:
        lTime = int(request.args.get('time'))
        dParam = {
            'public_key': dic['pubkey'],
            'time': lTime
        }
        r = requests.get(PREFIX_REC_API + '/certificate', headers=HEADERS, data=json.dumps(dParam, indent=2))
        res = r.json()
        if r.status_code != 200:
            return render_template('files/error.html', message=json.dumps(res, indent=2))
        dVer = res
        lTimeSigned = res.get('issued_at')
    elif 'key' in dic and 'digest' in dic:
        rec_obj = Record.from_dict(dic)
        if rec_obj.sig:
            dVer = get_record_dict(rec_obj)
            lTimeSigned = dic.get('timestamp')
        else:
            # Forward traversal to checkpoint (BFS)
            from collections import deque
            visited = set()
            start_digest = binascii.b2a_hex(rec_obj.get_signed_data()).decode()
            queue = deque([start_digest])
            found_checkpoint = False
            while queue:
                current_digest = queue.popleft()
                if current_digest in visited:
                    continue
                visited.add(current_digest)
                dParam = {'digest': current_digest}
                r = requests.post(PREFIX_REC_API + '/forward', headers=HEADERS, data=json.dumps(dParam, indent=2))
                if r.status_code != 200:
                    return render_template('files/results.html', result=False, details='Forward search failed')
                forward_records = r.json().get('records', [])
                if not forward_records:
                    continue
                for fwd in forward_records:
                    fwd_obj = Record.from_dict(fwd)
                    if fwd_obj.sig:
                        dVer = get_record_dict(fwd_obj)
                        lTimeSigned = fwd.get('timestamp')
                        found_checkpoint = True
                        break
                    next_digest = binascii.b2a_hex(fwd_obj.get_signed_data()).decode()
                    if next_digest not in visited:
                        queue.append(next_digest)
                if found_checkpoint:
                    break
            if not found_checkpoint or dVer is None:
                return render_template('files/results.html', result=False, details='No checkpoint found')
    else:
        return render_template('files/error.html', message='Unknown verification type.')

    # Common: get document and digest
    document = get_document(dVer)
    digest = get_digest(document)
    dParam = {
        'digest': binascii.b2a_hex(digest).decode()
    }
    # Get proof from evidence service
    r = requests.get(PREFIX_EVI_API + '/proof', headers=HEADERS, data=json.dumps(dParam, indent=2))
    res = r.json()
    if r.status_code != 200:
        return render_template('files/error.html', message=json.dumps(res, indent=2))
    dVer['proof'] = res['proof']
    # Verify using certify-api
    r = requests.get(PREFIX_CERTIFY_API + '/verify', headers=HEADERS, data=json.dumps(dVer, indent=2))
    res = r.json()
    if r.status_code != 200:
        return render_template('files/error.html', message=json.dumps(res, indent=2))
    return render_template('files/results.html',
            evidence=json.dumps(dVer, indent=2),
            results=json.dumps(res, indent=2), signed_time=lTimeSigned,
            time='Evidence Stored At: {0}'.format(datetime.fromtimestamp(
            res['time'])))


# end of files/views.py
