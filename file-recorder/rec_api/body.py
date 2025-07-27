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
import bbclib
import datetime
import hashlib
import json
import os
import string
import sys
import time
from bbc2.lib.data_store_lib import Database
from flask import Blueprint, request, abort, jsonify, g
import binascii
import random

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from recorder_tool import get_certificate_dict, Location, Record


MAX_TIME = (2 ** 63) - 1


NAME_OF_DB = 'rec_db'

LOSS_PROBABILITY = 0.0
PROTECT_CHECKPOINTS = True  # Set to False to allow checkpoints to be lost  # chance a record is marked as lost

record_table_definition = [
    ["key", "INTEGER"],
    ["filename", "TEXT"],
    ["digest", "BLOB"],
    ["timestamp", "INTEGER"],
    ["latitude", "TEXT"],
    ["longitude", "TEXT"],
    ["altitude", "TEXT"],
    ["algo", "INTEGER"],
    ["sig", "BLOB"],
    ["pubkey", "BLOB"],
    ["prev_digest", "BLOB"],
    ["skip_digests", "TEXT"],  # JSON
    ["is_lost", "BOOLEAN"],
]

IDX_KEY       = 0
IDX_FILENAME  = 1
IDX_DIGEST    = 2
IDX_TIMESTAMP = 3
IDX_LATITUDE  = 4
IDX_LONGITUDE = 5
IDX_ALTITUDE  = 6
IDX_ALGO      = 7
IDX_SIG       = 8
IDX_PUBKEY    = 9
IDX_PREV_DIGEST = 10
IDX_SKIP_DIGESTS = 11
IDX_IS_LOST = 12


domain_id = bbclib.get_new_id("file_recorder_domain", include_timestamp=False)


class Store:

    def __init__(self):
        self.db = Database()
        self.db.setup_db(domain_id, NAME_OF_DB)


    def close(self):
        try:
            self.db.close_db(domain_id, NAME_OF_DB)
        except KeyError:
            pass


    def read_records(self, time_from=0, time_to=MAX_TIME):
        rows = self.db.exec_sql(
            domain_id,
            NAME_OF_DB,
            'select * from record_table where ' +
                    'timestamp>=? and timestamp<=?',
            time_from,
            time_to
        )
        aRecord = []
        for row in rows:
            if row[IDX_IS_LOST]:
                print(f"[DEBUG] Skipped lost record: filename={row[IDX_FILENAME]}, timestamp={row[IDX_TIMESTAMP]}")
                continue
            aRecord.append(get_record_from_row(row))
        return aRecord


    def setup(self):
        self.db.create_table_in_db(domain_id, NAME_OF_DB, 'record_table',
                record_table_definition,
                indices=[IDX_TIMESTAMP, IDX_DIGEST])


    def write_record(self, record):
        # Serialize skip_digests as JSON
        skip_digests_json = json.dumps([
            binascii.b2a_hex(d).decode() if d else None 
            for d in record.skip_digests
        ]) if record.skip_digests else None
        is_lost = random.random() < LOSS_PROBABILITY
        
        # Protect checkpoints from being lost if PROTECT_CHECKPOINTS is True
        if PROTECT_CHECKPOINTS and record.sig:
            is_lost = False
        self.db.exec_sql(
            domain_id,
            NAME_OF_DB,
            'insert into record_table values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            record.key,
            record.filename,
            record.digest,
            record.timestamp,
            record.location.latitude,
            record.location.longitude,
            record.location.altitude,
            record.algo,
            record.sig,
            record.pubkey,
            record.prev_digest,
            skip_digests_json,
            is_lost
        )

    def get_records_by_prev_digest(self, digest):
        # Returns all records where prev_digest or skip_digests contains the given digest
        digest_hex = binascii.b2a_hex(digest).decode()
        rows = self.db.exec_sql(
            domain_id,
            NAME_OF_DB,
            'select * from record_table where prev_digest=? or skip_digests like ?',
            digest,
            f'%{digest_hex}%'
        )
        aRecord = []
        added_records = set()  # Track added records to avoid duplicates
        prev_count = 0
        skip_count = 0
        
        for row in rows:
            if row[IDX_IS_LOST]:
                print(f"[DEBUG] Skipped lost record: filename={row[IDX_FILENAME]}, timestamp={row[IDX_TIMESTAMP]}")
                continue
            
            record = get_record_from_row(row)
            record_key = (record.key, record.filename, record.timestamp)
            
            if record_key in added_records:
                continue  # Skip if already added
            
            # prev_digest check (binary)
            if row[IDX_PREV_DIGEST] == digest:
                aRecord.append(record)
                added_records.add(record_key)
                prev_count += 1
                continue
            # skip_digests check (JSON, exact match)
            skip_digests = []
            if row[IDX_SKIP_DIGESTS]:
                try:
                    skip_digests_hex = json.loads(row[IDX_SKIP_DIGESTS])
                    skip_digests = [d for d in skip_digests_hex if d == digest_hex]
                except (json.JSONDecodeError, binascii.Error):
                    skip_digests = []
            if skip_digests:
                aRecord.append(record)
                added_records.add(record_key)
                skip_count += 1
        
        # Remove debug output for normal operation
        pass
        
        return aRecord


def abort_by_bad_content_type(content_type):
    abort(400, description='Content-Type {0} is not expected'.format(
            content_type))


def abort_by_bad_json_format():
    abort(400, description='Bad JSON format')


def abort_by_certificate_out_of_date():
    abort(404, description='Certificate is out of date')


def abort_by_missing_certificate():
    abort(404, description='Certificate is not found')


def abort_by_missing_param(param):
    abort(400, description='{0} is missing'.format(param))


def get_record_from_row(row):
    # Restore skip_digests from JSON format
    skip_digests = []
    if row[IDX_SKIP_DIGESTS]:
        try:
            skip_digests_hex = json.loads(row[IDX_SKIP_DIGESTS])
            skip_digests = [
                binascii.a2b_hex(d) if d else None 
                for d in skip_digests_hex
            ]
        except (json.JSONDecodeError, binascii.Error):
            skip_digests = []
    
    t = (
        row[IDX_KEY],
        row[IDX_FILENAME],
        row[IDX_DIGEST],
        row[IDX_TIMESTAMP],
        Location(row[IDX_LATITUDE], row[IDX_LONGITUDE], row[IDX_ALTITUDE]),
        row[IDX_ALGO],
        row[IDX_SIG],
        row[IDX_PUBKEY],
        row[IDX_PREV_DIGEST],
        skip_digests,
    )
    return Record.from_tuple(t)


rec_api = Blueprint('rec_api', __name__)


@rec_api.after_request
def after_request(response):
    g.store.close()

    return response


@rec_api.before_request
def before_request():
    g.store = Store()


@rec_api.route('/')
def index():
    return jsonify({})


@rec_api.route('/certificate', methods=['GET'])
def get_certificate():
    if request.headers['Content-Type'] != 'application/json':
        abort_by_bad_content_type(request.headers['Content-Type'])

    public_key = request.json.get('public_key')
    lTime = request.json.get('time')

    files = os.listdir()

    isFound = False

    for fn in files:
        if fn.endswith('.json'):
            f = open(fn, 'r')
            dic = json.load(f)
            f.close()

            vdic = dic['vendor']
            if vdic['public_key'] == public_key:
                isFound = True
                if vdic['issued_at'] <= lTime and lTime < vdic['expires_at']:
                    return jsonify(get_certificate_dict(vdic, vdic))
            else:
                for d in dic['recorders']:
                    if d['public_key'] == public_key:
                        isFound = True
                        if d['issued_at'] <= lTime and lTime < d['expires_at']:
                            return jsonify(get_certificate_dict(d, vdic))

    if isFound:
        abort_by_certificate_out_of_date()

    abort_by_missing_certificate()


@rec_api.route('/record', methods=['POST'])
def post_record():
    if request.headers['Content-Type'] != 'application/json':
        abort_by_bad_content_type(request.headers['Content-Type'])

    record = Record.from_dict(request.get_json())
    g.store.write_record(record)

    return jsonify({
        'success': 'true'
    })


@rec_api.route('/records', methods=['GET'])
def get_records():
    if request.headers['Content-Type'] != 'application/json':
        abort_by_bad_content_type(request.headers['Content-Type'])

    lTimeFrom = request.json.get('timefrom')
    lTimeTo = request.json.get('timeto')

    aRecord = g.store.read_records(time_from=lTimeFrom, time_to=lTimeTo)

    adRecord = []
    for record in aRecord:
        adRecord.append(record.to_dict())

    return jsonify({
        'records': adRecord
    })


@rec_api.route('/setup', methods=['POST'])
def setup():
    g.store.setup()

    return jsonify({})


@rec_api.route('/forward', methods=['POST'])
def forward():
    if request.headers['Content-Type'] != 'application/json':
        abort_by_bad_content_type(request.headers['Content-Type'])
    data = request.get_json()
    digest_hex = data.get('digest')
    if not digest_hex:
        abort_by_missing_param('digest')
    digest = binascii.a2b_hex(digest_hex)
    records = g.store.get_records_by_prev_digest(digest)
    return jsonify({'records': [r.to_dict() for r in records]})


@rec_api.errorhandler(400)
@rec_api.errorhandler(404)
@rec_api.errorhandler(409)
def error_handler(e):
    return jsonify({'error': {
        'code': e.code,
        'name': e.name,
        'description': e.description,
    }}), e.code


@rec_api.errorhandler(ValueError)
@rec_api.errorhandler(KeyError)
def error_handler(e):
    return jsonify({'error': {
        'code': 400,
        'name': 'Bad Request',
        'description': str(e),
    }}), 400


# end of rec_api/body.py
