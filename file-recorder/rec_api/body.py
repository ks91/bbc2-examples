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

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from recorder_tool import get_certificate_dict, Location, Record


MAX_TIME = (2 ** 63) - 1


NAME_OF_DB = 'rec_db'

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
            aRecord.append(get_record_from_row(row))

        return aRecord


    def setup(self):
        self.db.create_table_in_db(domain_id, NAME_OF_DB, 'record_table',
                record_table_definition,
                indices=[IDX_TIMESTAMP])


    def write_record(self, record):
        self.db.exec_sql(
            domain_id,
            NAME_OF_DB,
            'insert into record_table values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            record.key,
            record.filename,
            record.digest,
            record.timestamp,
            record.location.latitude,
            record.location.longitude,
            record.location.altitude,
            record.algo,
            record.sig,
            record.pubkey
        )


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
    t = (
        row[IDX_KEY],
        row[IDX_FILENAME],
        row[IDX_DIGEST],
        row[IDX_TIMESTAMP],
        Location(row[IDX_LATITUDE], row[IDX_LONGITUDE], row[IDX_ALTITUDE]),
        row[IDX_ALGO],
        row[IDX_SIG],
        row[IDX_PUBKEY]
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
