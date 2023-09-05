# -*- coding: utf-8 -*-
"""
Copyright (c) 2021 beyond-blockchain.org.

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
from bbc2.lib.smart_rfid_reader_drv import RfidReadout, Location
from flask import Blueprint, request, abort, jsonify, g

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from reader_tool import get_certificate_dict


MAX_TIME = (2 ** 63) - 1


NAME_OF_DB = 'rfid_db'

rfid_readout_table_definition = [
    ["key", "INTEGER"],
    ["tag", "TEXT"],
    ["timestamp", "INTEGER"],
    ["latitude", "TEXT"],
    ["longitude", "TEXT"],
    ["altitude", "TEXT"],
    ["data", "TEXT"],
    ["algo", "INTEGER"],
    ["sig", "BLOB"],
    ["pubkey", "BLOB"],
]

IDX_KEY       = 0
IDX_TAG       = 1
IDX_TIMESTAMP = 2
IDX_LATITUDE  = 3
IDX_LONGITUDE = 4
IDX_ALTITUDE  = 5
IDX_DATA      = 6
IDX_ALGO      = 7
IDX_SIG       = 8
IDX_PUBKEY    = 9


domain_id = bbclib.get_new_id("rfid_logistics_domain", include_timestamp=False)


class Store:

    def __init__(self):
        self.db = Database()
        self.db.setup_db(domain_id, NAME_OF_DB)


    def close(self):
        try:
            self.db.close_db(domain_id, NAME_OF_DB)
        except KeyError:
            pass


    def read_readouts(self, idTag, time_from=0, time_to=MAX_TIME):
        rows = self.db.exec_sql(
            domain_id,
            NAME_OF_DB,
            'select * from readout_table where tag=? and ' +
                    'timestamp>=? and timestamp<=?',
            idTag,
            time_from,
            time_to
        )
        aReadout = []
        for row in rows:
            aReadout.append(get_readout_from_row(row))

        return aReadout


    def setup(self):
        self.db.create_table_in_db(domain_id, NAME_OF_DB, 'readout_table',
                rfid_readout_table_definition,
                indices=[IDX_TAG, IDX_TIMESTAMP])


    def write_readout(self, readout):
        self.db.exec_sql(
            domain_id,
            NAME_OF_DB,
            'insert into readout_table values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            readout.iRandom,
            readout.idTag,
            readout.timestamp,
            readout.location.latitude,
            readout.location.longitude,
            readout.location.altitude,
            readout.dataTag,
            readout.algo,
            readout.sig,
            readout.pubkey
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


def get_readout_from_row(row):
    t = (
        row[IDX_KEY],
        row[IDX_TAG],
        row[IDX_TIMESTAMP],
        Location(row[IDX_LATITUDE], row[IDX_LONGITUDE], row[IDX_ALTITUDE]),
        row[IDX_DATA],
        row[IDX_ALGO],
        row[IDX_SIG],
        row[IDX_PUBKEY]
    )
    return RfidReadout.from_tuple(t)


rfid_api = Blueprint('rfid_api', __name__)


@rfid_api.after_request
def after_request(response):
    g.store.close()

    return response


@rfid_api.before_request
def before_request():
    g.store = Store()


@rfid_api.route('/')
def index():
    return jsonify({})


@rfid_api.route('/certificate', methods=['GET'])
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
                for d in dic['readers']:
                    if d['public_key'] == public_key:
                        isFound = True
                        if d['issued_at'] <= lTime and lTime < d['expires_at']:
                            return jsonify(get_certificate_dict(d, vdic))

    if isFound:
        abort_by_certificate_out_of_date()

    abort_by_missing_certificate()


@rfid_api.route('/readout', methods=['POST'])
def post_readout():
    if request.headers['Content-Type'] != 'application/json':
        abort_by_bad_content_type(request.headers['Content-Type'])

    readout = RfidReadout.from_dict(request.get_json())
    g.store.write_readout(readout)

    return jsonify({
        'success': 'true'
    })


@rfid_api.route('/readouts', methods=['GET'])
def get_readouts():
    if request.headers['Content-Type'] != 'application/json':
        abort_by_bad_content_type(request.headers['Content-Type'])

    idTag = request.json.get('tag')
    lTimeFrom = request.json.get('timefrom')
    lTimeTo = request.json.get('timeto')

    aReadout = g.store.read_readouts(idTag,
            time_from=lTimeFrom, time_to=lTimeTo)

    adReadout = []
    for readout in aReadout:
        adReadout.append(readout.to_dict())

    return jsonify({
        'readouts': adReadout
    })


@rfid_api.route('/setup', methods=['POST'])
def setup():
    g.store.setup()

    return jsonify({})


@rfid_api.errorhandler(400)
@rfid_api.errorhandler(404)
@rfid_api.errorhandler(409)
def error_handler(e):
    return jsonify({'error': {
        'code': e.code,
        'name': e.name,
        'description': e.description,
    }}), e.code


@rfid_api.errorhandler(ValueError)
@rfid_api.errorhandler(KeyError)
def error_handler(e):
    return jsonify({'error': {
        'code': 400,
        'name': 'Bad Request',
        'description': str(e),
    }}), 400


# end of rfid_api/body.py
