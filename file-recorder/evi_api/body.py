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
import binascii
import datetime
import hashlib
import json
import os
import requests
import string
import sys
import time
import xml.etree.ElementTree as ET
from bbc2.lib.data_store_lib import Database
from bbc2.lib.support_lib import BYTELEN_BIT256
from bbc2.serv.api.certify_api_body import get_document
from brownie import *
from flask import Blueprint, request, abort, jsonify, g

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))


NAME_OF_DB = 'evi_db'

evi_evidence_table_definition = [
    ["digest", "BLOB"],
    ["key", "BLOB"],
    ["proof", "TEXT"],
]

IDX_DIGEST = 0
IDX_KEY    = 1
IDX_PROOF  = 2


# Put API host name here.
PREFIX_API = 'http://localhost:9000'


domain_id = bbclib.get_new_id("file_recorder_domain", include_timestamp=False)
domain_id_str = bbclib.convert_id_to_string(domain_id)


class Evidence:

    def __init__(self, digest, key, proof):
        self.digest = digest
        self.key = key
        self.proof = proof


    @staticmethod
    def from_row(row):
        return Evidence(row[IDX_DIGEST], row[IDX_KEY], row[IDX_PROOF])


class Store:

    def __init__(self):
        self.db = Database()
        self.db.setup_db(domain_id, NAME_OF_DB)


    def close(self):
        try:
            self.db.close_db(domain_id, NAME_OF_DB)
        except KeyError:
            pass


    def read_evidence(self, digest):
        rows = self.db.exec_sql(
            domain_id,
            NAME_OF_DB,
            'select * from evidence_table where digest=?',
            digest
        )
        if len(rows) <= 0:
            return None
        return Evidence.from_row(rows[0])


    def setup(self):
        self.db.create_table_in_db(domain_id, NAME_OF_DB, 'evidence_table',
                evi_evidence_table_definition, primary_key=IDX_DIGEST,
                indices=[IDX_KEY])


    def update_evidence_proof(self, evidence):
        self.db.exec_sql(
            domain_id,
            NAME_OF_DB,
            'update evidence_table set proof=? where digest=?',
            evidence.proof,
            evidence.digest
        )


    def write_evidence(self, evidence):
        self.db.exec_sql(
            domain_id,
            NAME_OF_DB,
            'insert into evidence_table values (?, ?, ?)',
            evidence.digest,
            evidence.key,
            evidence.proof
        )


def abort_by_bad_content_type(content_type):
    abort(400, description='Content-Type {0} is not expected'.format(
            content_type))


def abort_by_bad_json_format():
    abort(400, description='Bad JSON format')


def abort_by_evidence_not_found():
    abort(404, description='Evidence is not found')


def abort_by_merkle_root_not_found():
    abort(404, description='Merkle root not stored (yet)')


def abort_by_subsystem_not_supported():
    abort(400, description='non-supported subsystem')


def abort_by_missing_param(param):
    abort(400, description='{0} is missing'.format(param))


evi_api = Blueprint('evi_api', __name__)


@evi_api.after_request
def after_request(response):
    g.store.close()
    return response


@evi_api.before_request
def before_request():
    g.store = Store()


@evi_api.route('/')
def index():
    return jsonify({})


@evi_api.route('/proof', methods=['GET'])
def get_proof_for_document():
    sDigest = request.json.get('digest')
    if sDigest is None:
        abort_by_missing_param('digest')

    digest = bbclib.convert_idstring_to_bytes(sDigest, BYTELEN_BIT256)
    evidence = g.store.read_evidence(digest)

    if evidence is None:
        abort_by_evidence_not_found()

    if len(evidence.proof) > 0:
        return jsonify(json.loads(evidence.proof))

    headers = {'Content-Type': 'application/json'}

    r = requests.get(PREFIX_API + '/bbc-api/verify-digest',
            headers=headers, data=json.dumps({
                'domain_id': domain_id_str,
                'digest': sDigest
            }, indent=2))
    dic = r.json()

    if dic['result'] == False:
        abort_by_merkle_root_not_found()

    spec = dic['spec']
    if spec['subsystem'] != 'ethereum':
        abort_by_subsystem_not_supported()

    subtree = dic['subtree']

    spec_s = {}
    subtree_s = []

    for k, v in spec.items():
        spec_s[k] = v.decode() if isinstance(v, bytes) else v

    for node in subtree:
        subtree_s.append({
            'position': node['position'],
            'digest': node['digest']
        })

    dic = {
        'proof': {
            'spec': spec_s,
            'subtree': subtree_s
        }
    }

    evidence.proof = json.dumps(dic)
    g.store.update_evidence_proof(evidence)

    return jsonify(dic)


@evi_api.route('/evidence', methods=['POST'])
def register_evidence():
    sDigest = request.json.get('digest')
    if sDigest is None:
        abort_by_missing_param('digest')

    sKey = request.json.get('key')
    if sKey is None:
        abort_by_missing_param('key')

    digest = bbclib.convert_idstring_to_bytes(sDigest, BYTELEN_BIT256)
    key = bytes(binascii.a2b_hex(sKey))

    g.store.write_evidence(Evidence(digest, key, ''))

    headers = {'Content-Type': 'application/json'}

    r = requests.post(PREFIX_API + '/bbc-api/register-digest',
            headers=headers, data=json.dumps({
                'domain_id': domain_id_str,
                'digest': sDigest
            }, indent=2))

    return jsonify({
        'success': 'true'
    })


@evi_api.route('/setup', methods=['POST'])
def setup():
    g.store.setup()

    headers = {'Content-Type': 'application/json'}

    r = requests.post(PREFIX_API + '/bbc-api/create-domain', headers=headers,
            data=json.dumps({
                'domain_id': domain_id_str
            }, indent=2))
    res = r.json()

    return jsonify({'domain_id': domain_id_str})


@evi_api.errorhandler(400)
@evi_api.errorhandler(404)
@evi_api.errorhandler(409)
def error_handler(e):
    return jsonify({'error': {
        'code': e.code,
        'name': e.name,
        'description': e.description,
    }}), e.code


@evi_api.errorhandler(ValueError)
@evi_api.errorhandler(KeyError)
def error_handler(e):
    return jsonify({'error': {
        'code': 400,
        'name': 'Bad Request',
        'description': str(e),
    }}), 400


# end of evi_api/body.py
