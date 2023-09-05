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
from bbc2.lib import rfid_const
from bbc2.lib.smart_rfid_reader_drv import RfidReadout, Location
from bbc2.lib.support_lib import BYTELEN_BIT256
from datetime import datetime, timedelta, timezone
from flask import Blueprint, render_template, request, session, abort, jsonify

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from reader_tool import LIST_KEY_TYPES
from reader_tool import get_digest, get_document, get_readout_dict


# Put API host names here.
PREFIX_CERTIFY_API = 'http://localhost:9000/certify-api'
PREFIX_EVI_API = 'http://localhost:5000/evi-api'
PREFIX_RFID_API = 'http://localhost:5000/rfid-api'


HEADERS = {'Content-Type': 'application/json'}


# Put your timezone here.
ISO_TIMEZONE = ':00+09:00'


OFFSET_ACCELERATION_X = int(rfid_const.OFFSET_LAPIS_ACCELERATION_X, 16)
OFFSET_ACCELERATION_Y = int(rfid_const.OFFSET_LAPIS_ACCELERATION_Y, 16)
OFFSET_ACCELERATION_Z = int(rfid_const.OFFSET_LAPIS_ACCELERATION_Z, 16)
OFFSET_ATMOSPHERIC_PRESSURE = int(
        rfid_const.OFFSET_LAPIS_ATMOSPHERIC_PRESSURE, 16)
OFFSET_HUMIDITY = int(rfid_const.OFFSET_LAPIS_HUMIDITY, 16)
OFFSET_TEMPERATURE = int(rfid_const.OFFSET_LAPIS_TEMPERATURE, 16)

O_ACCELERATION_X = (OFFSET_ACCELERATION_X - OFFSET_TEMPERATURE) * 4
O_ACCELERATION_Y = (OFFSET_ACCELERATION_Y - OFFSET_TEMPERATURE) * 4
O_ACCELERATION_Z = (OFFSET_ACCELERATION_Z - OFFSET_TEMPERATURE) * 4
O_ATMOSPHERIC_PRESSURE = (OFFSET_ATMOSPHERIC_PRESSURE - OFFSET_TEMPERATURE) * 4
O_HUMIDITY = (OFFSET_HUMIDITY - OFFSET_TEMPERATURE) * 4
O_TEMPERATURE = (OFFSET_TEMPERATURE - OFFSET_TEMPERATURE) * 4


logi = Blueprint('logi', __name__, template_folder='templates',
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


@logi.route('/')
def index():
    return render_template('logi/index.html')


@logi.route('/search', methods=['GET'])
def search_readouts():
    idTag = request.args.get('tag')
    timeFrom = request.args.get('timefrom')
    timeTo = request.args.get('timeto')

    print('idTag: {0}'.format(idTag))
    print('timeFrom: {0}'.format(timeFrom))
    print('timeTo: {0}'.format(timeTo))

    if len(idTag) <= 0:
        return render_template('logi/error.html',
                message='Tag is not specified.')

    if len(timeFrom) <= 0 or len(timeTo) <= 0:
        return render_template('logi/error.html',
                message='From and/or To is not specified.')

    dt = datetime.fromisoformat(timeFrom + ISO_TIMEZONE)
    lTimeFrom = int(dt.timestamp())
    dt = datetime.fromisoformat(timeTo + ISO_TIMEZONE)
    lTimeTo = int(dt.timestamp())

    dParam = {
        'tag': idTag,
        'timefrom': lTimeFrom,
        'timeto': lTimeTo
    }

    r = requests.get(PREFIX_RFID_API + '/readouts', headers=HEADERS,
            data=json.dumps(dParam, indent=2))
    res = r.json()

    if r.status_code != 200:
        return render_template('logi/error.html',
                message=json.dumps(res, indent=2))

    aReadout = []
    for readout in res['readouts']:
        readout['signature-algorithm'] = LIST_KEY_TYPES[readout['algo']]
        readout['date-time'] = str(datetime.fromtimestamp(
                readout['timestamp']))

        data = readout['data']

        # if data is 7 words (16bit * 7), extracts all relevant data.
        if len(data) == (7 * 4):
            # temperature (Celsius)
            o = O_TEMPERATURE
            x = get_signed_16bit_value(int(data[o:o+4], 16)) / 10
            readout['temperature'] = x

            # acceleration (x,y,z in m/s^2, perhaps)
            o = O_ACCELERATION_X
            x = get_signed_16bit_value(int(data[o:o+4], 16)) / 100
            o = O_ACCELERATION_Y
            y = get_signed_16bit_value(int(data[o:o+4], 16)) / 100
            o = O_ACCELERATION_Z
            z = get_signed_16bit_value(int(data[o:o+4], 16)) / 100
            readout['acceleration'] = {'x': x, 'y': y, 'z': z}

            # humidity (%)
            o = O_HUMIDITY
            x = int(data[o:o+4], 16)
            readout['humidity'] = x

            # atmospheric pressure (hPa)
            o = O_ATMOSPHERIC_PRESSURE
            x = int(data[o:o+6], 16) / 100
            readout['atmospheric-pressure'] = x

        # if data is 1 word (16bit), it is assumed to be a temperature.
        elif len(data) == (1 * 4):
            x = get_signed_16bit_value(int(data, 16)) / 10
            if x >= -20.0 and x <= 75.0:
                readout['temperature'] = x

        aReadout.append((readout['timestamp'], json.dumps(readout, indent=2)))

    return render_template('logi/readouts.html', readouts=aReadout)


@logi.route('/verify', methods=['GET'])
def verify():
    verifying = request.args.get('verifying')

    dic = json.loads(verifying)

    if 'readout' in request.args:
        readout = RfidReadout.from_dict(dic)
        dVer = get_readout_dict(readout)
        lTimeSigned = dic['timestamp']

    elif 'certificate' in request.args:
        lTime = int(request.args.get('time'))

        dParam = {
            'public_key': dic['pubkey'],
            'time': lTime
        }

        r = requests.get(PREFIX_RFID_API + '/certificate', headers=HEADERS,
                data=json.dumps(dParam, indent=2))
        res = r.json()

        if r.status_code != 200:
            return render_template('logi/error.html',
                    message=json.dumps(res, indent=2))

        dVer = res
        lTimeSigned = res['issued_at']

    else:
        return render_template('logi/error.html',
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
        return render_template('logi/error.html',
                message=json.dumps(res, indent=2))

    dVer['proof'] = res['proof']

    r = requests.get(PREFIX_CERTIFY_API + '/verify', headers=HEADERS,
            data=json.dumps(dVer, indent=2))
    res =r.json()

    if r.status_code != 200:
        return render_template('logi/error.html',
                message=json.dumps(res, indent=2))

    return render_template('logi/results.html',
            evidence=json.dumps(dVer, indent=2),
            results=json.dumps(res, indent=2), signed_time=lTimeSigned,
            time='Evidence Stored At: {0}'.format(datetime.fromtimestamp(
            res['time'])))


# end of logi/views.py
