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
import argparse
import bbclib
import binascii
import datetime
import hashlib
import json
import os
import requests
import signal
import sys
import time
import urllib.parse
import xml.etree.ElementTree as ET
from bbc2.lib.document_lib import dict2xml, Document
from bbc2.lib.support_lib import BYTELEN_BIT256
from bbclib.libs import bbclib_binary
from flask import current_app
from logging import basicConfig, getLogger, INFO
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


LIST_KEY_TYPES = ['not-initialized', 'ecdsa-secp256k1', 'ecdsa-p256v1']

HEADERS = {'Content-Type': 'application/json'}

PATH_CONFIG_JSON_DEFAULT = 'config.json'

PREFIX_CERTIFY_API_DEFAULT = 'http://localhost:9000/certify-api'
PREFIX_EVIDENCE_SERVICE_API_DEFAULT = 'http://localhost:5000/evi-api'
PREFIX_REC_SERVICE_API_DEFAULT = 'http://localhost:5000/rec-api'

INTERVAL_DEFAULT = 2
KEY_DEFAULT = 1

NUMBER_OF_SECONDS_IN_A_YEAR = 60 * 60 * 24 * 365


class Location:

    def __init__(self, latitude, longitude, altitude):
        self.latitude = latitude
        self.longitude = longitude
        self.altitude = altitude


    @staticmethod
    def from_serialized_data(ptr, data):
        pass # FIXME


    def serialize(self):
        dat = bytearray()
        string = self.latitude.encode()
        dat.extend(bbclib_binary.to_1byte(len(string)))
        dat.extend(string)
        string = self.longitude.encode()
        dat.extend(bbclib_binary.to_1byte(len(string)))
        dat.extend(string)
        string = self.altitude.encode()
        dat.extend(bbclib_binary.to_1byte(len(string)))
        dat.extend(string)

        return bytes(dat)


    def serialize_for_digest(self):
        dat = bytearray()
        dat.extend(self.latitude.encode())
        dat.extend(self.longitude.encode())
        dat.extend(self.altitude.encode())

        return bytes(dat)


class Record:

    def __init__(self, key, filename, digest, timestamp, location):
        self.key = key
        self.filename = filename
        self.digest = digest
        self.timestamp = timestamp
        self.location = location


    @staticmethod
    def from_dict(dic):
        ld = dic['location']
        digest = binascii.a2b_hex(dic['digest'])
        record = Record(dic['key'], dic['filename'], digest, dic['timestamp'],
                Location(ld['latitude'], ld['longitude'], ld['altitude']))
        record.algo = dic['algo']
        record.sig = binascii.a2b_hex(dic['sig'])
        record.pubkey = binascii.a2b_hex(dic['pubkey'])

        return record


    @staticmethod
    def from_tuple(dataTuple):
        key, filename, digest, timestamp, location, algo, sig, pubkey = dataTuple
        record = Record(key, filename, digest, timestamp, location)
        record.algo = algo
        record.sig = sig
        record.pubkey = pubkey

        return record


    @staticmethod
    def from_serialized_data(ptr, data):
        pass # FIXME


    def get_digest_1(self):
        dat = bytearray(bbclib_binary.to_4byte(self.key))
        dat.extend(self.filename.encode())

        return hashlib.sha256(bytes(dat)).digest()


    def get_digest_2(self):
        dat = bytearray(self.digest)
        dat.extend(bbclib_binary.to_8byte(self.timestamp))
        dat.extend(self.location.serialize_for_digest())

        return hashlib.sha256(bytes(dat)).digest()


    def get_signed_data(self):
        digest1 = self.get_digest_1()
        digest2 = self.get_digest_2()

        dat = bytearray(digest1)
        dat.extend(digest2)

        return (hashlib.sha256(bytes(dat)).digest())


    def serialize(self):
        pass # FIXME


    def sign(self, keypair):
        self.algo = keypair.curvetype
        self.sig = keypair.sign(self.get_signed_data())
        self.pubkey = keypair.public_key


    def to_dict(self):
        return {
            'key': self.key,
            'filename': self.filename,
            'digest': binascii.b2a_hex(self.digest).decode(),
            'timestamp': self.timestamp,
            'location': {
                'latitude': self.location.latitude,
                'longitude': self.location.longitude,
                'altitude': self.location.altitude
            },
            'algo': self.algo,
            'sig': binascii.b2a_hex(self.sig).decode(),
            'pubkey': binascii.b2a_hex(self.pubkey).decode()
        }


    def to_tuple(self):
        return (
            self.key,
            self.filename,
            self.digest,
            self.timestamp,
            self.location,
            self.algo,
            self.sig,
            self.pubkey
        )


    def verify(self):
        keypair = bbclib.KeyPair(curvetype=self.algo, pubkey = self.pubkey)

        return keypair.verify(self.get_signed_data(), self.sig)


class Recorder:

    def __init__(self, location, keypair):
        self.location = location
        self.keypair = keypair


    @staticmethod
    def from_dict(dic):
        location = Location(dic['latitude'], dic['longitude'], dic['altitude'])
        keypair = get_keypair(dic)
        return Recorder(location, keypair)


    def record(self, filepath, args):
        logger = getLogger(__name__)

        filename = os.path.basename(filepath)
        logger.info(f"file name: {filename}")
        timestamp = int(os.path.getmtime(filepath))

        h = hashlib.new('sha256')
        l = hashlib.new('sha256').block_size * 0x800
        with open(filepath,'rb') as f:
            data = f.read(l)

            while data:
                h.update(data)
                data = f.read(l)

        digest = h.digest()
        logger.info(f"file digest: {binascii.b2a_hex(digest).decode()}")

        record = Record(args.key, filename, digest, timestamp, self.location)
        record.sign(self.keypair)

        assert record.verify() == True # testing just in case
        timestring = datetime.datetime.fromtimestamp(record.timestamp)
        logger.info(f"created at: {timestring}")

        dEvi = get_record_dict(record)
        document = get_document(dEvi)
        dParam = {
            'digest': binascii.b2a_hex(get_digest(document)).decode(),
            'key': dEvi['digest_1']
        }

        r = requests.post(args.evi_api + '/evidence', headers=HEADERS,
                data=json.dumps(dParam, indent=2))
        res = r.json()

        if r.status_code != 200:
            logger.warn('registering evidence failed: {0}'.format(
                    json.dumps(res, indent=2)))

        r = requests.post(args.rec_api + '/record', headers=HEADERS,
                data=json.dumps(record.to_dict(), indent=2))
        res = r.json()

        if r.status_code != 200:
            logger.warn('storing record failed: {0}'.format(
                    json.dumps(res, indent=2)))


class EventHandler(FileSystemEventHandler):

    def __init__(self, recorder, args):
        self.recorder = recorder
        self.args = args


    def on_created(self,e):
        self.recorder.record(e.src_path, self.args)


def argument_parser():
    argparser = argparse.ArgumentParser()
    subparsers = argparser.add_subparsers(dest="command_type", help='commands')

    # options
    #
    argparser.add_argument('-c', '--config', type=str,
            default=PATH_CONFIG_JSON_DEFAULT,
            help='name of the config file')
    argparser.add_argument('-e', '--evi_api', type=str,
            default=PREFIX_EVIDENCE_SERVICE_API_DEFAULT,
            help='URL prefix of the evidence service API')
    argparser.add_argument('-f', '--certify_api', type=str,
            default=PREFIX_CERTIFY_API_DEFAULT,
            help='URL prefix of the BBc-2 certify API')
    argparser.add_argument('-k', '--key', type=int,
            default=KEY_DEFAULT,
            help='shared key number between recorder service and clients')
    argparser.add_argument('-p', '--poll', action='store_true',
            help='poll the directory to watch')
    argparser.add_argument('-r', '--rec_api', type=str,
            default=PREFIX_REC_SERVICE_API_DEFAULT,
            help='URL prefix of the recorder service API')


    # list command
    parser = subparsers.add_parser('list',
            help='Lists existing recorders')

    # list_pubkey command
    parser = subparsers.add_parser('list_pubkey',
            help='Lists public keys of existing recorders')

    # new command
    parser = subparsers.add_parser('new',
            help='Registers a new recorder')

    parser.add_argument('name', action='store', default=None,
            help='Name of the new recorder')
    parser.add_argument('directory', action='store', default=None,
            help='Directory path to look for new files')
    parser.add_argument('latitude', action='store', default=None,
            help='Latitude of the new recorder')
    parser.add_argument('longitude', action='store', default=None,
            help='Longitude of the new recorder')
    parser.add_argument('altitude', action='store', default=None,
            help='Altitude of the new recorder')

    # remove command
    parser = subparsers.add_parser('remove',
            help='Removes a recorder')
    parser.add_argument('name', action='store', default=None,
            help='Name of the recorder to remove')

    # run command
    parser = subparsers.add_parser('run',
            help='Runs a recorder (blocking execution)')
    parser.add_argument('name', action='store', default=None,
            help='Name of the recorder to run')

    # setup command
    parser = subparsers.add_parser('setup',
            help='Sets up demo environment with a new vendor')

    # verify command
    parser = subparsers.add_parser('verify',
            help='Verifies the certificate for a recorder or vendor')
    parser.add_argument('name', action='store', default=None,
            help="Name of the recorder or 'vendor'")

    return argparser.parse_args()


def create_and_register_certificate(keypair, keypair_certifier, dic, vdic,
        args):
    dic['public_key'] = binascii.b2a_hex(keypair.public_key).decode()
    dic['private_key'] = binascii.b2a_hex(keypair.private_key).decode()
    dic['algo'] = keypair.curvetype
    dic['issued_at'] = int(time.time())
    dic['expires_at'] = dic['issued_at'] + NUMBER_OF_SECONDS_IN_A_YEAR

    document = get_document(get_certifying(dic))
    sig = keypair_certifier.sign(get_digest(document))
    dic['sig'] = binascii.b2a_hex(sig).decode()

    document = get_document(get_certificate_dict(dic, vdic))
    dParam = {
        'digest': bbclib.convert_id_to_string(get_digest(document),
                BYTELEN_BIT256),
        'key': dic['public_key']
    }

    r = requests.post(args.evi_api + '/evidence', headers=HEADERS,
            data=json.dumps(dParam, indent=2))
    res = r.json()

    if r.status_code != 200:
        print(json.dumps(res, indent=2))


def create_recorder(dic, args):
    dRecorder = dict()

    dRecorder['name'] = args.name
    dRecorder['directory'] = args.directory
    dRecorder['latitude'] = args.latitude
    dRecorder['longitude'] = args.longitude
    dRecorder['altitude'] = args.altitude

    dRecorder['subject'] = '{0}: a file recorder'.format(args.name)

    keypair = bbclib.KeyPair(curvetype=bbclib.DEFAULT_CURVETYPE)
    keypair.generate()
    create_and_register_certificate(keypair, get_keypair(dic['vendor']),
            dRecorder, dic['vendor'], args)

    dic['recorders'].append(dRecorder)

    write_config(args.config, dic)


def get_certificate_dict(dic, vdic):
    return {
        'public_key': dic['public_key'],
        'subject': dic['subject'],
        'issued_at': dic['issued_at'],
        'expires_at': dic['expires_at'],
        'algo': LIST_KEY_TYPES[vdic['algo']],
        'sig': dic['sig'],
        'pubkey': vdic['public_key']
    }


def get_record_dict(record):
    return {
        'digest_1': binascii.b2a_hex(record.get_digest_1()).decode(),
        'digest_2': binascii.b2a_hex(record.get_digest_2()).decode(),
        'algo': LIST_KEY_TYPES[record.algo],
        'sig': binascii.b2a_hex(record.sig).decode(),
        'pubkey': binascii.b2a_hex(record.pubkey).decode()
    }


def get_certifying(dic):
    return {
        'public_key': dic['public_key'],
        'subject': dic['subject'],
        'issued_at': dic['issued_at'],
        'expires_at': dic['expires_at']
    }


def get_digest(document):
    return hashlib.sha256(document.file()).digest()


def get_document(dict):
    root = dict2xml(dict)

    id = root.findtext('id', default='N/A')
    return Document(
        document_id=bbclib.get_new_id(id, include_timestamp=False),
        root=root
    )


def get_keypair(dic):
    public_key = bytes(binascii.a2b_hex(dic['public_key']))
    private_key = bytes(binascii.a2b_hex(dic['private_key']))
    algo = dic['algo']

    return bbclib.KeyPair(curvetype=algo, privkey=private_key,
            pubkey=public_key)


def get_recorder(name, recorders):
    for dRecorder in recorders:
        if dRecorder['name'] == name:
            return dRecorder

    return None


def get_setup_options_specified(args):
    options = []

    if args.key != KEY_DEFAULT:
        options.append('-k')
    if args.evi_api != PREFIX_EVIDENCE_SERVICE_API_DEFAULT:
        options.append('-e')
    if args.rec_api != PREFIX_REC_SERVICE_API_DEFAULT:
        options.append('-r')
    if args.certify_api != PREFIX_CERTIFY_API_DEFAULT:
        options.append('-f')

    return options


def list_recorders(dic, args):
    for d in dic['recorders']:
        print("{0}: {1} {2} {3} {4}".format(
                d['name'], d['directory'],
                d['latitude'], d['longitude'], d['altitude']))


def list_recorder_public_keys(dic, args):
    for d in dic['recorders']:
        print('{0}: {1}'.format(d['name'], d['public_key']))


def read_config(args):
    try:
        f = open(args.config, 'r')
        dic = json.load(f)
        f.close()

    except FileNotFoundError:
        dic = None

    return dic


def remove_recorder(dic, args):
    dRecorder = get_recorder(args.name, dic['recorders'])
    if dRecorder is None:
        print("Recorder '{0}' is not found.".format(args.name))
        return

    dic['recorders'].remove(dRecorder)

    write_config(args.config, dic)


def run_recorder(dic, args):
    basicConfig(filename=args.name + '.log', format='%(asctime)s %(message)s',
            level=INFO)
    logger = getLogger(__name__)

    dRecorder = get_recorder(args.name, dic['recorders'])
    if dRecorder is None:
        print("Recorder '{0}' is not found.".format(args.name))
        return

    recorder = Recorder.from_dict(dRecorder)
    path = dRecorder['directory']

    if args.poll:
        files = os.listdir(path)

    else:
        observer = Observer()
        observer.schedule(EventHandler(recorder, args), path=path,
                recursive=False)
        observer.start()

    try:
        logger.info('*** opened ***')
        while True:
            time.sleep(5)

            if args.poll:
                filesNow = os.listdir(path)
                for file in filesNow:
                    if file not in files:
                        recorder.record(os.path.join(path, file), args)
                files = filesNow

    except KeyboardInterrupt:
        pass

    finally:
        logger.info('*** closing ***')


def setup_config(args):

    dConfig = dict()

    dic = dict()
    dic['subject'] = 'A recorder vendor'
    keypair = bbclib.KeyPair(curvetype=bbclib.DEFAULT_CURVETYPE)
    keypair.generate()
    create_and_register_certificate(keypair, keypair, dic, dic, args)

    dConfig['vendor'] = dic

    dic = dict()
    dic['key'] = args.key
    dic['api-url'] = args.rec_api

    dConfig['rec-service'] = dic

    dic = dict()
    dic['api-url'] = args.evi_api

    dConfig['evidence-service'] = dic

    dConfig['recorders'] = []

    write_config(args.config, dConfig)


def sig_handler(signum, frame) -> None:
    sys.exit(1)


def sys_check(args):
    return


def verify_certificate(dic, args):
    if args.name == 'vendor':
        dTarget = dic['vendor']

    else:
        dTarget = get_recorder(args.name, dic['recorders'])
        if dTarget is None:
            print("Recorder '{0}' is not found.".format(args.name))
            return

    dCert = get_certificate_dict(dTarget, dic['vendor'])
    document = get_document(dCert)
    dParam = {
        'digest': bbclib.convert_id_to_string(get_digest(document),
                bytelen=BYTELEN_BIT256)
     }

    r = requests.get(args.evi_api + '/proof', headers=HEADERS,
            data=json.dumps(dParam, indent=2))
    res = r.json()

    if r.status_code != 200:
        print(json.dumps(res, indent=2))
        return

    dCert['proof'] = res['proof']
    print('Certificate: ' + json.dumps(dCert, indent=2))

    r = requests.get(args.certify_api + '/verify', headers=HEADERS,
            data=json.dumps(dCert, indent=2))
    res = r.json()

    print('Result: ' + json.dumps(res, indent=2))
    if res['time'] is not None:
        print('Certificate was stored at: {0}'.format(
                datetime.datetime.fromtimestamp(res['time'])))


def write_config(sConfig, dic):
    f = open(sConfig, 'w')
    json.dump(dic, f, indent=2)
    f.close()


if __name__ == '__main__':

    parsed_args = argument_parser()

    try:
        sys_check(parsed_args)

    except Exception as e:
        print(str(e))
        sys.exit(0)

    dConfig = read_config(parsed_args)

    if parsed_args.command_type == 'setup':
        if dConfig is not None:
            while True:
                choice = input("Config file '{0}'".format(parsed_args.config) +
                        " exists: are you sure to overwrite? [y/N]: ").lower()

                if choice in ['y', 'ye', 'yes']:
                    break

                elif choice in ['n', 'no']:
                    sys.exit(0)

        setup_config(parsed_args)


    else:
        if dConfig is None:
            print("Config file '{0}' is not found: maybe forgot to setup?"
                    .format(parsed_args.config))
            sys.exit(0)

        options = get_setup_options_specified(parsed_args)
        if len(options) > 0:
            print('Specified option(s) {0} is only allowed with setup command.'
                    .format(options))
            sys.exit(0)

        if parsed_args.command_type == 'run':
            run_recorder(dConfig, parsed_args)

        elif parsed_args.command_type == 'list':
            list_recorders(dConfig, parsed_args)

        elif parsed_args.command_type == 'verify':
            verify_certificate(dConfig, parsed_args)

        elif parsed_args.command_type == 'new':
            create_recorder(dConfig, parsed_args)

        elif parsed_args.command_type == 'list_pubkey':
            list_recorder_public_keys(dConfig, parsed_args)

        elif parsed_args.command_type == 'remove':
            remove_recorder(dConfig, parsed_args)

    sys.exit(0)


# end of recorder_tool.py
