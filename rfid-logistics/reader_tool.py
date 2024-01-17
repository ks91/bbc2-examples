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
import argparse
import bbclib
import binascii
import datetime
import hashlib
import json
import requests
import signal
import sys
import time
import urllib.parse
import xml.etree.ElementTree as ET
from bbc2.lib import rfid_const
from bbc2.lib.cdexcru920mj_drv import SimpleCdexCru920Mj
from bbc2.lib.document_lib import dict2xml, Document
from bbc2.lib.smart_rfid_reader_drv import SimpleRfidReaderSimulator
from bbc2.lib.smart_rfid_reader_drv import RfidReadout, SmartRfidReader
from bbc2.lib.smart_rfid_reader_drv import Location
from bbc2.lib.support_lib import BYTELEN_BIT256
from flask import current_app
from logging import basicConfig, getLogger, INFO


LIST_KEY_TYPES = ['not-initialized', 'ecdsa-secp256k1', 'ecdsa-p256v1']

HEADERS = {'Content-Type': 'application/json'}

PATH_CONFIG_JSON_DEFAULT = 'config.json'

PREFIX_CERTIFY_API_DEFAULT = 'http://localhost:9000/certify-api'
PREFIX_EVIDENCE_SERVICE_API_DEFAULT = 'http://localhost:5000/evi-api'
PREFIX_RFID_SERVICE_API_DEFAULT = 'http://localhost:5000/rfid-api'

INTERVAL_DEFAULT = 2
KEY_DEFAULT = 1

NUMBER_OF_SECONDS_IN_A_YEAR = 60 * 60 * 24 * 365


def argument_parser():
    argparser = argparse.ArgumentParser()
    subparsers = argparser.add_subparsers(dest="command_type", help='commands')

    # options
    #
    # By default, RFID tags were assumed to be data loggers by LAPIS Technology
    # and we tried to read all relevant data, including temperature (1),
    # acceleration (3; x,y,z), humidity (1), and atmospheric pressure (1.5),
    # where (n) means n words (1 word = 16bits), reading 7 consecutive words.
    # However, since such tags are not so common, and because it is prone to
    # induce errors, the default is now set to 0 data length.
    #
    argparser.add_argument('-b', '--bank', type=str,
            default=rfid_const.BANK_USER,
            help='bank of tag memory for data')
    argparser.add_argument('-c', '--config', type=str,
            default=PATH_CONFIG_JSON_DEFAULT,
            help='name of the config file')
    argparser.add_argument('-e', '--evi_api', type=str,
            default=PREFIX_EVIDENCE_SERVICE_API_DEFAULT,
            help='URL prefix of the evidence service API')
    argparser.add_argument('-f', '--certify_api', type=str,
            default=PREFIX_CERTIFY_API_DEFAULT,
            help='URL prefix of the BBc-2 certify API')
    argparser.add_argument('-i', '--interval', type=int,
            default=INTERVAL_DEFAULT,
            help='interval between reading out (2(secs) by default)')
    argparser.add_argument('-k', '--key', type=int,
            default=KEY_DEFAULT,
            help='shared key number between RFID service and clients')
    argparser.add_argument('-l', '--length', type=str,
            default='0',
            help='length to read tag memory for data')
    argparser.add_argument('-o', '--offset', type=str,
            default=rfid_const.OFFSET_LAPIS_TEMPERATURE,
            help='offset to read tag memory for data')
    argparser.add_argument('-p', '--passwd', type=str,
            default='0',
            help='access password for tag memory for data')
    argparser.add_argument('-r', '--rfid_api', type=str,
            default=PREFIX_RFID_SERVICE_API_DEFAULT,
            help='URL prefix of the RFID service API')

    # list command
    parser = subparsers.add_parser('list',
            help='Lists existing readers')

    # list_pubkey command
    parser = subparsers.add_parser('list_pubkey',
            help='Lists public keys of existing readers')

    # new command
    parser = subparsers.add_parser('new',
            help='Registers a new reader')

    subsubparsers = parser.add_subparsers(dest="reader_type", help='types')

    subsubparsers.add_parser('simulated', help='Simulated reader')
    subsubparsers.add_parser('cdexcru920mj', help='CDEX CRU-920MJ reader')

    parser.add_argument('name', action='store', default=None,
            help='Name of the new reader')
    parser.add_argument('device', action='store', default=None,
            help='Device file (or simulated input text file)')
    parser.add_argument('latitude', action='store', default=None,
            help='Latitude of the new reader')
    parser.add_argument('longitude', action='store', default=None,
            help='Longitude of the new reader')
    parser.add_argument('altitude', action='store', default=None,
            help='Altitude of the new reader')

    # remove command
    parser = subparsers.add_parser('remove',
            help='Removes a reader')
    parser.add_argument('name', action='store', default=None,
            help='Name of the reader to remove')

    # run command
    parser = subparsers.add_parser('run',
            help='Runs a reader (blocking execution)')
    parser.add_argument('name', action='store', default=None,
            help='Name of the reader to run')

    # setup command
    parser = subparsers.add_parser('setup',
            help='Sets up demo environment with a new vendor')

    # verify command
    parser = subparsers.add_parser('verify',
            help='Verifies the certificate for a reader or vendor')
    parser.add_argument('name', action='store', default=None,
            help="Name of the reader or 'vendor'")

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


def create_reader(dic, args):
    dReader = dict()

    dReader['name'] = args.name
    dReader['type'] = args.reader_type
    dReader['device'] = args.device
    dReader['latitude'] = args.latitude
    dReader['longitude'] = args.longitude
    dReader['altitude'] = args.altitude

    sType = args.reader_type
    if sType == 'cdexcru920mj':
        sType = 'CDEX CRU-920MJ'

    dReader['subject'] = '{0}: a {1} reader'.format(args.name, sType)

    dReader['bank'] = args.bank
    dReader['passwd'] = args.passwd
    dReader['offset'] = args.offset
    dReader['length'] = args.length

    keypair = bbclib.KeyPair(curvetype=bbclib.DEFAULT_CURVETYPE)
    keypair.generate()
    create_and_register_certificate(keypair, get_keypair(dic['vendor']),
            dReader, dic['vendor'], args)

    dic['readers'].append(dReader)

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


def get_readout_dict(readout):
    return {
        'digest_1': binascii.b2a_hex(readout.get_digest_1()).decode(),
        'digest_2': binascii.b2a_hex(readout.get_digest_2()).decode(),
        'algo': LIST_KEY_TYPES[readout.algo],
        'sig': binascii.b2a_hex(readout.sig).decode(),
        'pubkey': binascii.b2a_hex(readout.pubkey).decode()
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


def get_reader(name, readers):
    for dReader in readers:
        if dReader['name'] == name:
            return dReader

    return None


def get_setup_options_specified(args):
    options = []

    if args.key != KEY_DEFAULT:
        options.append('-k')
    if args.evi_api != PREFIX_EVIDENCE_SERVICE_API_DEFAULT:
        options.append('-e')
    if args.rfid_api != PREFIX_RFID_SERVICE_API_DEFAULT:
        options.append('-r')

    return options


def list_readers(dic, args):
    for d in dic['readers']:
        print("{0}: {1} '{2}' {3} {4} {5}".format(
                d['name'], d['type'], d['device'],
                d['latitude'], d['longitude'], d['altitude']))


def list_reader_public_keys(dic, args):
    for d in dic['readers']:
        print('{0}: {1}'.format(d['name'], d['public_key']))


def read_config(args):
    try:
        f = open(args.config, 'r')
        dic = json.load(f)
        f.close()

    except FileNotFoundError:
        dic = None

    return dic


def remove_reader(dic, args):
    dReader = get_reader(args.name, dic['readers'])
    if dReader is None:
        print("Reader '{0}' is not found.".format(args.name))
        return

    dic['readers'].remove(dReader)

    write_config(args.config, dic)


def run_reader(dic, args):
    basicConfig(filename=args.name + '.log', format='%(asctime)s %(message)s',
            level=INFO)
    logger = getLogger(__name__)

    dReader = get_reader(args.name, dic['readers'])
    if dReader is None:
        print("Reader '{0}' is not found.".format(args.name))
        return

    sType = dReader['type']

    if sType == 'simulated':
        reader = SimpleRfidReaderSimulator(dReader['device'])

    elif sType == 'cdexcru920mj':
        reader = SimpleCdexCru920Mj(dReader['device'])

    else:
        print("Reader type '{0}' is not recognized.".format(sType))
        return

    smartReader = SmartRfidReader(dic['rfid-service']['key'], reader,
            keypair=get_keypair(dReader), data_passwd=dReader['passwd'],
            data_bank=dReader['bank'], data_offset=dReader['offset'],
            data_length=dReader['length'])
    smartReader.set_location(Location(dReader['latitude'],
            dReader['longitude'], dReader['altitude']))

    signal.signal(signal.SIGTERM, sig_handler)

    try:
        logger.info('*** opened ***')
        while True:
            time.sleep(args.interval)

            aReadout = smartReader.read()
            logger.info('{0} tag(s):'.format(len(aReadout)))

            for t in aReadout:
                readout = RfidReadout.from_tuple(t)
                assert readout.verify() == True # testing just in case
                logger.info('{0}/{1} at {2}'.format(readout.idTag,
                        readout.dataTag,
                        datetime.datetime.fromtimestamp(readout.timestamp)))

                dEvi = get_readout_dict(readout)
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

                r = requests.post(args.rfid_api + '/readout', headers=HEADERS,
                        data=json.dumps(readout.to_dict(), indent=2))
                res = r.json()

                if r.status_code != 200:
                    logger.warn('storing readout failed: {0}'.format(
                            json.dumps(res, indent=2)))

    except KeyboardInterrupt:
        pass

    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        logger.info('*** closing ***')
        smartReader.close()
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.signal(signal.SIGINT, signal.SIG_DFL)


def setup_config(args):

    dConfig = dict()

    dic = dict()
    dic['subject'] = 'An RFID vendor'
    keypair = bbclib.KeyPair(curvetype=bbclib.DEFAULT_CURVETYPE)
    keypair.generate()
    create_and_register_certificate(keypair, keypair, dic, dic, args)

    dConfig['vendor'] = dic

    dic = dict()
    dic['key'] = args.key
    dic['api-url'] = args.rfid_api

    dConfig['rfid-service'] = dic

    dic = dict()
    dic['api-url'] = args.evi_api

    dConfig['evidence-service'] = dic

    dConfig['readers'] = []

    write_config(args.config, dConfig)


def sig_handler(signum, frame) -> None:
    sys.exit(1)


def sys_check(args):
    return


def verify_certificate(dic, args):
    if args.name == 'vendor':
        dTarget = dic['vendor']

    else:
        dTarget = get_reader(args.name, dic['readers'])
        if dTarget is None:
            print("Reader '{0}' is not found.".format(args.name))
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
            run_reader(dConfig, parsed_args)

        elif parsed_args.command_type == 'list':
            list_readers(dConfig, parsed_args)

        elif parsed_args.command_type == 'verify':
            verify_certificate(dConfig, parsed_args)

        elif parsed_args.command_type == 'new':
            create_reader(dConfig, parsed_args)

        elif parsed_args.command_type == 'list_pubkey':
            list_reader_public_keys(dConfig, parsed_args)

        elif parsed_args.command_type == 'remove':
            remove_reader(dConfig, parsed_args)

    sys.exit(0)


# end of reader_tool.py
