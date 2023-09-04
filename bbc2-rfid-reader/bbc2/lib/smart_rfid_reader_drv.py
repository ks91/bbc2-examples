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
import binascii
import hashlib
import time

from bbc2.lib.rfid_const import BANK_USER
from bbc2.lib.simple_rfid_reader_drv import SimpleRfidReader
from bbclib.libs import bbclib_binary


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


class RfidReadout:

    def __init__(self, iRandom, idTag, timestamp, location, dataTag):
        self.iRandom = iRandom
        self.idTag = idTag
        self.timestamp = timestamp
        self.location = location
        self.dataTag = dataTag


    @staticmethod
    def from_dict(dic):
        ld = dic['location']
        readout = RfidReadout(dic['key'], dic['tag'], dic['timestamp'],
                Location(ld['latitude'], ld['longitude'], ld['altitude']),
                dic['data'])
        readout.algo = dic['algo']
        readout.sig = binascii.a2b_hex(dic['sig'])
        readout.pubkey = binascii.a2b_hex(dic['pubkey'])

        return readout


    @staticmethod
    def from_tuple(dataTuple):
        x, idTag, timestamp, location, dataTag, algo, sig, pubkey = dataTuple
        readout = RfidReadout(x, idTag, timestamp, location, dataTag)
        readout.algo = algo
        readout.sig = sig
        readout.pubkey = pubkey

        return readout


    @staticmethod
    def from_serialized_data(ptr, data):
        pass # FIXME


    def get_digest_1(self):
        dat = bytearray(bbclib_binary.to_4byte(self.iRandom))
        dat.extend(self.idTag.encode())

        return hashlib.sha256(bytes(dat)).digest()


    def get_digest_2(self):
        dat = bytearray(bbclib_binary.to_8byte(self.timestamp))
        dat.extend(self.location.serialize_for_digest())
        dat.extend(self.dataTag.encode())

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
            'key': self.iRandom,
            'tag': self.idTag,
            'timestamp': self.timestamp,
            'location': {
                'latitude': self.location.latitude,
                'longitude': self.location.longitude,
                'altitude': self.location.altitude
            },
            'data': self.dataTag,
            'algo': self.algo,
            'sig': binascii.b2a_hex(self.sig).decode(),
            'pubkey': binascii.b2a_hex(self.pubkey).decode()
        }


    def to_tuple(self):
        return (
            self.iRandom,
            self.idTag,
            self.timestamp,
            self.location,
            self.dataTag,
            self.algo,
            self.sig,
            self.pubkey
        )


    def verify(self):
        keypair = bbclib.KeyPair(curvetype=self.algo, pubkey = self.pubkey)

        return keypair.verify(self.get_signed_data(), self.sig)


class SimpleRfidReaderSimulator(SimpleRfidReader):

    def __init__(self, path):
        self._f = open(path)
        self._dic = dict()


    def close(self):
        self._f.close()


    def read(self):
        sLine = self._f.readline().rstrip('\n')
        aTags = []

        aS = [] if len(sLine) <= 0 else sLine.split(',')

        for s in aS:
            epc_data = s.split('/')
            if len(epc_data) > 1:
                self._dic[epc_data[0]] = epc_data[1]
            aTags.append(epc_data[0])

        return aTags


    def read_data(self, epc, passwd, bank, offset, length):
        return self._dic[epc] if epc in self._dic else ''


class SmartRfidReader:

    def __init__(self, iRandom, reader, key_type=bbclib.DEFAULT_CURVETYPE,
            keypair=None, data_passwd='0', data_bank=BANK_USER,
            data_offset='0', data_length='1'):
        self._iRandom = iRandom
        self._reader = reader
        self.data_passwd = data_passwd
        self.data_bank = data_bank
        self.data_offset = data_offset
        self.data_length = data_length

        if keypair is None:
            self._keypair = bbclib.KeyPair(curvetype=key_type)
            self._keypair.generate()

        else:
            self._keypair = keypair


    def close(self):
        self._reader.close()


    @staticmethod
    def from_serialized_data(ptr, data, reader):
        pass # FIXME


    def get_key_type(self):
        return self._keypair.curvetype


    def get_public_key(self):
        return self._keypair.public_key


    def read(self):
        aS = self._reader.read()
        timestamp = int(time.time())
        aReadout = []

        for idTag in aS:
            try:
                if self.data_length != '0':
                    dataTag = self._reader.read_data(idTag, self.data_passwd,
                            self.data_bank, self.data_offset, self.data_length)
                else:
                    dataTag = ''

            except:
                continue

            readout = RfidReadout(self._iRandom, idTag, timestamp,
                    self._location, dataTag)
            readout.sign(self._keypair)
            aReadout.append(readout.to_tuple())

        return aReadout


    def serialize(self):
        pass # FIXME


    def set_location(self, location):
        self._location = location


# end of smart_rfid_reader_drv.py
