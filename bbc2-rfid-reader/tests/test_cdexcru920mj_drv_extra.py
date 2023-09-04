# -*- coding: utf-8 -*-
#
# Rewrite the device path ('/dev/tty...') as you see fit.
# try `$ pytest tests -s`
# to print results to the standard output.
#
import time
from bbc2.lib import rfid_const
from bbc2.lib.cdexcru920mj_drv import SimpleCdexCru920Mj


# assumes LAPIS Technology RFID data logger
def test_cdexcru920mj_data_humidity_and_pressure():

    reader = SimpleCdexCru920Mj('/dev/tty.usbmodem21H1400361')

    for i in range(10):
        time.sleep(2)

        aTags = reader.read()

        print('Humidity/Pressure Case {0}: {1} tag(s):'.format(i, len(aTags)))
        for sTag in aTags:
            try:
                data = reader.read_data(sTag, '0', rfid_const.BANK_USER,
                        rfid_const.OFFSET_LAPIS_HUMIDITY, '1')
                x = int(data, 16)
                print('humidity: {0}%'.format(x))

                data = reader.read_data(sTag, '0', rfid_const.BANK_USER,
                        rfid_const.OFFSET_LAPIS_ATMOSPHERIC_PRESSURE, '2')
                x = int(data, 16)
                print('atmospheric pressure: {0}hPa'.format((x >> 8) / 100))

            except:
                print('serial exception : probably the tag has left.')

    reader.close()


# assumes LAPIS Technology RFID data logger
def test_cdexcru920mj_data_acceleration():

    reader = SimpleCdexCru920Mj('/dev/tty.usbmodem21H1400361')

    for i in range(10):
        time.sleep(2)

        aTags = reader.read()

        print('Acceleration Case {0}: {1} tag(s):'.format(i, len(aTags)))
        for sTag in aTags:
            try:
                data = reader.read_data(sTag, '0', rfid_const.BANK_USER,
                        rfid_const.OFFSET_LAPIS_ACCELERATION_X, '1')
                x = int(data, 16)
                if x > 0x7fff:
                    x = ~(x ^ 0xffff)
                print('acceleration x: {0}'.format(x / 100))

                data = reader.read_data(sTag, '0', rfid_const.BANK_USER,
                        rfid_const.OFFSET_LAPIS_ACCELERATION_Y, '1')
                x = int(data, 16)
                if x > 0x7fff:
                    x = ~(x ^ 0xffff)
                print('acceleration y: {0}'.format(x / 100))

                data = reader.read_data(sTag, '0', rfid_const.BANK_USER,
                        rfid_const.OFFSET_LAPIS_ACCELERATION_Z, '1')
                x = int(data, 16)
                if x > 0x7fff:
                    x = ~(x ^ 0xffff)
                print('acceleration z: {0}'.format(x / 100))

            except:
                print('serial exception : probably the tag has left.')

    reader.close()


# end of tests/test_cdexcru920mj_drv_extra.py
