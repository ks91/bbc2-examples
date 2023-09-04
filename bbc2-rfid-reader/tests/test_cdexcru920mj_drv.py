# -*- coding: utf-8 -*-
#
# Rewrite the device path ('/dev/tty...') as you see fit.
# try `$ pytest tests -s`
# to print results to the standard output.
#
import time
from bbc2.lib import rfid_const
from bbc2.lib.cdexcru920mj_drv import SimpleCdexCru920Mj


def test_cdexcru920mj():

    reader = SimpleCdexCru920Mj('/dev/tty.usbmodem21H1400361')

    for i in range(10):
        time.sleep(2)

        aTags = reader.read()

        print('Case {0}: {1} tag(s):'.format(i, len(aTags)))
        for sTag in aTags:
            print(sTag)

    reader.close()


# assumes LAPIS Technology RFID data logger
def test_cdexcru920mj_data():

    reader = SimpleCdexCru920Mj('/dev/tty.usbmodem21H1400361')

    for i in range(10):
        time.sleep(2)

        aTags = reader.read()

        print('Temperature Case {0}: {1} tag(s):'.format(i, len(aTags)))
        for sTag in aTags:
            try:
                data = reader.read_data(sTag, '0', rfid_const.BANK_USER,
                        rfid_const.OFFSET_LAPIS_TEMPERATURE, '1')
                x = int(data, 16)
                if x > 0x7fff:
                    x = ~(x ^ 0xffff)
                print(x / 10)

            except:
                print('serial exception : probably the tag has left.')

    reader.close()


# end of tests/test_cdexcru920mj_drv.py
