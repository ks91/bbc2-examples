# -*- coding: utf-8 -*-
#
# Rewrite the simulated data path ('sim-data.txt') as you see fit.
# try `$ pytest tests -s`
# to print results to the standard output.
#
from bbc2.lib import rfid_const
from bbc2.lib.smart_rfid_reader_drv import SimpleRfidReaderSimulator


def test_simulator():

    reader = SimpleRfidReaderSimulator('sim-data.txt')

    for i in range(10):
        aTags = reader.read()

        print('Case {0}: {1} tag(s):'.format(i, len(aTags)))
        for sTag in aTags:
            print(sTag)

    reader.close()


# assumes LAPIS Technology RFID data logger simulation
def test_simulator_data():

    reader = SimpleRfidReaderSimulator('sim-data.txt')

    for i in range(10):
        aTags = reader.read()

        print('Case {0}: {1} tag(s):'.format(i, len(aTags)))
        for sTag in aTags:
            data = reader.read_data(sTag, '0', rfid_const.BANK_USER,
                    rfid_const.OFFSET_LAPIS_TEMPERATURE, '1')
            if len(data) > 0:
                x = int(data, 16)
                if x > 0x7fff:
                    x = ~(x ^ 0xffff)
                print(x / 10)

    reader.close()


# end of tests/test_simulator_drv.py
