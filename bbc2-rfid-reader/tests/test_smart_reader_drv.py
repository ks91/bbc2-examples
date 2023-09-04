# -*- coding: utf-8 -*-
#
# Rewrite the device path ('/dev/tty...') as you see fit.
# Rewrite the simulated data path ('sim-data.txt') as you see fit.
# try `$ pytest tests -s`
# to print results to the standard output.
#
import datetime
import time
from bbc2.lib import rfid_const
from bbc2.lib.cdexcru920mj_drv import SimpleCdexCru920Mj
from bbc2.lib.smart_rfid_reader_drv import SimpleRfidReaderSimulator
from bbc2.lib.smart_rfid_reader_drv import RfidReadout, SmartRfidReader
from bbc2.lib.smart_rfid_reader_drv import Location


def test_readout():

    dic1 = {
        "key": 1,
        "tag": "E28338002000010000750233",
        "timestamp": 1630727723,
        "location": {
            "latitude": "3569.1741N",
            "longitude": "13977.0859E",
            "altitude": "5"
        },
        "data": "0105",
        "algo": 2,
        "sig": "1bff4a4d5c81603875e0b795731ce2fb86c6a770768919811b6959fb1fd7ab92c9eb5eb06e4163b1c1035d7b1ae913828b7b670c0555b8e90ba5c49fd198ed13",
        "pubkey": "04c7c6885a3bb9349c2fb77be8abbbdc375177751c2e2addadddf3798e35afe0449b9636155ac5f0021de4d4e6583d281789ff8789cd933ba6641d9765a84e7a68"
    }

    readout = RfidReadout.from_dict(dic1)

    dic2 = readout.to_dict()

    assert dic1 == dic2


def test_smart_rfid_reader():

    readers = [
        ('CDEX CRU-920MJ', SimpleCdexCru920Mj('/dev/tty.usbmodem21H1400361')),
        ('Simulator', SimpleRfidReaderSimulator('sim-data.txt'))
    ]

    for (name, reader) in readers:
        print('Base reader: {0}'.format(name))
        smartReader = SmartRfidReader(12345678, reader,
                data_offset=rfid_const.OFFSET_LAPIS_TEMPERATURE)
        smartReader.set_location(
                Location('3568.0959N', '13976.7307E', '-29.19'))

        for i in range(10):
            time.sleep(2)

            aReadout = smartReader.read()

            print('Case {0}: {1} tag(s):'.format(i, len(aReadout)))

            for t in aReadout:
                readout = RfidReadout.from_tuple(t)
                assert readout.verify() == True
                data = readout.dataTag
                if len(data) > 0:
                    x = int(data, 16)
                    if x > 0x7fff:
                        x = ~(x ^ 0xffff)
                    data = str(x / 10)
                print('{0}/{1} at {2}'.format(readout.idTag, data,
                        datetime.datetime.fromtimestamp(readout.timestamp)))

        smartReader.close()


# end of tests/test_smart_reader_drv.py
