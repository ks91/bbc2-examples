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
from serial import Serial, SerialException
from bbc2.lib.simple_rfid_reader_drv import SimpleRfidReader


CMD_C1GEN2I  = b'C1GEN2I 0,1\r\n'
CMD_C1GEN2S  = b'C1GEN2S 0,0,1,0,0,0\r\n'
CMD_C1GEN2XX = b'C1GEN2XX 0,0\r\n'
CMD_C1GEN2RA = 'C1GEN2RA {0},{1},{2},{3},{4},{5}\r\n'

# {0} : session ('0')
# {1} : EPC
# {2} : access password ('0')
# {3} : bank ('1' : EPC, '2' : TID, '3' : User)
# {4} : offset (in words)
# {5} : length (in words)

CMD_RF_A         = b'RFA\r\n'
CMD_RF_AM        = b'RFAM\r\n'
CMD_RF_FRQ_ORDER = b'RFFRQORDER\r\n'
CMD_RF_VER       = b'RFVER\r\n'
CMD_RF_A_MODE    = b'RFAMODE\r\n'
CMD_RF_C_MODE    = b'RFCMODE\r\n'


class SimpleCdexCru920Mj(SimpleRfidReader):

    def __init__(self, path):
        self._ser = Serial(path, timeout=1)

        self._ser.write(CMD_RF_VER)
        self.__read()
        self._ser.write(CMD_RF_A_MODE)
        self.__read()
        self._ser.write(CMD_RF_C_MODE)
        self.__read()
        self._ser.write(CMD_RF_A)
        self.__read()
        self._ser.write(CMD_RF_AM)
        self.__read()
        self._ser.write(CMD_RF_FRQ_ORDER)
        self.__read()


    def close(self):
        self._ser.close()


    def read(self):
        self._ser.write(CMD_C1GEN2I)
        self.__read()
        self._ser.write(CMD_C1GEN2S)
        self.__read()
        self._ser.write(CMD_C1GEN2XX)
        s = self.__read()

        aS = s.split(',')

        return aS[1:len(aS) - 1]


    def read_data(self, epc, passwd, bank, offset, length):
        self._ser.write(CMD_C1GEN2RA.format('0', epc, passwd, bank,
                offset, length).encode())
        s = self.__read()

        aS = s.split(',')

        return aS[1]


    def __read(self):
        s = self._ser.readline() # first, echo back
#       print('echo back: {0}'.format(s))
        s = ''
        while True:
            sTmp = self._ser.readline().decode().rstrip('\r\n')
#           print('rt: {0}'.format(sTmp))
            s += sTmp
            if sTmp.endswith('OK'):
                break

            elif sTmp[3] != '9' or sTmp[6] != '.': # radio frequency
                raise SerialException('rfid protocol')

        return s


# end of cdexcru920mj_drv.py
