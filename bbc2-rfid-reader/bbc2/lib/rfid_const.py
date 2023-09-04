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
#
# EPCglobal C1G2
#
BANK_EPC  = '1'
BANK_TID  = '2'
BANK_USER = '3'

# 
# LAPIS Technology RFID data logger
# All values are in hexadecimal.
#

# Acceleration : 100x values stored in 1 word (2 bytes) each.
OFFSET_LAPIS_ACCELERATION_X = '14'
OFFSET_LAPIS_ACCELERATION_Y = '15'
OFFSET_LAPIS_ACCELERATION_Z = '16'

# Atmospheric pressure : value in Pa (100x hPa) is stored in 3 bytes.
OFFSET_LAPIS_ATMOSPHERIC_PRESSURE = '18'

# Humidity : percentage is stored in 1 word (2 bytes).
OFFSET_LAPIS_HUMIDITY = '17'

# Temperature : 10x value in Celsius is stored in 1 word (2 bytes).
OFFSET_LAPIS_TEMPERATURE = '13'


# end of rfid_const.py
