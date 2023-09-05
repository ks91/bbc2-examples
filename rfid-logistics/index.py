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
import subprocess
from flask import Flask


app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False


from evi_api.body import evi_api
app.register_blueprint(evi_api, url_prefix='/evi-api')

from rfid_api.body import rfid_api
app.register_blueprint(rfid_api, url_prefix='/rfid-api')

from logi.views import logi
app.register_blueprint(logi, url_prefix='/logi')


app.secret_key = 'rKNk.VPPxm4@UvRi6cZx9*WD'


if __name__ == '__main__':
    # it is assumed that bbc1 core is running at the user's home directory.
    args = [
        'bbc_eth_tool.py',
        '-w',
        '~/.bbc2',
        '-d',
        '6faa4bfba6d9daed9517d4b71f402ba9d17c4a464144bfa6baadcae71fc8e01a',
        'enable'
    ]

    try:
        subprocess.check_call(args)
    except:
        print('*** Warning: problem experienced in enabling ledger subsystem')

    app.run(host='0.0.0.0', threaded=True)


# end of index.py
