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
import subprocess
from flask import Flask


app = Flask(__name__)
app.json.sort_keys = False


from evi_api.body import evi_api
app.register_blueprint(evi_api, url_prefix='/evi-api')

from rec_api.body import rec_api
app.register_blueprint(rec_api, url_prefix='/rec-api')

from files.views import files
app.register_blueprint(files, url_prefix='/files')


app.secret_key = 'NeToaLZTWjPMXiBD*Yci7J8Q'


if __name__ == '__main__':
    # it is assumed that bbc2 service is running at the user's home directory.
    args = [
        'bbc_eth_tool.py',
        '-w',
        '~/.bbc2',
        '-d',
        '3a643c70bbf9cc53887630eef4f27a06d23c8466a89ce7fd46b13cd48e1eff13',
        'enable'
    ]

    try:
        subprocess.check_call(args)
    except:
        print('*** Warning: problem experienced in enabling ledger subsystem')

    app.run(host='0.0.0.0', threaded=True)


# end of index.py
