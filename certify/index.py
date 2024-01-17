# -*- coding: utf-8 -*-
"""
Copyright (c) 2020 beyond-blockchain.org.

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


from cert.views import cert
app.register_blueprint(cert, url_prefix='/cert')


app.secret_key = '8HQCm2dWD9qn4d3c7tQ_8.YGNh26Hpsa'


if __name__ == '__main__':
    # it is assumed that bbc2 server is running at the user's home directory.
    args = [
        'bbc_eth_tool.py',
        '-w',
        '~/.bbc2',
        '-d',
        '7bc5dc8c1f3c4dc16e165beac165d73e4cb60530ac0b11bc433f6fba517d67b7',
        'enable'
    ]

    try:
        subprocess.check_call(args)
    except:
        print('*** Warning: problem experienced in enabling ledger subsystem')

    app.run(host='0.0.0.0', threaded=True)


# end of index.py
