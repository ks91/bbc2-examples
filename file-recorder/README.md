File Recorder
==========
This app provides simple Web APIs and a command line tool to demonstrate how we can provide proof of authenticity of general files.

Recorder service (General App) : the following set of API is provided:
* **/rec-api/certificate** [GET] returns a certificate for a public key stated valid for the specified point of time.
* **/rec-api/record** [POST] registers a single record of a file (used by a recorder).
* **/rec-api/records** [GET] returns a set of records matching the input.
* **/rec-api/setup** [POST] sets the environment (a simple database).

Evidence service (BBc-2 App) : the following set of API is provided:
* **/evi-api/evidence** [POST] registers a single evidence, used by a recorder (for records) or a vendor (for public key certificates).
* **/evi-api/proof** [GET] returns the proof spec and Merkle subtree for an evidence.
* **/evi-api/verify** [GET] verifies an evidence accompanied with the proof structure (provided for convenience).
* **/evi-api/setup** [POST] sets the environment (a BBc-2 domain and a simple database).


## Dependencies
* bbc2
* py-bbclib >= 1.6
* Flask >= 1.1.2
* watchdog

## Installing dependencies
You need to pip-install py-bbclib, watchdog and Flask. Others (including bbc2 at the moment) are currently at their late development stages, and you will need to do `git clone -b develop [URI]`  to clone the project's development branch, go to the project directory and `python setup.py sdist` to generate an installer tar ball, and then `pip install dist/[tar.gz file]`.

## File record, its evidence and public key certificates
**Sample file record**
```
{
  "key": 1,
  "filename": "sample-file.mp4",
  "digest": "73289c56e9b17c3d8e601f4997d662ab836a0561041be912a170f5e1effc4420",
  "timestamp": 1631233757,
  "location": {
    "latitude": "3569.1741N",
    "longitude": "13977.0859E",
    "altitude": "5"
  },
  "algo": 2,
  "sig": "e312d1fcefd2e5d2de15314de73227d9be7c935e1aa648fff2981f8c38a61e2f3ad50710eb0c2ffc46e3a998f1f041e41c3797f03be7a9edb34e92ea9c20fd35",
  "pubkey": "04844e144d23aa63403b22f5f8365a0c9e6e3bfec31a59b90aa561bbd3bf6bfe541a49838a52e5957266c275efbf3b030db9ac5f2d31adcecfa9751c260ab03453"
}
```
**Sample evidence** (supposedly of the above record)
```
{
  "digest_1": "a90d9c56e9b17c3d8e601f4997d662ab836a0561041be912a170f5e1effc0735",
  "digest_2": "74fc4ccba4b20e250a545dd86d3111bd57aa707d836219940b67bec4a5c48cf3",
  "algo": "ecdsa-p256v1",
  "sig": "e312d1fcefd2e5d2de15314de73227d9be7c935e1aa648fff2981f8c38a61e2f3ad50710eb0c2ffc46e3a998f1f041e41c3797f03be7a9edb34e92ea9c20fd35",
  "pubkey": "04844e144d23aa63403b22f5f8365a0c9e6e3bfec31a59b90aa561bbd3bf6bfe541a49838a52e5957266c275efbf3b030db9ac5f2d31adcecfa9751c260ab03453"
}
```
Specifically, the file name, as well as other information, is kept private from the evidence service, while the service is capable (not currently implemented as API) of making a search over "digest_1" values (which is the digest of "key" and "filename" values concatinated).

**Sample public key certificate**
```
{
  "public_key": "04844e144d23aa63403b22f5f8365a0c9e6e3bfec31a59b90aa561bbd3bf6bfe541a49838a52e5957266c275efbf3b030db9ac5f2d31adcecfa9751c260ab03453",
  "subject": "foo: a meteor recorder",
  "issued_at": 1631233689,
  "expires_at": 1662769689,
  "algo": "ecdsa-p256v1",
  "sig": "c0ff25551931599f47995268416a723093dc3a76f59a178ca49b6c0fc6d13931777f8a6a50c4886fc910e1312138a30f0dc74f7c85a62242d7670e59a20e6f26",
  "pubkey": "0407c743525244017a0e0d26e75cccb5106f9f8d85feebebd253a9191b5e144f5f27d914564cef54c729a9ae0f2d4fb11c7d90ac1f4530c6263f4ca6cd17fc9cb1"
}
```

Before verification, these dictionary structures are accompanied with a 'proof' structure that has the specification for how blockchain was used and a Merkle subtree, the same as our 'certify' example.

## How to use this example
Below, it is assumed that "bbc_serv.py" runs at the user's home directory, and Ethereum's Sepolia testnet is used (and you have a sufficient amount of ETH (1 would be more than enough) in an account in Sepolia). At first, "bbc_serv.py" should be stopped.

To use Sepolia testnet, you need to set up brownie for that. You may want to refer to https://speakerdeck.com/beyondblockchain/bbc-2-hands-on-basic-installation?slide=17 and https://speakerdeck.com/beyondblockchain/bbc-2-hands-on-basic-installation?slide=18 (these slides are in Japanese)

1. Set up ledger subsystem (this writes to BBc-2's config file)
    ```
    bbc_eth_tool.py -w ~/.bbc2 auto [infura.io project ID] [private key]
    ```
    Take note (make copy) of the displayed contract address that was deployed by the command above.

2. Start bbc_serv.py

3. Set up the API (index.py of this example needs to run)

    POST 'api/setup' to set up.
    ```shell
    $ curl -X POST http://IP_ADDRESS:PORT/evi-api/setup
    {"domain_id": DOMAIN_ID} # returned
    $ curl -X POST http://IP_ADDRESS:PORT/rec-api/setup
    {} # returned
    ```

4. Stop bbc_serv.py (because again we will write to BBc-2's config file)

5. Configure Merkle tree settings of the ledger subsystem

    ```
    bbc_eth_tool.py -w ~/.bbc2 -d [domain id] config_tree [number of documents] [seconds]
    ```
        
    This configures the subsystem so that Merkle tree is closed and Merkle root is written to a Ethereum blockchain upon reaching either the specified number of processed documents or the specified seconds.

6. Start bbc_serv.py

7. (Re)start index.py of this example

    By default, the server runs at "http://localhost:5000/files".

**recorder_tool.py** is a utility program to set up the recorder vendor and recorders, each of which has a unique key-pair, and to run recorders to watch some specific directory for new files. First, do the following:

```
python recorder_tool.py setup
```

This creates a vendor keypair and a configuration file 'config.json'. Other than `setup` the following commands are available:
* **list** : lists the names of existing recorders.
* **list_pubkey** : lists the public keys of existing recorders.
* **new** NAME DIRECTORY LATITUDE LONGITUDE ALTITUDE : registers a new recorder.
  * **NAME** : name of the recorder.
  * **DIRECTORY** : path of the directory to look for new files.
  * **LATITUDE, LONGITUDE, ALTITUDE** : GPS location of the recorder.
* **remove** NAME : removes the specified recorder.
* **run** NAME : runs the specified recorder; logger messages are put to a file named 'NAME.log'; execution can be stopped by a keyboard interrupt (ctrl+C).
* **verify** {NAME, vendor}: verifies the certificate for a recorder (signed by the vendor) or the vendor (self-signed).

