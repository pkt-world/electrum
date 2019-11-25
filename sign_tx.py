#!/usr/bin/env python3
import sys
import hashlib
import getpass
import json
import os
import logging
from electrum.logging import console_stderr_handler
from electrum.transaction import Transaction
from electrum.transaction import tx_from_str
from electrum import keystore
from electrum.storage import WalletStorage
from electrum.wallet import Multisig_Wallet

SEED_FILE = os.environ['SEED_FILE']

## Testing seed:
## kick mouse drill book wagon sudden ship rifle corn patch announce leisure
## Zpub6yv5s7ac6bDbCrMxaugzYMX66jDRnxvXgxYrWucUk6L4dc9UUv9RWb581MpfaUE5Bdy9rbUFWsnGVNWFKPLYRyt4weHfTjdEs6Xfm3nCvnQ

## Zpub6yhuP7EAUvHMD93Ceu4PGDE86zAzPGz3ZgWizgV3anasihU2qPPs9ec1U2WntBxuSmEdj42LWrHvB2RX1nFNdfaBJUb5vWgysvFuFkDoLsn

m = 3
NS_KEYS = [
    'Zpub6yhuP7EAUvHMD93Ceu4PGDE86zAzPGz3ZgWizgV3anasihU2qPPs9ec1U2WntBxuSmEdj42LWrHvB2RX1nFNdfaBJUb5vWgysvFuFkDoLsn',
    'Zpub6yt9oJkcseap5mLKarQ7hAK1ULGGAqRuYBgqY198MBmQ2mYpc6w4U9fyCFyniaQbgQcRRGKbbQhcn93dEXZn79dRtxkcB1henE4xAJGAyuh',
    'Zpub6xjHZeTc5PcMdcwj6rriBAajcGgZ2M9qi9yTcaR9CeM4yUTi7N7xji6sKRyohABmFtMN6KkAhBQheRKQBWawTAXCMBWVGGMiKXj1ku6wZga',
    'Zpub6ytA3HwmyULpysGgM5bMkCQcVzxxrLBXvGqJdR7VQFGSqDoBNvJFJW5M3ppF3a5xgTU1A3A4mZMXoc7PHtLQaZgLAwfiLJzL6goSJuwLodP',
    'Zpub6xvbH2BzG22zeXEEBb7kmQtrxPvAFjw7DNKgoVWh1jbPiEtuwV6Y8XaSiSdSh2eAJKBaPA4qgaYzrhtP7nEVemBQk644zu671DyyiL79bvv',
]
NS_ADDRESS = "bc1q6hqsqhqdgqfd8t3xwgceulu7k9d9w5t2amath0qxyfjlvl3s3u4st4nj3u"
def wallet(ks0):
    ws = WalletStorage("/tmp/fakewallet")
    ws.put('wallet_type', "%dof%d" % (m, len(NS_KEYS)))
    ksmp = ks0.get_master_public_key()
    for i, k in enumerate(NS_KEYS):
        if ksmp == k:
            ks = ks0
        else:
            ks = keystore.from_master_key(k)
        ws.put('x%d/' % (i + 1), ks.dump())
    return Multisig_Wallet(ws)

def password_stretch(password):
    return hashlib.scrypt(
        password.encode('utf-8'),
        salt=b'pass',
        n=2**17, r=8,
        p=1,
        dklen=32,
        maxmem=2**28
    ).hex()

def outfile_exists(file):
    if os.path.exists(file):
        print(file + " already exists, I'm not confident enough to overwrite it")
        return True

def combine_transactions(transaction_bin, outfile):
    if outfile_exists(outfile): return
    transactions = list(
        map(lambda tx_bin: Transaction(tx_from_str(tx_bin)), transaction_bin))
    tx0 = transactions[0]
    tx0.deserialize(True)
    for tx in transactions[1:]:
        i = 0
        for txin in tx.inputs():
            signingPos = 0
            for sig in txin['signatures']:
                if sig != None:
                    tx0.add_signature_to_txin(i, signingPos, sig)
                signingPos += 1
            i += 1
    f = open(outfile, 'w')
    f.write(tx.serialize_to_network())
    f.close()
    print("Result written to " + outfile)

console_stderr_handler.setLevel(logging.DEBUG)

def sign_tx(tx, filename):
    f = open(SEED_FILE, 'r')
    ks = keystore.BIP32_KeyStore( json.loads(f.read()) )
    f.close()
    passwd = getpass.getpass("Enter your signing password: ")
    print("creating wallet")
    w = wallet(ks)
    print("preparing inputs")
    for txin in tx.inputs():
        w.add_input_info(txin)
    print("signing " + str(len(tx.inputs())) + " inputs...")
    ks.sign_transaction(tx, password_stretch(passwd))
    ok = False
    for txin in tx.inputs():
        print(txin)
        for sig in txin['signatures']:
            if sig != None:
                ok = True
                break
    if not ok:
        print("Signing failed, perhaps your key does not match?")
        return
    f = open(filename + '.signed', 'w')
    f.write(tx.serialize())
    f.close()
    print("Signed transaction written to " + filename + ".signed")

def prompt_to_sign(tx_bin, filename):
    if outfile_exists(filename + '.signed'): return
    tx = Transaction(tx_from_str(tx_bin))
    print("Parsing transaction...")
    tx.outputs()
    print("This transaction will:")
    for o in tx.outputs():
        print("  * pay " + o.address + " " + str(o.value / 0x40000000) + " PKT")
    while True:
        yn = input("Do you want to sign? [y/n] ")
        if yn == 'n':
            print("Ok, bye")
            return
        if yn == 'y':
            sign_tx(tx, filename)
            return
        print("Your choices are 'y' or 'n'")

def configure_seed():
    if outfile_exists(SEED_FILE): return
    seed = input("Type your seed words: ")
    passwd = ''
    while True:
        passwd = getpass.getpass("Enter your signing password: ")
        passwd2 = getpass.getpass("Confirm your signing password: ")
        if passwd != passwd2:
            print("passwords do not match")
            continue
        break
    ks0 = keystore.from_seed(seed, '', True)
    ks0.update_password(None, password_stretch(passwd))
    f = open(SEED_FILE, 'w')
    f.write(json.dumps(ks0.dump()))
    f.close()
    print(SEED_FILE + " written")
    print("Your master public key is " + ks0.get_master_public_key())

def usage():
    print("Usage: ./sign_tx.py seed                                  # configure your seed")
    print("       ./sign_tx.py sign /path/to/transaction/file.hex    # sign a transaction")
    print("       ./sign_tx.py combine /path/to/tx1 /path/to/tx2 /path/to/output")
    print("                                                          # combine partial signed transactions")

def main():
    if len(sys.argv) > 4 and sys.argv[1] == 'combine':
        txs = []
        for i in range(2,len(sys.argv)-1):
            with open(sys.argv[2], 'r') as file:
                txs.append( file.read().replace('\n', '') )
        combine_transactions(txs)
    if len(sys.argv) == 3 and sys.argv[1] == 'sign':
        if len(sys.argv) < 3:
            usage()
            return
        if not os.path.exists(SEED_FILE):
            print(SEED_FILE + " does not exist, please run `./sign_tx.py seed` first")
            return
        filename = sys.argv[2]
        with open(filename, 'r') as file:
            data = file.read().replace('\n', '')
            prompt_to_sign(data, filename)
            return
    if len(sys.argv) == 2 and sys.argv[1] == 'seed':
        configure_seed()
        return
    usage()
main()
