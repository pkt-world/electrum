from urllib import request
from electrum.transaction import Transaction
from electrum.transaction import tx_from_str
import ssl
import json
import sys
import codecs

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

gcontext = ssl.SSLContext()
gcontext.verify_mode = ssl.CERT_NONE

def req(method, args):
    req = request.Request("https://localhost:64763",
    data=json.dumps({
      "jsonrpc":"1.0",
      "id":"txid",
      "method":method,
      "params":args
    }).encode(),
    headers={
      'Authorization': 'Basic eDp4'
    })
    f = request.urlopen(req, context=gcontext)
    page = f.read()
    obj = json.loads(page)
    if obj['error'] != None:
        raise obj['error']
    return obj['result']

def mk_tx(amount, payTo, heightLimit):
    return req("createtransaction", [
        "imported",
        payTo,
        amount,
        True,
        "pkt1q6hqsqhqdgqfd8t3xwgceulu7k9d9w5t2amath0qxyfjlvl3s3u4sjza2g2", # change address
        heightLimit
    ])

MAX_TX_AMT=100000

def mk_transactions(amount, payTo, heightLimit):
    i = 0
    while amount > 0:
        eprint("Transaction " + str(i) + " with height limit " + str(heightLimit))
        i = i + 1
        toPay = amount
        if toPay > MAX_TX_AMT:
            toPay = MAX_TX_AMT
        amount = amount - MAX_TX_AMT
        tx = mk_tx(toPay, payTo, heightLimit)
        elecTx = Transaction(tx_from_str(tx))
        for inp in elecTx.inputs():
            prevTx = req("getrawtransaction", [ inp['prevout_hash'], 1 ])
            block = req("getblock", [ prevTx['blockhash'] ])
            eprint('  ' + inp['prevout_hash'] + ' ' + str(block['height']))
            if heightLimit <= block['height']:
                heightLimit = block['height'] + 1
        print(codecs.encode(codecs.decode(tx, 'hex'), 'base64').decode().replace("\n", ""))


mk_transactions(10000000-10000, 'p7Gdf7YhaxSkWm6u6yU452S6C9mJpuTfwu', 0)
