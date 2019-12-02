#!/usr/bin/env python3
import sys
from electrum.util import bh2u
from electrum.bitcoin import base_decode
from electrum.transaction import Transaction
from electrum.transaction import tx_from_str
import pkt_constants
pkt_constants.load()


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def dump_tx(tx_bin):
    tx = Transaction(tx_from_str(tx_bin))
    eprint("Parsing transaction...")
    tx.outputs()
    eprint("This transaction will:")
    for o in tx.outputs():
        eprint("  * pay " + o.address + " " + str(o.value / 0x40000000) + " PKT")
    for inp in tx.inputs():
        #print(inp)
        print(inp['prevout_hash'])

def main():
    if len(sys.argv) < 2:
        eprint("Need a file to parse")
        return
    filename = sys.argv[1]
    with open(filename, 'r') as file:
        data = file.read().replace('\n', '')
    if data[0:2] == "00":
        data = data[2:]
    dump_tx(data)
main()
