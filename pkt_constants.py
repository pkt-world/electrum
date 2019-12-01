from electrum import constants

# We're intentionally not overloading all of the constants because there exist
# private keys which are in the bitcoin form and we do want to be able to import
# them.
def load():
    constants.net.ADDRTYPE_P2PKH = 0x75
    constants.net.SEGWIT_HRP = "pkt"
