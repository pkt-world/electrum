# For signing PKT multisig transactions

git clone https://github.com/cjdelisle/electrum.git
cd electrum
python3.7 -m pip install .[fast]
export SEED_FILE=/path/to/usb/device/encrypted.seed.json
python3.7 sign_tx.py seed
python3.7 sign_tx.py sign /path/to/transaction/file.hex
