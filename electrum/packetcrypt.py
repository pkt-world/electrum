import os
import asyncio
import time

from typing import Optional, List, TYPE_CHECKING
from .logging import get_logger
from .blockchain import deserialize_header, hash_header, Blockchain, HEADER_SIZE, serialize_header, bfh
from .packetcrypt_bindings import packetcrypt_ann_header_numbers, packetcrypt_validate
from .crypto import sha256d

if TYPE_CHECKING:
    from .interface import Interface

_logger = get_logger(__name__)

async def _get_coinbase(net: 'Interface', header: dict) -> str:
    _logger.debug("_get_coinbase(height: {})".format(header['block_height']))
    res = await net.get_txid_from_txpos(header['block_height'], 0, True)
    _logger.debug("_get_coinbase(height: {}) -> {}".format(header['block_height'], res['tx_hash']))
    #verify_tx_is_in_block(res['tx_hash'], res['merkle'], 0, header, header['block_height'])
    ret = await net.get_transaction(res['tx_hash'])
    _logger.debug("_get_coinbase(height: {}) -> {} complete".format(header['block_height'], res['tx_hash']))
    return ret

async def _get_header_proof(net: 'Interface', header: dict):
    _logger.debug("_get_header_proof(height: {})".format(header['block_height']))
    if header['additional'] is not None:
        _logger.debug("_get_header_proof(height: {}) complete".format(header['block_height']))
        return
    header1 = await net.get_block_header(header['block_height'], 'packetcrypt_proof_check')
    _logger.debug("_get_header_proof(height: {}) got proof".format(header['block_height']))
    h0 = hash_header(header)
    h1 = hash_header(header1)
    if h0 != h1:
        raise Exception("Getting header {}, server gave us {}".format(h0, h1))
    header['additional'] = header1['additional']
    _logger.debug("_get_header_proof(height: {}) complete".format(header['block_height']))

def _contextual_get_header(
    chain: 'Blockchain',
    additional_chunk: bytes,
    additional_chunk_height: int,
    header_height: int,
) -> Optional[dict]:
    if header_height > additional_chunk_height:
        if header_height < additional_chunk_height + (len(additional_chunk) // HEADER_SIZE):
            i = (header_height - additional_chunk_height) * HEADER_SIZE
            buf = additional_chunk[i : i + HEADER_SIZE]
            assert len(buf) == HEADER_SIZE
            return deserialize_header(buf, header_height)
    return chain.read_header(header_height)

async def check_packetcrypt_proof(
    sem: asyncio.Semaphore,
    net: 'Interface',
    chain: Blockchain,
    header: dict,
    chunk: bytes,
    chunk_height: int,
) -> str:
    async with sem:
        _logger.debug(f"check_packetcrypt_proof(height: {header['block_height']})")
        coinbase = await _get_coinbase(net, header)
        await _get_header_proof(net, header)
        header_and_proof = bfh(serialize_header(header, include_additional=True))
        hashes: List[str] = []
        for num in packetcrypt_ann_header_numbers(header_and_proof):
            hdr = _contextual_get_header(chain, chunk, chunk_height, num)
            if hdr is None: raise Exception(f"Unable to get header at height {num}")
            hashes.append(hash_header(hdr))
        pwh = packetcrypt_validate(
            hashes,
            bfh(coinbase),
            bfh(serialize_header(header, include_additional=True)),
            header['block_height'])
        _logger.info(f"check_packetcrypt_proof(height: {header['block_height']}) -> {pwh}")
        return pwh

def deduce_tip(chain: Blockchain) -> int:
    gb = chain.read_header(0)
    if gb is None: raise Exception("Can't deduce chain tip, don't have genesis block")
    elapsed_time = int(time.time()) - gb['timestamp']
    return elapsed_time // 60 # TODO(cjd): 60 is non-portable

class PacketCrypt:
    def __init__(self):
        self.deduced_tip = None
        self.rand = os.urandom(8).hex()

    async def check_proofs(
        self,
        net: 'Interface',
        chain: Blockchain,
        tip: Optional[int],
        chunk: bytes,
        chunk_height: int,
    ):
        if chunk_height < 200000:
            _logger.info(f"Skipping check for block number {chunk_height} because it might be version 0")
            return
        if self.deduced_tip is None:
            self.deduced_tip = deduce_tip(chain)
        if tip is None: tip = self.deduced_tip
        sem = asyncio.Semaphore(8)
        jobs = []
        x = chunk_height - 1
        for i in range(0, len(chunk), HEADER_SIZE):
            x += 1
            header = deserialize_header(chunk[i:i+HEADER_SIZE], x)
            num = int.from_bytes(sha256d(hex(x) + self.rand)[:4],
                byteorder='little', signed=False) / 4294967296.0
            if num > (20 / max(1, min(tip, self.deduced_tip) - x)):
                #print(f"skip {x} because {num} > 20/{max(1, min(tip, self.deduced_tip) - x)}")
                continue
            d = {}
            d['header'] = header
            d['future'] = asyncio.ensure_future(
                check_packetcrypt_proof(sem, net, chain, header, chunk, chunk_height)
            )
            jobs.append(d)
        if len(jobs) == 0: return
        await asyncio.wait(map(lambda x: x['future'], jobs), return_when=asyncio.ALL_COMPLETED)
        for j in jobs:
            f = j['future']
            h = j['header']
            def hname(): f"Checking PacketCrypt proof on [{hash_header(h)}] ([{h['block_height']}])"
            if not f.done():
                raise Exception(f"{hname()} - future did not complete")
            if f.cancelled():
                raise Exception(f"{hname()} - future was cancelled")
            if f.exception():
                raise Exception(f"{hname()} - future raised exception: {f.exception()}")