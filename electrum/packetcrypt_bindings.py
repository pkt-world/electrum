import os
import sys
from typing import Tuple, Union, List, Optional, Any, TypeVar, Type
from enum import Enum
import ctypes
from ctypes import c_int, c_uint32, c_uint64, c_char_p, c_void_p
from .transaction import Transaction, BCDataStream
from .blockchain import HEADER_SIZE
from .bitcoin import rev_hex
from .util import bfh

from .logging import get_logger
_logger = get_logger(__name__)

def _load_library():
    if sys.platform == 'darwin':
        library_paths = (os.path.join(os.path.dirname(__file__), 'libpacketcrypt_dll.dylib'),
                         'libpacketcrypt_dll.dylib')
    elif sys.platform in ('windows', 'win32'):
        library_paths = (os.path.join(os.path.dirname(__file__), 'packetcrypt_dll.dll'),
                         'packetcrypt_dll.dll')
    elif 'ANDROID_DATA' in os.environ:
        library_paths = ('libpacketcrypt_dll.so',)
    else:  # desktop Linux and similar
        library_paths = (os.path.join(os.path.dirname(__file__), 'libpacketcrypt_dll.so'),
                         'libpacketcrypt_dll.so')

    exceptions = []
    packetcrypt = None
    for libpath in library_paths:
        try:
            packetcrypt = ctypes.cdll.LoadLibrary(libpath)
        except BaseException as e:
            exceptions.append(e)
        else:
            break
    if not packetcrypt:
        _logger.error(f'libpacketcrypt library failed to load. exceptions: {repr(exceptions)}')
        return None

    try:
        packetcrypt.pc_Validate_checkBlock.restype = c_int
        packetcrypt.pc_Validate_checkBlock.argtypes = [
        # int Validate_checkBlock(
            c_char_p, # const PacketCrypt_HeaderAndProof_t* hap,
            c_uint32, # uint32_t hapLen,
            c_uint32, # uint32_t blockHeight,
            c_uint32, # uint32_t shareTarget,
            c_char_p, # const PacketCrypt_Coinbase_t* coinbaseCommitment,
            c_char_p, # const uint8_t blockHashes[static PacketCrypt_NUM_ANNS * 32],
            c_char_p, # uint8_t workHashOut[static 32],
            c_void_p, # PacketCrypt_ValidateCtx_t* vctx
        # );
        ]

        packetcrypt.pc_get_effective_target.restype = c_uint32
        packetcrypt.pc_get_effective_target.argtypes = [
            c_uint32, # uint32_t blockTar,
            c_uint32, # uint32_t annTar,
            c_uint64, # uint64_t annCount
        # );
        ]

        packetcrypt.pc_ValidateCtx_create.restype = c_void_p
        packetcrypt.pc_ValidateCtx_create.argtypes = []

        packetcrypt.pc_Validate_checkBlock_outToString.restype = c_char_p
        packetcrypt.pc_Validate_checkBlock_outToString.argtypes = [ c_int ]

        return packetcrypt
    except (OSError, AttributeError) as e:
        _logger.error(f'libpacketcrypt library was found and loaded but there was an error when using it: {repr(e)}')
        return None


_libpacketcrypt = None
_libpacketcrypt_ctx = None
try:
    _libpacketcrypt = _load_library()
    _libpacketcrypt_ctx = _libpacketcrypt.pc_ValidateCtx_create()
except BaseException as e:
    _logger.error(f'failed to load libpacketcrypt: {repr(e)}')


if _libpacketcrypt is None or _libpacketcrypt_ctx is None:
    # hard fail:
    sys.exit(f"Error: Failed to load libpacketcrypt.")

class PacketCryptEntity(Enum):
    PCP = 1
    SIGNATURES = 2
    CONTENT_PROOF = 3
    VERSION = 4

def _split_proof(header_and_proof: bytes) -> List[Tuple[PacketCryptEntity, bytes]]:
    vds = BCDataStream()
    vds.write(header_and_proof[HEADER_SIZE:])
    out: List[Tuple[PacketCryptEntity, bytes]] = []
    while True:
        typ = vds.read_compact_size()
        length = vds.read_compact_size()
        if typ == 0 and length == 0: return out
        out.append((PacketCryptEntity(typ), vds.read_bytes(length)))

def _get_entity(
    ents: List[Tuple[PacketCryptEntity, bytes]],
    et: PacketCryptEntity
) -> Optional[bytes]:
    for e in ents:
        if e[0] == et: return e[1]
    return None

# Get the numbers of parent blocks for a given proof
def packetcrypt_ann_header_numbers(header_and_proof: bytes) -> List[int]:
    pcp = _get_entity(_split_proof(header_and_proof), PacketCryptEntity.PCP)
    if pcp is None: raise Exception("PacketCrypt proof has no pcp entity")
    # 4 byte nonce
    c = 4
    out:List[int] = []
    for _ in range(0,4):
        # offset of parent block height is 12
        out.append(int.from_bytes(pcp[c+12 : c+12+4], byteorder='little'))
        # ann size is 1024
        c += 1024
    if len(pcp) < c: raise Exception("PacketCrypt proof too short")
    return out

Tassert_t = TypeVar('Tassert_t')
def tassert(x: Union[Tassert_t, Any], t: Type[Tassert_t], msg: Optional[str]=None) -> Tassert_t:
    assert isinstance(x, t), msg
    return x


def packetcrypt_get_effective_target(target_compact: int, ann_tar_compact: int, ann_count: int) -> int:
    bt = c_uint32(target_compact)
    at = c_uint32(ann_tar_compact)
    ac = c_uint64(ann_count)
    return _libpacketcrypt.pcdiff_get_effective_target(bt, at, ac)

# typedef struct {
#     PacketCrypt_BlockHeader_t blockHeader;
#     uint32_t _pad;
#     uint32_t nonce2;
#     PacketCrypt_Announce_t announcements[PacketCrypt_NUM_ANNS];
#     uint8_t proof[8]; // this is a flexible length buffer
# } PacketCrypt_HeaderAndProof_t;
#
# The format of PacketCrypt proof found in the blockchain is a TLV 
# namely signatures and version number
def _native_proof(header_and_proof: bytes) -> bytes:
    spl = _split_proof(header_and_proof)
    v = tassert(_get_entity(spl, PacketCryptEntity.VERSION), bytes, "Missing PacketCrypt version")
    if v != b'\2':
        raise Exception("Incompatible PacketCrypt version")
    pcp = tassert(_get_entity(spl, PacketCryptEntity.PCP), bytes, "Missing PacketCrypt proof")
    return header_and_proof[:HEADER_SIZE] + b'\0\0\0\0' + pcp

def packetcrypt_get_coinbase_commit(coinbase: bytes) -> bytes:
    coinbase_commit: Union[None, bytes] = None
    cb = Transaction(coinbase)
    cb.deserialize()
    inp = cb.inputs()
    if len(inp) != 1 or not inp[0].is_coinbase_input():
        raise Exception("coinbase parameter is not a coinbase")
    for out in cb.outputs():
        if out.value != 0: continue
        if out.scriptpubkey[:6].hex() == '6a3009f91102':
            coinbase_commit = out.scriptpubkey[2:]
            if len(coinbase_commit) != 48:
                raise Exception("PacketCrypt coinbase commitment is incorrect length")
            return coinbase_commit
    raise Exception("coinbase does not contain a PacketCrypt commitment")


def packetcrypt_validate(
        ann_header_hashes: List[str],
        coinbase: bytes,
        header_and_proof: bytes,
        height: int) -> str:
    native_hap = _native_proof(header_and_proof)
    coinbase_commit = packetcrypt_get_coinbase_commit(coinbase)
    if len(ann_header_hashes) != 4:
        raise Exception("unexpected number of ann_header_hashes")
    joined_hashes = b''.join(map(bfh, map(rev_hex, ann_header_hashes)))
    if len(joined_hashes) != 32*4:
        raise Exception("unexpected length of ann_header_hashes")
    work_hash_out = b'\0' * 32
    ret = _libpacketcrypt.pc_Validate_checkBlock(
        native_hap, # const PacketCrypt_HeaderAndProof_t* hap,
        c_uint32(len(native_hap)), # uint32_t hapLen,
        c_uint32(height), # uint32_t blockHeight,
        c_uint32(0), # uint32_t shareTarget,
        coinbase_commit, # const PacketCrypt_Coinbase_t* coinbaseCommitment,
        joined_hashes, # const uint8_t blockHashes[static PacketCrypt_NUM_ANNS * 32],
        work_hash_out, # uint8_t workHashOut[static 32],
        _libpacketcrypt_ctx # PacketCrypt_ValidateCtx_t* vctx
    )
    if ret == 0:
        return rev_hex(work_hash_out.hex())
    ret_str = _libpacketcrypt.pc_Validate_checkBlock_outToString(ret).decode('utf8')
    raise Exception("PacketCrypt replied: [{}]".format(ret_str))