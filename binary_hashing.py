import hashlib
import zlib

from fastcrc.crc64 import xz as _crc64_xz


HASH_CHUNK_SIZE = 1024 * 1024
CRC64_XZ_MASK = (1 << 64) - 1
CRC64_XZ_INITIAL = CRC64_XZ_MASK


def _update_crc64_xz(checksum: int, chunk: bytes) -> int:
    """Update the internal CRC64-XZ state using fastcrc's native implementation."""
    return _crc64_xz(chunk, checksum ^ CRC64_XZ_MASK) ^ CRC64_XZ_MASK


def hash_file(path) -> dict[str, str | int]:
    """Return hashes and byte count for one file's raw bytes."""
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    crc32 = 0
    crc64 = CRC64_XZ_INITIAL
    size = 0
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(HASH_CHUNK_SIZE), b""):
            md5_hash.update(chunk)
            sha256_hash.update(chunk)
            crc32 = zlib.crc32(chunk, crc32)
            crc64 = _update_crc64_xz(crc64, chunk)
            size += len(chunk)
    return {
        "md5": md5_hash.hexdigest(),
        "sha256": sha256_hash.hexdigest(),
        "crc32": f"{crc32 & 0xFFFFFFFF:08x}",
        "crc64": f"{crc64 ^ CRC64_XZ_MASK:016x}",
        "size": size,
    }
