import hashlib
import unittest
import zlib
from pathlib import Path
from statistics import median
from tempfile import TemporaryDirectory
from time import perf_counter

from binary_hashing import CRC64_XZ_INITIAL, CRC64_XZ_MASK, HASH_CHUNK_SIZE, _update_crc64_xz, hash_file


CRC64_XZ_REFLECTED_POLYNOMIAL = 0xC96C5795D7870F42


def _build_python_crc64_xz_table() -> tuple[int, ...]:
    table = []
    for value in range(256):
        checksum = value
        for _ in range(8):
            if checksum & 1:
                checksum = (checksum >> 1) ^ CRC64_XZ_REFLECTED_POLYNOMIAL
            else:
                checksum >>= 1
        table.append(checksum & CRC64_XZ_MASK)
    return tuple(table)


PYTHON_CRC64_XZ_TABLE = _build_python_crc64_xz_table()


def _update_crc64_xz_in_python(checksum: int, chunk: bytes) -> int:
    for value in chunk:
        checksum = PYTHON_CRC64_XZ_TABLE[(checksum ^ value) & 0xFF] ^ (checksum >> 8)
    return checksum & CRC64_XZ_MASK


class TestHashFile(unittest.TestCase):
    def test_returns_standard_hashes_and_crc_test_vectors(self) -> None:
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "binary.bin"
            path.write_bytes(b"123456789")
            metadata = hash_file(path)

        self.assertEqual(
            {
                "md5": "25f9e794323b453885f5181f1b624d0b",
                "sha256": "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225",
                "crc32": "cbf43926",
                "crc64": "995dc9bbdf1939fa",
                "size": 9,
            },
            metadata,
        )

    def test_reads_all_chunks_as_one_raw_byte_stream(self) -> None:
        payload = (b"chunk-boundary" * ((HASH_CHUNK_SIZE // len(b"chunk-boundary")) + 2)) + b"tail"
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "binary.bin"
            path.write_bytes(payload)
            metadata = hash_file(path)

        self.assertEqual(hashlib.md5(payload).hexdigest(), metadata["md5"])
        self.assertEqual(hashlib.sha256(payload).hexdigest(), metadata["sha256"])
        self.assertEqual(f"{zlib.crc32(payload) & 0xFFFFFFFF:08x}", metadata["crc32"])
        self.assertEqual("43f1915ca35c9a0f", metadata["crc64"])
        self.assertEqual(len(payload), metadata["size"])

    def test_native_crc64_matches_python_reference_across_chunks(self) -> None:
        payload = bytes(range(256)) * ((HASH_CHUNK_SIZE * 2 // 256) + 1)
        chunks = (
            payload[: HASH_CHUNK_SIZE - 1],
            payload[HASH_CHUNK_SIZE - 1 : HASH_CHUNK_SIZE + 1],
            payload[HASH_CHUNK_SIZE + 1 :],
        )
        native_checksum = CRC64_XZ_INITIAL
        python_checksum = CRC64_XZ_INITIAL

        for chunk in chunks:
            native_checksum = _update_crc64_xz(native_checksum, chunk)
            python_checksum = _update_crc64_xz_in_python(python_checksum, chunk)

        self.assertEqual(python_checksum, native_checksum)

    def test_native_crc64_is_faster_than_python_reference(self) -> None:
        payload = bytes(range(256)) * (4 * 1024 * 1024 // 256)

        def benchmark(update_crc64, repeats: int) -> tuple[int, float]:
            samples = []
            checksum = CRC64_XZ_INITIAL
            for _ in range(repeats):
                started_at = perf_counter()
                checksum = update_crc64(CRC64_XZ_INITIAL, payload)
                samples.append(perf_counter() - started_at)
            return checksum, median(samples)

        python_checksum, python_elapsed = benchmark(_update_crc64_xz_in_python, repeats=3)
        native_checksum, native_elapsed = benchmark(_update_crc64_xz, repeats=5)

        self.assertEqual(python_checksum, native_checksum)
        self.assertLess(
            native_elapsed,
            python_elapsed,
            f"native CRC64-XZ took {native_elapsed:.6f}s; Python reference took {python_elapsed:.6f}s",
        )


if __name__ == "__main__":
    unittest.main()
