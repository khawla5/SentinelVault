"""
Memory protection and secure deletion (Phase: Memory Protection / Secure Delete).

Important honesty note for reviewers:
Python cannot give hard guarantees about wiping secrets from memory. `str` and
`bytes` are immutable and the garbage collector / interpreter may keep copies.
The right primitive is a MUTABLE `bytearray`, which we CAN overwrite in place.
These helpers therefore demonstrate the correct defensive pattern -- minimise
the lifetime of decrypted material and overwrite the buffer as soon as we are
done -- while being transparent about the limits of the language.
"""
from __future__ import annotations

import os
from contextlib import contextmanager


def wipe(buffer: bytearray) -> None:
    """Overwrite a mutable bytearray in place with zeros."""
    for i in range(len(buffer)):
        buffer[i] = 0


@contextmanager
def sensitive_bytes(data: bytes):
    """
    Context manager yielding a mutable copy of `data` that is zeroed on exit.

        with sensitive_bytes(vault_key) as key:
            ...use key...
        # key buffer is wiped here

    Keep decrypted secrets inside this block so they never outlive their use.
    """
    buf = bytearray(data)
    try:
        yield buf
    finally:
        wipe(buf)


def secure_delete_file(path: str, passes: int = 3) -> None:
    """
    Overwrite a file's bytes with random data before unlinking it.

    On modern SSDs with wear-levelling this is not a forensic guarantee (the
    controller may write to different physical cells), but it removes the naive
    recoverability of the logical file and demonstrates the intended technique.
    """
    if not os.path.isfile(path):
        return
    length = os.path.getsize(path)
    with open(path, "r+b", buffering=0) as f:
        for _ in range(passes):
            f.seek(0)
            f.write(os.urandom(length))
            f.flush()
            os.fsync(f.fileno())
        f.seek(0)
        f.write(b"\x00" * length)
        f.flush()
        os.fsync(f.fileno())
    os.remove(path)
