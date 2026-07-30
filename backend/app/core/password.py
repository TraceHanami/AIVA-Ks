"""
Password hashing — argon2id via argon2-cffi.

argon2id is the OWASP-recommended choice over bcrypt/PBKDF2 for new
systems: it's memory-hard (resists GPU/ASIC cracking better than bcrypt)
and the 'id' variant mixes both side-channel resistance (argon2i) and
GPU-cracking resistance (argon2d), which is why the RFC 9106 and OWASP
guidance both default to it.
"""
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_hasher = PasswordHasher()  # sane defaults: time_cost=3, memory_cost=64MB, parallelism=4


def hash_password(plaintext: str) -> str:
    return _hasher.hash(plaintext)


def verify_password(plaintext: str, hashed: str) -> bool:
    try:
        _hasher.verify(hashed, plaintext)
        return True
    except VerifyMismatchError:
        return False
