"""
symmetric.py
Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

=== Support file to handle pycryptodome and pycryptodomex
"""

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import SHAKE256
except ImportError:
    from Cryptodome.Cipher import AES
    from Cryptodome.Hash import SHAKE256
