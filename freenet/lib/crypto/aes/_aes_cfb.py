#!/usr/bin/env python3

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def encrypt(key, iv, byte_data):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    return encryptor.update(byte_data) + encryptor.finalize()


def decrypt(key, iv, byte_data):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    return decryptor.update(byte_data) + decryptor.finalize()
