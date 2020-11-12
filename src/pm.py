#!/usr/bin/env python3

"""ProtonMail private key encryption simulation

Simulate the encryption/decryption of a private key in ProtonMail given a user
password and a salt. The data to encrypt/decrypt is read from stdin and the
encrypted/decrypted data is written to stdout. The input can be raw data or an
ASCII armored PGP private key (if the --armored option is set).

Usage:
  pm.py encrypt [-a|--armored] <password> <salt>
  pm.py decrypt [-a|--armored] <password> <salt>
  pm.py (-h|--help)

Arguments:
  <password>  The user password
  <salt>      A Base64-encoded salt for hashing the password (16 bytes = 128 bits)

Options:
  -a --armored  Interpret input and write output as ASCII armored PGP key
  -h --help     Show this help message

Dependencies:
  - pgpy (https://pypi.org/project/PGPy/)
  - bcrypt (https://pypi.org/project/bcrypt/)
  - libscrc (https://pypi.org/project/libscrc/)
  - cryptography (https://pypi.org/project/cryptography/)
  - docopt (https://pypi.org/project/docopt/)
"""

import os
import sys
import re
import base64
import bcrypt
import _bcrypt
import libscrc
from docopt import docopt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from pgpy.packet.fields import String2Key
from pgpy.constants import SymmetricKeyAlgorithm, HashAlgorithm, String2KeyType


def main(args):
    data = sys.stdin.buffer.read()
    password = bytes(args['<password>'], 'utf-8')
    salt = base64.b64decode(args['<salt>'])

    hash = password_hash(password, salt)
    key = s2k(hash)

    if args['encrypt']:
        if args['--armored']:
            data = unarmor(data)
        ciphertext = aes256_encrypt(data, key)
        if args['--armored']:
            ciphertext = armor(ciphertext)
        sys.stdout.buffer.write(ciphertext)
    elif args['decrypt']:
        if args['--armored']:
            data = unarmor(data)
        plaintext = aes256_decrypt(data, key)
        if args['--armored']:
            plaintext = armor(plaintext)
        sys.stdout.buffer.write(plaintext)

def armor(data):
    """Convert a PGP private key into ASCII armored format. The ASCII armored
    format is described here: https://tools.ietf.org/html/rfc4880#section-6
    Args:
        data (bytes): the private key
    Return:
        bytes: the ASCII armored private key as a UTF-8 encoded byte array
    """
    checksum = crc24(data)
    key = str(base64.b64encode(data), 'utf-8')
    key = re.sub("(.{60})", "\\1\n", key, 0, re.DOTALL).strip()
    return bytes(f"""-----BEGIN PGP PRIVATE KEY BLOCK-----

{key}
={checksum}
-----END PGP PRIVATE KEY BLOCK-----
""", 'utf-8')

def unarmor(text):
    """Extract the key data from an ASCII armored PGP key. The ASCII armored
    format is described here: https://tools.ietf.org/html/rfc4880#section-6
    Args:
        text (bytes): an ASCII armored PGP key as a UTF-8 encoded byte array
    Return:
        bytes: the extracted key data
    """
    text = str(text, 'utf-8')
    lines = text.splitlines()
    first, last = None, None
    for i, line in enumerate(lines):
        if re.match(r'^$', line):
            if first == None: first = i+1
        if re.match(r'^[^0-9a-zA-Z+/]', line):
            if first != None and last == None: last = i-1
    data = base64.b64decode(''.join(lines[first:last+1]))
    # Verify checksum if present
    if re.match(r'^=', lines[last+1]):
        wanted = lines[last+1][1:]
        actual = crc24(data)
        if wanted != actual:
            raise RuntimeError(f"Checksum verification failed for ASCII armored input: got '{actual}', wanted '{wanted}'")
    return data

def crc24(data):
    """Calculate CRC-24 checksum as described in https://tools.ietf.org/html/rfc4880#section-6.1
    and encode it as four Base64 characters (24 bits).
    Args:
        data (bytes): the data for which to calculate the checksum
    Return:
        str: the checksum as a string of four Base64 characters
    """
    return str(base64.b64encode(libscrc.openpgp(data).to_bytes(3, 'big')), 'utf-8')

def aes256_encrypt(plaintext, key):
    """Encrypt data with AES-256 CBC mode and the provided key.
    Args:
        plaintext (bytes): the data to ecnrypt
        key (bytes):       the AES-256 key for encryption (256 bits = 32 bytes)
    Returns:
        bytes: the encrypted data
    """
    # Padding data to block size of AES CBC mode (128 bits = 16 bytes)
    padder = padding.PKCS7(128).padder()
    plaintext = padder.update(plaintext) + padder.finalize()
    # TODO: what initialisation vector to use?
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    # TODO: how to include the initialisation vector in the ciphertext?
    return iv + encryptor.update(plaintext) + encryptor.finalize()

def aes256_decrypt(ciphertext, key):
    """Decrypt ciphertext with AES-256 CBC mode and the provided key.
    Args:
        ciphertext (bytes): the ciphertext to decrypt
        key (bytes):        the AES-256 key for decryption (256 bits = 32 bytes)
    Returns:
        bytes: the decrypted data
    """
    # TODO: how to handle the initialisation vector?
    iv, ciphertext = ciphertext[:16], ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(plaintext) + unpadder.finalize()

def s2k(passphrase):
    """Generate an AES-256 key from a passphrase ("string to key").
    Args:
        passphrase (bytes): the passphrase as a UTF-8 encoded byte array
    Returns:
        bytes: the derived AES-256 key (256 bits = 32 bytes)
    """
    s2k = String2Key()
    # TODO: what salt to use (must be static or must be passed in)?
    s2k.salt = b'aaaaaaaa'
    # TODO: what S2K type and hash algorithm to use?
    s2k.specifier = String2KeyType.Iterated
    s2k.encalg = SymmetricKeyAlgorithm.AES256
    s2k.halg = HashAlgorithm.SHA256
    return s2k.derive_key(str(passphrase, 'utf-8'))

def password_hash(password, salt):
    """Hash the user password with the provided salt.
    Args:
        password (bytes): the user password as a UTF-8 encoded byte array
        salt (bytes):     an arbitrary salt of 128 bits (16 bytes)
    Returns:
        bytes: the hashed password as a UTF-8 encoded byte array
    """
    # Encode salt in bcrypt's Base64 format and prepend bcrypt prefix
    salt_base64 = _bcrypt.ffi.new("char[]", 30)
    _bcrypt.lib.encode_base64(salt_base64, salt, 16)
    salt_base64 = bytes("$2y$10$", 'utf-8') + _bcrypt.ffi.string(salt_base64)
    # Hash password and return everything after prefix and salt (first 29 chars)
    password_hash = bcrypt.hashpw(password, salt_base64)
    return password_hash[29:]

def format(arr):
    """Format a byte array as a string of hexadecimal digits (for debugging).
    Args:
        arr (bytes): a byte array
    Return:
        str: a string of space-separated hexadecimal digits (e.g. "E6 73 D2")
    """
    return ''.join(" {:02X}".format(e) for e in arr).strip()

if __name__ == '__main__':
    args = docopt(__doc__)
    main(args)
