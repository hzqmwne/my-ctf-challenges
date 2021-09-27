#!/usr/bin/env python3

import hashlib
from Crypto.Cipher import AES


FLAG = "flag{13290b14c1bb00486c9d4ba94bd50fdf}"

aeskey = bytes.fromhex("7e28a99358f40673cdb160f3ed02ebe2")
keybefore = bytes.fromhex("5dc00f4ecde50a22a5166e6d573f1f03")
keyafter = bytes.fromhex("19dcb026b0f57882e31dff9e85b437ff")


def bytes_xor(a, b):
    if len(a) != len(b):
        raise Exception
    return bytes(x^y for x,y in zip(a,b))


def aes_encrypt(m):
    if len(m) != 16:
        raise Exception
    cryptor = AES.new(aeskey, AES.MODE_ECB)
    c = cryptor.encrypt(bytes_xor(m, keybefore))
    return bytes_xor(c, keyafter)

def aes_decrypt(c):
    if len(c) != 16:
        raise Exception
    cryptor = AES.new(aeskey, AES.MODE_ECB)
    m = cryptor.decrypt(bytes_xor(c, keyafter))
    return bytes_xor(m, keybefore)

# --------------------------------------

def secure_hash(m):
    if len(m) != 16:
        raise Exception
    buf = m
    for i in range(1337):
        buf = aes_encrypt(hashlib.md5(buf).digest())
    return hashlib.md5(buf).digest()

def secure_decrypt(c):
    if len(c) != 16:
        raise Exception
    buf = c
    for i in range(1337):
        buf = aes_encrypt(buf)
    return buf

def secure_encrypt(m):
    if len(m) != 16:
        raise Exception
    buf = m
    for i in range(1337):
        buf = aes_decrypt(buf)
    return buf

# --------------------------------------

def generate_passwordhash(username, password):
    tmp1 = username.encode("ascii")
    tmp2 = password.encode("ascii")
    if len(tmp1) > 4 or len(tmp2) > 12:
        raise Exception
    buf = tmp1.ljust(4, b"\0") + tmp2.ljust(12, b"\0")
    return secure_hash(buf).hex()

def generate_token(username, passwordhash):
    buf = bytes.fromhex(passwordhash)
    if len(buf) != 16:
        raise Exception
    return secure_encrypt(secure_hash(buf)).hex()

def encrypt_token(token):
    buf = bytes.fromhex(token)
    if len(buf) != 16:
        raise Exception
    return secure_encrypt(buf).hex()

'''
def decrypt_token(encrypted_token):
    buf = bytes.fromhex(encrypted_token)
    if len(buf) != 16:
        raise Exception
    return secure_decrypt(buf).hex()
'''

def check_password(username, password, passwordhash):
    if len(username) > 4 or len(password) > 12:
        return False
    return generate_passwordhash(username, password) == passwordhash

def check_token(username, token, passwordhash):
    if len(token) != 32 or set(token)-set("0123456789abcdef"):
        return False
    if len(passwordhash) != 32 or set(passwordhash)-set("0123456789abcdef"):
        return False
    return secure_decrypt(bytes.fromhex(token)) == secure_hash(bytes.fromhex(passwordhash))

__all__ = ["FLAG", "generate_passwordhash", "generate_token", "encrypt_token", "check_password", "check_token"]

