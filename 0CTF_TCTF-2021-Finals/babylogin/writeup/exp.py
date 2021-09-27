#!/usr/bin/env python3

import ctypes
import aeskeyschedule
import phoenixAES
from Crypto.Cipher import AES
from unicorn import *
from unicorn.x86_const import *


def p32(n):
    n &= (1<<32)-1
    return n.to_bytes(4, "little")

def u32(s):
    assert len(s) == 4
    return int.from_bytes(s, "little")

def p64(n):
    n &= (1<<64)-1
    return n.to_bytes(8, "little")

def u64(s):
    assert len(s) == 8
    return int.from_bytes(s, "little")

def bytes_xor(a, b):
    assert len(a) == len(b)
    return bytes(x^y for x,y in zip(a,b))

# --------------------------------------

def secure_hash(m):
    global global_libsmartcard
    if len(m) != 16:
        raise Exception
    buf = ctypes.create_string_buffer(m, 16)
    global_libsmartcard.secure_hash(bytes(m), buf)
    return buf.raw

def secure_decrypt(c):
    if len(c) != 16:
        raise Exception
    buf = ctypes.create_string_buffer(c, 16)
    global_libsmartcard.secure_decrypt(bytes(c), buf)
    return buf.raw

def generate_passwordhash(username, password):
    tmp1 = username.encode('ascii')
    tmp2 = password.encode('ascii')
    if len(tmp1) > 4 or (len(tmp2) > 12):
        raise Exception
    buf = tmp1.ljust(4, b'\x00') + tmp2.ljust(12, b'\x00')
    return secure_hash(buf).hex()

# --------------------------------------

def bruteforce_baba_password():
    def iter():
        validchars = "0123456789"
        for a in validchars:
            yield a
            for b in validchars:
                yield a+b
                for c in validchars:
                    yield a+b+c
                    for d in validchars:
                        yield a+b+c+d
    for pw in iter():
        if generate_passwordhash("baba", pw) == "b7a44ef9e4c00312fcf98c6e0833b10e":
            return pw

# --------------------------------------

def hook_code64(uc, address, size, user_data):
    if address == 0x401477:
        rbp = uc.reg_read(UC_X86_REG_RBP)
        turn = u32(uc.mem_read(rbp-0x1c, 4))
        state_addr = u64(uc.mem_read(rbp-0x28, 8))
        state = bytearray(uc.mem_read(state_addr, 16))
        if turn == user_data[0]:
            state[user_data[1]] ^= 0xff
            uc.mem_write(state_addr, bytes(state))

def do_emulate(turn, index, inputbytes=b"\0"*16):
    global code_segment
    global data_segment

    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(0x401000, 0x3000)
    mu.mem_map(0x404000, 0x80000)
    mu.mem_map(0x7fff00000000, 0x8000)

    mu.reg_write(UC_X86_REG_FS_BASE, 0x7fff00000000)
    mu.reg_write(UC_X86_REG_RSP, 0x7fff00001000)

    mu.mem_write(0x401000, code_segment)
    mu.mem_write(0x404000, data_segment)

    mu.hook_add(UC_HOOK_CODE, hook_code64, (turn, index))

    mu.mem_write(0x7fff00004000, inputbytes)
    mu.reg_write(UC_X86_REG_RDI, 0x7fff00004000)

    mu.emu_start(0x40144a, 0x402975)

    r = mu.mem_read(0x7fff00004000, 16)
    return r


def do_dfa(roundnum, roundkeys):
    assert 1 <= roundnum <= 10
    
    testinputbytes = b"\0"*16
    ref = do_emulate(None, 0, testinputbytes)

    r9faults = []
    for j in range(16):
        inputbytes = testinputbytes
        if roundnum == 1:
            tmp = phoenixAES.InvMC(inputbytes)
            tmp[j] ^= 0xff
            inputbytes = bytes(phoenixAES.MC(tmp))
        r = do_emulate(roundnum-2, j, inputbytes)
        r9faults.append(r)

    lastroundkeys = roundkeys[roundnum+1:][::-1]
    rewindref = phoenixAES.rewind(ref, lastroundkeys, encrypt=True)
    r = phoenixAES.crack_bytes(r9faults, rewindref, lastroundkeys, encrypt=True, outputbeforelastrounds=False, verbose=0)
    roundkeys[roundnum] = bytes.fromhex(r)

    if roundnum == 1:
        output_after_addroundkey0 = phoenixAES.rewind(ref, roundkeys[1:][::-1], encrypt=True, mimiclastround=False)
        roundkeys[0] = bytes_xor(output_after_addroundkey0, testinputbytes)


def recover_roundkeys():
    roundkeys = [None]*11
    for roundnum in range(10, 0, -1):
        do_dfa(roundnum, roundkeys)
    return roundkeys


def recover_realkeys(roundkeys):
    aeskey = aeskeyschedule.reverse_key_schedule(roundkeys[9], 9)
    realroundkeys = aeskeyschedule.key_schedule(aeskey)
    for i in range(1, 10):
        assert realroundkeys[i] == roundkeys[i]
    keybefore = bytes_xor(roundkeys[0], realroundkeys[0])
    keyafter = bytes_xor(roundkeys[10], realroundkeys[10])
    return aeskey, keybefore, keyafter

# --------------------------------------

def aes_decrypt(c):
    global aeskey, keybefore, keyafter
    if len(c) != 16:
        raise Exception
    cryptor = AES.new(aeskey, AES.MODE_ECB)
    m = cryptor.decrypt(bytes_xor(c, keyafter))
    return bytes_xor(m, keybefore)

def secure_encrypt(m):
    if len(m) != 16:
        raise Exception
    buf = m
    for i in range(1337):
        buf = aes_decrypt(buf)
    return buf

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

################################################################################

with open("./libsmartcard.so", "rb") as f:
    allcontent = f.read()
code_segment = allcontent[0x1000:0x1000+0x2a79] 
data_segment = allcontent[0x4000:0x4000+0x7f2ec]


global_libsmartcard = ctypes.CDLL("./libsmartcard.so")
#pw = bruteforce_baba_password()
#print(pw)

aeskey, keybefore, keyafter = recover_realkeys(recover_roundkeys())
'''
aeskey = bytes.fromhex("7e28a99358f40673cdb160f3ed02ebe2")
keybefore = bytes.fromhex("5dc00f4ecde50a22a5166e6d573f1f03")
keyafter = bytes.fromhex("19dcb026b0f57882e31dff9e85b437ff")
'''
print(aeskey.hex())
print(keybefore.hex())
print(keyafter.hex())

encrypted_token = encrypt_token(generate_token("root", generate_passwordhash("root", "123")))
print(generate_passwordhash("root", "123"))
print(encrypted_token)

