from pwn import *
import base64

context.arch = "amd64"


def ROR(a, b):
    a &= 0xffffffff
    b &= 0xffffffff
    r = (a >> b) | (a << (32-b))
    return r & 0xffffffff


def CH(x, y, z):
    return (x & y) ^ ((~x) & z)


def MAJ(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def EP0(x):
    return ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22)


def EP1(x):
    return ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25)


def SIG0(x):
    return ROR(x, 7) ^ ROR(x, 18) ^ (x >> 3)


def SIG1(x):
    return ROR(x, 17) ^ ROR(x, 19) ^ (x >> 10)


def sha256_transform(state, block):
    assert len(state) == 8
    assert len(block) == 64

    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    m = [None] * 64
    for i in range(16):
        m[i] = int.from_bytes(block[4*i:4*(i+1)], "big")
    for i in range(16, 64):
        m[i] = (SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16]) & 0xffffffff

    a, b, c, d, e, f, g, h = state
    for i in range(64):
        # if i % 4 == 0:
        #     print(hex(a), hex(b), hex(c), hex(d), hex(e), hex(f), hex(g), hex(h))
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i]
        t2 = EP0(a) + MAJ(a, b, c)
        e, f, g, h = (d + t1) & 0xffffffff, e, f, g
        a, b, c, d = (t1 + t2) & 0xffffffff, a, b, c

    new_state = tuple((t1 + t2) & 0xffffffff for t1, t2 in zip(state, (a, b, c, d, e, f, g, h)))
    return new_state


def sha256_padding(s):
    raw_len = len(s)
    roundup_len = ((raw_len + 8 + 1 - 1) // 64 + 1) * 64
    r = s + b'\x80' + b'\x00' * (roundup_len - 8 - 1 - raw_len) + (raw_len * 8).to_bytes(8, "big")
    return r


def sha256_sum(s, padding=True):
    state = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)
    if padding:
        s = sha256_padding(s)
    else:
        assert len(s) % 64 == 0
    for i in range(0, len(s), 64):
        block = s[i:i+64]
        state = sha256_transform(state, block)
    return b''.join(t.to_bytes(4, "big") for t in state)


def build_elf64_ehdr():
    e_ident = b'\x7fELF' + b'\x02\x01\x01\x00' + p64(0)    # unsigned char e_ident[EI_NIDENT];     /* Magic number and other info */

    e_type = p16(2)            # Elf64_Half    e_type;                 /* Object file type */
    e_machine = p16(0x3e)      # Elf64_Half    e_machine;              /* Architecture */
    e_version = p32(1)         # Elf64_Word    e_version;              /* Object file version */
    e_entry = p64(0x400078)    # Elf64_Addr    e_entry;                /* Entry point virtual address */

    e_phoff = p64(0x40)        # Elf64_Off     e_phoff;                /* Program header table file offset */
    e_shoff = p64(0)           # Elf64_Off     e_shoff;                /* Section header table file offset */

    e_flags = p32(0)           # Elf64_Word    e_flags;                /* Processor-specific flags */
    e_ehsize = p16(0x40)       # Elf64_Half    e_ehsize;               /* ELF header size in bytes */
    e_phentsize = p16(0x38)    # Elf64_Half    e_phentsize;            /* Program header table entry size */
    e_phnum = p16(1)           # Elf64_Half    e_phnum;                /* Program header table entry count */
    e_shentsize = p16(0)       # Elf64_Half    e_shentsize;            /* Section header table entry size */
    e_shnum = p16(0)           # Elf64_Half    e_shnum;                /* Section header table entry count */
    e_shstrndx = p16(0)        # Elf64_Half    e_shstrndx;             /* Section header string table index */

    elf64_ehdr = e_ident \
        + e_type + e_machine + e_version + e_entry \
        + e_phoff + e_shoff \
        + e_flags + e_ehsize + e_phentsize + e_phnum + e_shentsize + e_shnum + e_shstrndx

    return elf64_ehdr


def build_elf64_phdr():
    p_type = p32(1)            # Elf64_Word    p_type;                 /* Segment type */
    p_flags = p32(7)           # Elf64_Word    p_flags;                /* Segment flags */
    p_offset = p64(0)          # Elf64_Off     p_offset;               /* Segment file offset */

    p_vaddr = p64(0x400000)    # Elf64_Addr    p_vaddr;                /* Segment virtual address */
    p_paddr = p64(0x400000)    # Elf64_Addr    p_paddr;                /* Segment physical address */

    p_filesz = p64(0x1000)     # Elf64_Xword   p_filesz;               /* Segment size in file */
    p_memsz = p64(0x2000)      # Elf64_Xword   p_memsz;                /* Segment size in memory */

    p_align = p64(0x1000)      # Elf64_Xword   p_align;                /* Segment alignment */

    elf64_phdr = p_type + p_flags + p_offset \
        + p_vaddr + p_paddr \
        + p_filesz + p_memsz \
        + p_align

    return elf64_phdr


shellcode_asm = '''

start:
    mov edi, 0x401200
    mov esi, 0x400200
    mov ch, 0xe
    rep movsb

    sub rsp, 64*4
    push rsp
    pop rdi
    call init_sha256_k_table
    push rsp
    pop rdx

    mov eax, 0x401000
    mov byte ptr [rax], 0x80
    mov al, 0x3e
    mov byte ptr [rax], 0x80

    mov edi, 0x401e00
    push 16
    pop rcx
mainloop1:
    push rcx

    mov esi, 0x400e00
    push 9
    pop rcx
mainloop2:
    push rsi
    push rcx
    call sha256_transform_internal
    pop rcx
    pop rsi
    add esi, 64
    loop mainloop2

    // now rdi points to little-endian [f,e,b,a,h,g,d,c], but we want big-endian [a,b,c,d,e,f,g,h]
    xchg rdi, rsp
    pop rax
    pop rcx
    pop rsi
    pop rbp
    bswap rcx
    bswap rbp
    bswap rax
    bswap rsi
    push rsi
    push rax
    push rbp
    push rcx
    xchg rdi, rsp

    add edi, 32
    pop rcx
    loop mainloop1

    xor edx, edx
    mov dh, 0xe
    mov esi, 0x401200
    push 1
    pop rdi
    push 1
    pop rax
    syscall

    xor edi, edi
    push 0x3c
    pop rax
    syscall
    hlt


// [out]rdi: unsigned int K[64];

init_sha256_k_table:
    push 3
    pop rax
    cvtsi2sd xmm3, eax
    xor edx, edx
    dec edx
    inc rdx
    cvtsi2sd xmm5, rdx

    lea rsi, [rip+CONSTS1]
    xor ecx, ecx
L0:
    xor eax, eax
    lodsb
    push rcx
    and ecx, 1
    jnz L00
    shr al, 4
    dec rsi
L00:
    and al, 0xf
    add edx, eax
    cvtsi2sd xmm2, edx

    // 14 is the minimal iteration count
    push 14
    pop rcx
    movaps  xmm0, xmm2
L1:
    movaps xmm4, xmm0
    mulsd xmm4, xmm0
    movaps xmm1, xmm2
    divsd xmm1, xmm4
    addsd xmm0, xmm0
    addsd xmm0, xmm1
    divsd xmm0, xmm3
    loop L1
    mulsd xmm0, xmm5
    cvttsd2si rax, xmm0
    stosd

    pop rcx
    inc ecx
    cmp ecx, 64
    jl L0

    ret

CONSTS1:
    .byte   33, 34, 66, 66, 70, 38, 66, 70, \
            98, 100, 38, 70, 132, 36, 36, 228, \
            98, 162, 102, 70, 98, 162, 66, 204, \
            66, 70, 42, 102, 98, 100, 42, 228


// [in,out]rdi: unsigned int state[8] = { F, E, B, A,  H, G, D, C };
// [in]rsi: const unsigned char block[64];
// [in]rdx: const unsigned int K[64];

sha256_transform_internal:
    enter 512, 0
    push rsp
    pop rax
    push rdi
    push rax
    pop rdi

    push 16
    pop rcx
L20:
    lodsd
    bswap eax
    stosd
    loop L20

    pop rdi

    push 8
    pop rcx
L2:
    movups xmm1, [rsp+8*rcx-16*4]
    sha256msg1 xmm1, xmm0
    movups xmm0, [rsp+8*rcx-7*4]
    paddd xmm1, xmm0
    movhps xmm2, [rsp+8*rcx-2*4]
    sha256msg2 xmm1, xmm2
    movups [rsp+8*rcx], xmm1
    inc ecx
    cmp ecx, 32
    jl L2

    // rdi point to [f,e,b,a,h,g,d,c], which are all little-endian
    // ABEF from 127..0
    movups xmm6, [rdi]
    movaps xmm2, xmm6
    // CDGH from 127..0
    movups xmm5, [rdi+0x10]
    movaps xmm1, xmm5

    xor ecx, ecx
L3:
    // m
    movups xmm0, [rsp+8*rcx]
    // K
    movups xmm3, [rdx+8*rcx]
    paddd xmm0, xmm3
    sha256rnds2 xmm1, xmm2
    movhlps xmm0, xmm0
    sha256rnds2 xmm2, xmm1
    // now, xmm1 is H G D C in little endian, xmm2 is F E B A in little endian
    add ecx, 2
    cmp ecx, 32
    jl L3

    paddd xmm6, xmm2
    paddd xmm5, xmm1

    movups [rdi], xmm6
    movups [rdi+0x10], xmm5

    leave
    ret
'''

shellcode = asm(shellcode_asm)
print(len(shellcode))
assert len(shellcode) <= 392    # 4096-0xc00-32*16-64-56 = 512-128+8 = 256+128+8 = 384+8 = 392



N_PROGRAMS = 16

s = process("../src/interweave")
# s = remote("127.0.0.1", 12022)
# s = remote("202.112.28.106", 8888)
'''
s = remote("101.132.105.41.nip.io", 22022)
instance_uuid = "881476eaafe24ee994458c66e8829d78"
instance_uuid = "f495e22329bb48598a3a140ae27bc802"
instance_uuid = "13891f0e5eb946efb3a00831ba66b2c6"
s.send(f"CONNECT {instance_uuid} HTTP/1.1\r\n\r\n".encode())
s.recvuntil("\r\n\r\n")
'''

messages = [None] * N_PROGRAMS
programs = [None] * N_PROGRAMS

for i in range(N_PROGRAMS):
    r = s.recvline()
    messages[i] = base64.b64decode(r)

part2 = b""

for i in range(N_PROGRAMS):
    assert len(messages[i]) == 0xc00
    assert len(shellcode) <= 392
    part1 = build_elf64_ehdr() + build_elf64_phdr() + shellcode.ljust(392) + messages[i]
    programs[i] = part1
    middlestate_bytes = sha256_sum(part1, padding=False)
    a, b, c, d, e, f, g, h = [int.from_bytes(middlestate_bytes[i:i+4], 'big') for i in range(0, len(middlestate_bytes), 4)]
    middlestate_bytes_for_calculate = b''.join(tmp.to_bytes(4, 'little') for tmp in (f, e, b, a, h, g, d, c))
    part2 += middlestate_bytes_for_calculate

for i in range(N_PROGRAMS):
    programs[i] += part2

for i in range(N_PROGRAMS):
    s.sendline(base64.b64encode(programs[i]))

s.interactive()
