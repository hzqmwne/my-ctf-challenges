# Writeup

## Overview

This challenge is an emulation of **Compiler Backdoor**.  

## Background

Here are some definitions in this article:
- **bytes**: A sequence of binary bytes.  
- **program**: A **program** is some special **bytes** that reads some bytes as input, does some calculation, and writes some bytes out. It implicates a **mapping relation** about how to translate the *input* into *output*.  
- **source**: A **source** is some special **bytes** which also implicates a **mapping relation** between *input* and *output*, but its bytes are usually printable. Actually, **program** and **source** are the same thing in some concept.  
- **logic-equal**: It means the two **bytes** implicates the same **mapping relation**.  
- **bytes-equal**: It means the byte sequence of two **bytes** are exactly same. Obviously, **bytes-equal** implicates **logic-equal**, but the converse may not true.  
- **compile**: The **compile** is a special **mapping relation** that converts **source** to **program** while keeps them **logic-equal**.  
- **compiler**: A **compiler** is a special **program** that does **compile**.  

It is easy to find an inference: If two **program**s are **logic-equal** (but may not **bytes-equal**) and their *input*s are **bytes-equal**, their *output*s must be **bytes-equal**.  

### Bootstrapping

A **compiler** can **compile** any valid **source**s, include itself's. The technique of producing a self-compiling compiler is called ***[bootstrapping](https://en.wikipedia.org/wiki/Bootstrapping_(compilers))***.  
1. Use another **compiler** to **compile** the **source** of target **compiler** and get **program**1. Here, this another **compiler** may **NOT** be **logic-equal** to the **source** of target **compiler**.  
   Notice **program**1 is **logic-equal** to the **source** of target **compiler**.  
2. Use **program**1 to **compile** its **source** code and get **program**2.  
   Because the **compiler** to compile **program**2 and the **compiler** to compile **program**1 are not **logic-equal**, **program**2 and **program**1 are also **NOT** **bytes-equal**, but they should be both **logic-equal** to the original **source**.  
3. Use **program**2 to **compile** its **source** code and get **program**3.  
   Because **program**2 and **program**1 are **logic-equal**, their **compiler** result **program**2 and **program**3 must be **bytes-equal**.  
Now, no matter how many times we repeat stage3, the output **program** will always be **bytes-equal**, so **program**3 passes the final stable check and is a stable version and can be public released.  

### Compiler Backdoor

A backdoord compiler can automatically add malicious code when building special program.  
If we want to insert such a backdoor into a compiler, we should make it still preserved after bootstrapping and pass the final stable check.  

The backdoor in a malicious compiler's **source** looks like this:
```
input = readinput()
switch check_type(input):
    case "the special program":
	    output = compile_and_insert_backdoor_into_program(input)
		break
    case "the normal compiler's source":
        output = compile_and_insert_backdoor_into_compiler(input)
		break
	default:
	    output = compile(input)
writeoutput(output)
```

Let's see what will happen if we use this **source** to start bootstrapping procedure:  
- stage1: the another **compiler** is normal and will just **compile**, so the output **program**1 is **logic-equal** to this *malicious* **source**.  
- stage2: when malicious **program**1 runs with the malicious **source** as input, it will **NOT** trigger the "the normal compiler's **source**" logic because the input is "malicious **source**", so the result **program**2 is still **logic-equal** to this *malicious* **source**.  
- stage3: **program**2 runs with the malicious **source** as input then get **program**3, because **program**2 and **program**1 are **logic-equal**, their outputs **program**3 and **program**2 are **bytes-equal**.  
Obviously, it can still pass final stable check.  

But we want to hide backdoor code from the **source**. Notice stage1 needs an another **compiler**, what will happen if we use the malicious **compiler** and normal **source** to start bootstrapping?  
- stage1: the malicious **compiler** runs with normal code as input, it will trigger the "the normal compiler's source" logic, then get a special **program**1.  
- stage2: **program**1 runs with normal **source** as input and generates **program**2.  
- stage3: **program**2 runs with normal **source** as input and generates **program**3.  
We need to ensure **program**3 and **program**2 to be **bytes-equal**, so the **compiler**s that **compile**d them, which are **program**2 and **program**1, should be **logic-equal**.  
Also, **program**3 should be a malicious **compiler**, that means it should contain the `case "the normal compiler's source"` logic. As **program**3 **bytes-equal** to **program**2 and **program**2 **logic-equal** to **program**1, means **program**1 should contain the `case "the normal compiler's source"` logic as well.  
However, **program**1 is just generated by the `case "the normal compiler's source"` logic. That means, the `case "the normal compiler's source"` logic should output the `case "the normal compiler's source"` logic itself!  
In other words, the `compile_and_insert_backdoor_into_compiler(input)` logic should be a "[quine](https://en.wikipedia.org/wiki/Quine_(computing))", or at least, a "cheating quine".  

## Design

Inplementation a real compiler is too complex. But recall that a **compiler** is just a **program** that contains the logic which implicates a **mapping relation** between *input* and *output* while keeps them **logic-equal**.  
In this challenge, I define pure shellcode as **program** and its base64 encoding as **source**, so the **compile** logic is just doing base64 decode. This is really easy to imply, but can still show the core idea.  

To run the shellcode **program**, I also write a simple **linker**, which adds ELF header and Program Headers and generates a real ELF binary. A **fullcompiler** is a combination of **compiler**'s and **linker**'s **program** binaries.  
Then, I use [`memfd_create`](https://man7.org/linux/man-pages/man2/memfd_create.2.html) syscall (to create an anonymous file) and [`execveat`](https://man7.org/linux/man-pages/man2/execveat.2.html) syscall to perform fileless exec.  

## Solution

### reversing

#### main program
The command `strings babalogin | grep -i gcc` returns "GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0", so we know the `babalogin` binary is generated in Ubuntu 20.04 and statically linked glibc 2.31.   
IDA [FLIRT](https://hex-rays.com/products/ida/tech/flirt/) is the best way to recover libc function names. (Or if you like, you can do it manually ^_^)  

By reverse, there are three critical functions:
- sub_A24D: `run_binary`. It first forks, and in child process, perform the "fileless exec" and initializes a sandbox (seccomp whitebox: read, write, execveat; close all fds expect 0 and 1). Parent process sends input to child and retrives output from child by pipe.  
- sub_A497: `do_fullcompile`. Give a **fullcompiler** and a **source**, return the **compile**d binary **program**.  
- sub_A5BF: `do_fullcompiler_bootstrap`. Give a **fullcompiler** as well as the **source**s of a **compiler** and a **linker**, perform the *bootstrapping* procedure and return the new **fullcompiler**.  
- sub_A961: `main`. It first uses `raw_fullcompiler`(see below) to bootstrapping a `malicious fullcompiler`, then uses `malicious fullcompiler` to bootstrapping the `normal fullcompiler`, finally uses `"normal" fullcompiler` to **compile** the `mylogin` **source**. After these steps, it runs the final `mylogin` **program** by "fileless exec", but there is **NO** sandbox here.  
(see [babalogin.c](../src/babalogin.c) for details)

(Note: sub_A0F3 invokes the `close_range` syscall, so you need Linux kernel >= 5.9 to run `babalogin` binary. Or for local debug, you can just patch sub_A0F3 to nop)

#### shellcodes

- maliciouscompiler_source: 0xEC43C, base64 encoded
- maliciouslinker_source: 0xEE440, base64 encoded
- mycompiler_source: 0xEF440, base64 encoded
- mylinker_source: 0xEF7A0, base64 encoded
- mylogin_source: 0xEFBE0, base64 encoded
- raw_fullcompiler: 0xF0140, pure shellcode + length

It is a bit hard to reversing them, because `-Os` gcc optimizing is enabled on them. (Yes, all the shellcodes are generated from C source and build by gcc, see [Makefile](../src/Makefile))  
The "mycompiler" **program** just does an base64 decoding, and "mylinker" **program** just add ELF Header and Program Headers.  

But, the "mylogin" **program** is a trap! Here is part of its source code  
```
	x = (x << 22) >> 22;
	y = (y << 22) >> 22;
	z = (z << 22) >> 22;
	if (x*x*x + y*y*y + z*z*z == tocheck) {
```
(see [mylogin.c](../src/mylogin.c) for details)

It asks `username`, then `password`, and uses `username` to generate `tocheck`. The `username` must be "root" to pass the later check, but now `the tocheck` value will be 4.  
However, the "[sums of three cubes](https://en.wikipedia.org/wiki/Sums_of_three_cubes)" problem is unsolvable when the sum value is `9n±4` (see proof [here](https://math.stackexchange.com/questions/1509225/show-that-x3-y3-z3-4-has-no-solutions)).  

The x,y,z are signed int32_t and it seems there is integer overflow here. After `(x << 22) >> 22`, the x,y,z are in the range \[-1024, 1023\].  
So that `-3221225472 = -1024**3 *3 <= x**3+y**3+z**3 <= 1023**3 *3 = 3211797501`, the range is quite over the signed int32_t, which is \[-2147483648, 2147483647\].  
However, `4+k*0x100000000` is outside the range \[-3221225472, 3211797501\] when k != 0, so the only one possible sum value is 4, and 4 is proved no solution.  
(Or, just brute force `(x,y)` in `product(\[-1024,1023\],\[-1024,1023\])` and check if `4-x**3-y**3` has a integer cube root. The answer is exact not exists)  

### exploiting

In fact, you don't need to analyze the "mylogin" **program** at all. Back to the begin of `babalogin`, at 0xA9FA, the `scanf("%4095s", ...)` can read max to 4095 bytes into 0xED03C, and this will overwrite the original `maliciouscompiler_source` at 0xED43D
We can overwrite it with a backdoored compiler **source** (see above), which checks: if the input is `mylogin`'s **source**, output an open-read-write shellcode to get "flag.txt"; else if the input is `mycompiler`'s **source**, just output itself using PC-relative addressing, which is a "cheating quine"; else keep its origin logic.  
This will pass the first two bootstraps (at 0xAA26 and 0xAA65) and finally run your ORW shellcode without sandbox in sub_AAE4.  

## Reference

- [Reflections on Trusting Trust](https://www.cs.cmu.edu/~rdriley/487/papers/Thompson_1984_ReflectionsonTrustingTrust.pdf)  
- [如何评价 Ken Thompson 在 C 编译器里植入了后门这件事？](https://www.zhihu.com/question/26866999/answer/34335540): my inspiration for this challenge is from here  
- [给开源编译器插入后门](https://ring0.me/2014/11/insert-backdoor-into-compiler/)  

## Acknowledgment

Thanks to @[loser](https://github.com/YZloser) and @[G6](https://github.com/GANGE666) for testing this challenge.  

## Postscript

Why this challenge is called "babalogin"?  
- For "login", *Ken Thompson* gives an example about the UNIX login program in "`Reflections on Trusting Trust`".  
- For "baba", there are three reasons. First I really like the "[Baba Is You](https://hempuli.com/baba/)" game, and I think the game and this challenge has a same point: "changing the rules" (in this challenge, we overflow `maliciouscompiler_source`, and this changes the later **compile** rules). Second, "baba" echoes the background story of the challenge "[babylogin](../../babylogin)". Third, "baba" means harder than "baby", and it is true that "babalogin" is harder than "babylogin".  
