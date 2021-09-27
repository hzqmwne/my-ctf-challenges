# Writeup

## Overview

As the description of this challenge, there are three binaries which you should pay attention to:
- qemu-system-x86_64, with a new device "ss" added in it
- An kernel module "ss.ko" to interact with device
- An user land program "ss_agent" to interact with the kernel module

Each part contains a vulnerability, but you have to exploit them one by one in order:
- The final goal is to get the qemu pwned, then cat the flag.txt that outsides the guest vm
- When connect to server, you will get a shell with uid=1000 and gid=1000
- To communicate with the device directly, you must gain root privilege first
- The usual method to grab root privilege is pwning the kernel
- Device file ```/dev/ss``` has 0660 perm and its own:group is 1000:900, which is no permission for the shell uid/gid to access
- ```/challenge/ss_agent``` file's group is 900 and has SGID bit setted

So the full exploiting path is:
1. Pwn user land program ```ss_agent``` to gain permission of gid 900
2. Pwn kernel module ```/dev/ss``` with gid 900 to gain root privilege
3. Pwn qemu


## Intended Solution

### Stage0: analysis

Reversing is a bit tough because all the three binaries are stripped. And also, understanding qemu device and kernel driver needs some background knowledges. 
The first step is trying to recognize functions. You can just use your experience, or use some tools like IDA FLIRT, bindiff, diaphora, and so on. 

#### reversing qemu-system-x86_64

The source code of the ss pci device (see [ss_device.c](../src/ss_device.c) ) is modified from [edu.c](https://github.com/qemu/qemu/blob/stable-4.2/hw/misc/edu.c), and also the `OBJECT_CHECK` macro leaves file name and function name in the code. These are helpful for recognizing some important functions.  
```
sub_4F0370 -> ss_class_init
sub_4F0410 -> ss_instance_init
sub_4F04D0 -> pci_ss_realize
sub_6F98B0 -> timer_init_full
sub_4F0900 -> ss_dma_timer
sub_4F05D0 -> ss_mmio_read
sub_4F0640 -> ss_mmio_write
sub_6F9B20 -> timer_mod
```

The device registers a mmio bar. Read `ss_mmio_read` and `ss_mmio_write`, here are the actions when read/write at different offset with size 8:
| mmio offset | readable/writable | action                   |
| -           | -                 | -                        |
| 0x00        | r                 | get the magic const      |
| 0x10        | r                 | get the device status    |
| 0x18        | w                 | give command to device   |
| 0x20        | rw                | get/set dma block number |
| 0x28        | rw                | get/set dma bus address  |

There are four main statuses: closed (0), normal (1), busy (2), wait dma args (3), dma finished (0x14 for success, 0x24 for error).
The "command" decided how the "status" transfers: (first column is command, first row is old status, middle grid is new status )
|                 | closed (0) | normal (1)  | busy (2) | dma prepare (3) | dma complete (4) |
| -               | -          | -           | -        | -               | -                |
| to normal   (1) | normal     | normal      | -        | normal          | normal           |
| prepare dma (2) | -          | dma prepare | -        | -               | -                |
| start dma   (3) | -          | -           | -        | busy            | -                |

When device enters status "busy", the timer is setted to call `ss_dma_timer` **after 5ms**, which will fetch the memory block by the given "dma block number", and do DMA read/write from/to memory at the given "dma bus address".

The vulnerability in qemu-system-x86_64 is here: the check for block number is ">=0" and "<=0x100" (at 0x4F096F), but actually the total block count is only 0x100.
That means if the input block number is equals to 0x100, we can do one-block (4096 bytes) **overflow** read/write.  

#### reversing ss.ko

It is better to identify functions and structures by reading the header file of Linux kernel **5.4**.  This is the non-stripped file [ss.ko_with_debuginfo](https://github.com/hzqmwne/my-ctf-challenges/releases/download/Secure%20Storage/ss.ko_with_debuginfo).  
The kernel driver controls the device by mmio, transfers data by DMA and handles interupts.  Also, it provides the abstract of "slot" to userland program.  

There are 256 blocks inside the device and each block is 4096 bytes.  The driver groups 16 blocks into on slot and the total count of slots is 16.  The driver has pieces of cache memory for each slot.    
After an userland program open the "/dev/ss" device file, it should select a slot using `ioctl` system call, then it can use `mmap` syscall to map the slot cache memory in kernel into user memory space.  

But the dev_mmap function (sub_7E0) does not use `remap_pfn_range` to create the page table mapping immediately. Instead, it registers a page fault callback function which is `vma_fault` (sub_3E0).  
The driver caches the data block in memory (unk_3000), and uses a bitmap (byte_103000) to track status.  

When `vma_fault` is called, if the bit for such page is not marked in bitmap, it will call `readwriteblock` (sub_90) to fetch the block data from device then marks this bit in bitmap.  
And in function `dev_release` (sub_5F0), it writes all the marked page back into device and clears correlative bitmap bits. 

The vulnerability in ss.ko is in the `vma_fault` function: when caculating the offset of the absent page in the slot cache by `vmf->address` and `vma->vm_pgoff`, it truncates the origin unsigned 64-bit value into a **signed** 32-bit value then uses signed compare instruction (0x416) to check the value. So if the caculated offset value is an negative int32, there will be an **underflow**.  
 underflow. 

#### reversing ss_agent

It implements a single secret message store service. Users can select a slot, write some message and set a password. Only one who knows the password can retrieve the stored message.  

The vulnerability is in kick_out_last_registered_user function (sub_A1D5): As long as the input admin key is correct, the "global_username" pointer can be freed (at 0xA355) and not set to NULL, **double free**. 
(It is very easy to find this in decompiled code, but in source code [ss_agent.c](../src/ss_agent.c#L284), the bug is just caused by missing the braces of an "if" statement and may be ignored by programmer)  


### Stage1: leak admin_key

So, we have to manage to leak the admin_key to start the pwnings.  
Take care of the admin_key checking logical in the "kick_out_last_registered_user" menu, it is easy to find it compares the user input key with the correct key byte by byte ( my_memcmp (sub_9A48) ).  
However, a secure password comparison implementation should be content-independent and take constant time. (Recall that OpenSSL provides such a `CRYPTO_memcmp` function)  

Because this program checks admin_key byte by byte, when we guess the first byte of the admin_key correctly it will continue to check the second byte, and this takes more time than guessing wrongly.  
However, the time difference is too small to be detected, obviously. We should find a method to enlarge it.  

Have a look at the memory layout around admin_key: 
| 8 bytes     | message_len bytes | 32 bytes  |
| -           | -                 | -         |
| message_len | message           | admin_key |

The message is the user name we have input in "register_user" menu, which means its length and content can be fully controlled.  

Notice that the max allowed length of message is 9999, which is larger than one PAGE (4096), so we can control the message length, and **force the first byte of admin_key located at the last byte position of the first mmapped PAGE, and left the other bytes of admin_key located at the second mmapped PAGE**. 
At the first time the program accesses the mmapped PAGE, it will trigger the hardware PAGE FAULT exception. Then, kernel catches it and calls the `vma_fault` (sub_3E0) function, fills in the page table mapping of this virtual address with the kernel cache page so later memory accesses on virtual address of this PAGE will no longer trigger PAGE FAULT exception.  

Just before the byte-by-byte memcmp on admin_key, the program accesses the message_len part memory (see .text 0xA27F), so **the first page has already get a physical page mapping in hardware page table, and this memory access instruction takes very little time**.  
But it is not true for the second mmapped page.  If the program accesses the second page, it will trigger hardware page fault, then goto kernel `vma_fault` function. Because the bitmap is not marked, kernel will finally interact with the device to fetch data, and this will **take at least 5ms** ! (see [above analysises](#reversing-qemu-system-x8664), the 5ms delay before doing DMA in qemu is added deliberately)  

Also, there is a `puts("Checking...");` just before the byte-by-byte memcmp function, and a `puts("Error: key error");`/`puts("Pass check");` just after it, which accurately indicates the start time and end time of the memcmp operation.  

Now we can leak the admin_key byte by byte: guess the first byte, 
    - if the guessing is **wrong**, the byte-by-byte memcmp will return intermediately, and the second byte (at the second page) will not be accessed. In my test, it only takes **80us** in this situation. (and very seldom the time difference can be about 1000us, but never larger than 5000us)
    - if the guessing is **correct**, the byte-by-byte memcmp will try to compare the second byte, and then accesses the second mmapped PAGE memory. In this case, the time difference is exactly larger than **5000us** .
For one byte, we can find the correct value in no more than 62 times attempts. 

Repeat these 32 times until all the admin_key bytes are known to us.  

Finally, 80us vs 5ms is still indistinguishable if you try to interact with server's ss_agent from your local computer by pwntools because the network latency and fluctuation is much longer than that. So you have to write the interact logic in C language, then upload the binary to server and run it "locally" on the server.  


### Stage2: userland pwn

Run `strings ss_agent | grep -i "gcc"` will show `GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0`, but actually it is statically linked with [glibc 2.27 ubuntu1.2](http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_2.27-3ubuntu1.2_amd64.deb ) version (not 2.31).
Tcache in this version's glibc does not have double free detection, so the vulnerability is easy to exploit.

Through the `register_user` function, we can alloc a heap chunk with any size (less than 10000) then place any bytes (except '\n') at it, and it is very good that there is no '\0' truncation.  
Through the `kick_out_last_registered_user` function, we can free this heap chunk any number of times.   

Although we can only hold one heap pointer at a time, this is enough to get the arbitrary alloc primitive:  
1. alloc a heap chunk within tcache size range (less equal than 0x408).  
2. free the heap chunk.
3. free the heap chunk again, now there will be a loop in this size's tcache single linked list.
4. alloc once with this size and place the target memory address in the alloced chunk, now the first two items in tcache list will be the heap chunk and target memory address.  
5. alloc once with this size again.
6. alloc once, this pointer returned by malloc is the target memory address.  
Further more,
for arbitrary write primitive: alloc at target address, and give target value bytes when program asks "What is your name ?";  
for arbitrary read primitive: alloc at target address, and give a single '\n' byte when program asks "What is your name ?", then receive the bytes after the program prints "Hello ".

Because the program is built with `--static-pie` compilation option, its TLS (Thread Local Storage) region and Heap region are merged together, which means **the offset between TLS's var address and heap chunk address is a fixed value**. And it is also important that **there are program address and stack address in the TLS region**.  

Leak heap address is easy: just free one heap chunk into tcache twice continuously, then alloc it and get the first 8 bytes, which is the `fd` field of `struct malloc_chunk` and is a pointer of a heap address.  
Then, add an offset on the leaked heap address to get the address where stores a program address and a stack address, and use the arbitrary read primitive to leak them.  
Finally, use the arbitrary alloc primitive to alloc a chunk at stack, and replace the function return address with a ROP chain (the address of ROP gadgets can be caculated by the leaked program address). When the function returns, the ROP chain will be triggered and the program is fully compromised by us.  

During my test, when **ASLR is enabled** (this is oblivious true on remote server), in the TLS-Heap region, a QWORD at offset 0x858 is a pointer to the `main_arena` var at program, and a QWORD at offset 0xb80 is a pointer to the environ vars at stack. And 0xb80-0x858=0x328 that is less than max tcache size (0x408), so we can leak the two values at a time when alloc a fake chunk at 0x858.  
However, it is a bit confusing that when ASLR is disabled, the two offsets will have different values, and I don't know the reason.  Also, sometimes the last 12 bits of the leaked heap address will also have a little difference, but this doesn't matter because we can just `& ~0xfff` to hide the difference.  

How to debug this program is another problem, because it needs `/dev/ss` kernel module and the kernel module needs the modified `qemu-system-x86_64` so cannot run under normal environment. Here are some methods:  
- The quickest way is patching the program, removing all the interacts with `/dev/ss` and only preserving heap malloc/free operations.  
- Another way is starting `qemu-system-x86_64` with its gdb stub, then add breakpoint at userland memory address. Yes, gdb will break at userland when user program executing to that address, but gdb will not recognize the user program binary so it is not convenient.  
- The best way I think is copying a statically linked gdbserver in guest os and forwarding its interface to the outside of qemu:  
  - Forwarding a serial: add command line parameter `-serial mon:stdio -serial tcp::3234,server,nowait` to qemu-system-x86_64 (and remove the `-monitor none` parameter), this will add to serial devices into qemu: `/dev/ttyS0` for the default console which is forwarded to stdio, and `/dev/ttyS1` which is forwarded to host tcp listen port 3234. Then, **keep ASLR enabled**, start debugger inside qemu by `gdbserver --no-disable-randomization /dev/ttyS1 /challenge/ss_agent`. Finally, do gdb attach to tcp 3234 port from host normally, and start the debugging progress.  
  - Or, Forwarding network, but this is more complex: add command line parameter `-nic user,hostfwd=tcp::2234-:1234` to qemu-system-x86_64 to enable port forwarding, then download the [linux-modules](http://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux-modules-5.4.0-77-generic_5.4.0-77.86_amd64.deb) deb package of this kernel, extract the NIC driver `e1000.ko`, copy it into qemu and insmod it by `insmod e1000.ko` to enable network device in guest os. Then, configure DHCP client in guest os by `udhcpc -i eth0 -s /etc/udhcp/simple.script` command (Note: `/etc/udhcp/simple.script` is copied from [`examples/udhcp/simple.script`](https://git.busybox.net/busybox/tree/examples/udhcp/simple.script) in busybox source code and must have executable permission). After doing all above, the network has been unobstructed. Finally, start gdbserver by `gdbserver --no-disable-randomization 0.0.0.0:1234 /challenge/ss_agent` in qemu and do gdb attach to tcp 2234 port from host.  

Because qemu stdio is the guest OS's Serial TTY, there are some extra problems about it: the TTY echos back the input, the TTY output uses "\r\n" instead of "\n" as newline separator, the TTY input triggers some special characters as SIGNAL (for example, input "\x03" will cause a SIGINT sent to program) or terminal control, and so on.  
To avoid these interferences, one way is still writing exp in C language to interact with program through PIPE and uploading it on server, just the same as Stage1. In fact, this is not necessary. 
Typing `stty raw ; stty -echo` in guest OS's shell, this will disable all escape behaviors of TTY (To recover, use `stty -raw ; stty echo` or `reset`). Then, you can use Python to write the exp and connect to remote server using pwntools from local as normal.  

Another issue that needs attention is how to preserve the SGID permission to a interact shell.  
If you just do `execve("/bin/sh", NULL, NULL)` using ROP, you may find the GID in the new shell is still 1000, not 900.  
The reason is that execving a SET-GID program only changes EGID, but the `/bin/sh`(`busybox`) program will reset EGID with real GID when they are not the same.  
Solution for this issue is doing `gid_t egid = getegid(); setresgid(egid, egid, egid);` before execving `/bin/sh`.  You can do this in the ROP chain, or more simply, execve a [loader program](./bin_sh_loader.c) instead of the original `/bin/sh`.  

To reduce the network transmission of exp binary file uploading, use musl libc instead glibc and disable server echo by typing `stty -echo` on remote server.  

After finishing this stage, you can access the `/dev/ss` driver freedomly, and read the content of `/challenge/secret2.txt` file.  


### Stage3: kernel pwn

The most critical function in `ss.ko` is `sub_3E5`, which is the `vma_fault` callback function when page fault is triggered.  
According to the [source code of Linux 5.4](https://elixir.bootlin.com/linux/v5.4/source/include/linux/mm.h#L417), we can recovery the `vm_fault` struct (notice the prototype of struct vm_fault and function vma_fault are different in various version Linux source code).  

Here is the code with debug info:
```C
vm_fault_t __fastcall vma_fault(vm_fault *vmf)    // sub_3E0 & sub_3E5
{
  int v2; // eax
...
  v2 = (LODWORD(vmf->vma->vm_pgoff) << 12) + ((vmf->address - vmf->vma->vm_start) & 0xFFFFF000);
  if ( v2 <= 0xFFFF )
...
}
```

`vm_pgoff`, `address` and `vm_start` are all **unsigned** `uint64_t` values, but here converts them to **signed** `int32_t` forcely. And most important, at .text 0x416 there is a **signed** cmp-jmp: `jg      loc_4CE`, it only checks the upper bound but does **NOT** check the **lower bound**, so there is an **underflow**.  
(This is the only one intended vuln in `ss.ko`. I try to avoid concurrent bugs so there are lots of lock operations in code, but I still cannot fully confirm this.)

Now its time to think how to use this vuln. Recall the prototype of mmap syscall `void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);`: `vm_pgoff` corresponds to `offset`, `vm_start` corresponds to `addr`, `address` corresponds to the real memory access virtual address who triggers page fault, and all the three values are fullly controlled from userland.  
So, control these values and let the final `v2` value be a negative int32, we can choose a page from the under 4GB range as the returned `vmf->page`.  

The first impression may be finding a rw page contains a function pointer then using this vuln to map it into userland address space and modifying it, but the simplest way is mapping the kernel code memory page into userland. Because we do this through kernel api, such isolation protections (e.g. *smep*, *smap*, *pti*) are all bypassed.  
Although kernel code page vaddr is read only in kernelspace, but if we manage to map its related physical page into usersapce, we will gain the ability to modify it from userland! Then we can just rewrites the code with the `commit_creds(prepare_kernel_cred(0))` shellcode. And another good news is that there is no [Function Granular KASLR](https://lwn.net/Articles/817605/) in this kernel.  

This page should be alloced by vmalloc, because `vmalloc_to_page` is called later on its vaddr. A good message is that the kernel module memory is just alloced by vmalloc and its code section and data section have a fixed offset.  
(There is a little pit: ss.ko's .bss section starts at module base offset 0x2000 in IDA, but the real offset in memory is 0x3000. Dynamic debug is needed to find this. )
Also, we should let the bittest at ss.ko 0x4A3 success to avoid enter the complex device interaction process. This can be easily done by mapping the bitmap memory page into userspace and filling it with 0xff.  

In userland, call `mmap` syscall with `MAP_SHARED`(important!) flag and size larger than UINT32_MAX(0x100000000).  
It seems not necessary to add a `MAP_NOPRESERVE` flag, but the `MAP_SHARED` flag cannot be replaced by `MAP_PRIVATE`, because we must ensure just this page setted to vmf->page at 0x45d will be added into page table. But if the map is private, kernel will alloc a new page, just copy the data and free the old page. See [this article](https://zhou-yuxin.github.io/articles/2018/%E6%B7%B7%E5%90%88%E5%86%85%E5%AD%98%E7%B3%BB%E7%BB%9Fhybridmem%EF%BC%88%E4%BA%8C%EF%BC%89%E2%80%94%E2%80%94MAP_SHARED%E3%80%81MAP_PRIVATE%E4%B8%8ECOW/index.html) for details.  

How to debug: just use qemu's gdb stub (*-s*/*-gdb dev* option). Although the `ss.ko` is stripped (--strip-unneeded), its base load address can still be found from `/proc/moudles`, this address is also the `sub_0` function. To gain root privilege, modify the /etc/inittab file or add an set-uid root file in initramfs.cpio.  

After finishing this stage, you will get root privilege in the guest os, and cat read the content of `/challenge/secret3.txt` file.  


### Stage4: qemu pwn

After reversing qemu-system-x86_64, we can find the block number off-by-one vuln at 0x4F096F, and this value will be transfered to two indirect function call at 0x4F0AD6 and 0x4F09A0.  
By dynamic debuging, it is easy to find when block number is 0x100, the overflow page contains such two function pointers.  

Then, we should reverse the device mmio interaction protocol (see [Stage0](#reversing-qemu-system-x8664)) and notice all data blocks storaged into device are transparently encrypted by function `sub_4F0810` (That's why this challenge is called *"Secure"* Storage).  
First leak qemu process base address from this two function pointers, then caculate the real address of `system@plt`, cover the function pointer with its encrypted value.  Also, the pointing content of first arg when the two funtion pointer called is also controlled (which is the first storage block), just set the content to `"/bin/sh\0"`. Finally, trigger the indirect call will actually call `system("/bin/sh")`.  

Notice that the kernel module contains underflow but no overflow and qemu contains overflow but no underflow, so userland program cannot trigger this qemu device vuln through kernel module.  
So we have to finish stage3 before, and then with root privilege, we can interact with device directly.  

One way to access device mmio space is writing a kernel module and replace `ss.ko`. The kernel header files can be downloaded from [ubuntu packages](https://packages.ubuntu.com/focal/linux-headers-5.4.0-77-generic).  
But the simplest way to access device mmio space from userland is by mmaping the `"/sys/devices/pci0000:00/0000:00:0?.0/resource0"` file from a root privileged process.  
Devices use bus address to perform DMA memory access. As IOMMU is not enabled in kernel, bus address is equal to physical address. Process with root privilege can get physical address from virtual address from `"/proc/self/pagemap"` file (see [this](https://www.kernel.org/doc/Documentation/vm/pagemap.txt)).  

A little pit here is that only bus-mastering enabled PCI device can initiate DMA (see [this](https://en.wikipedia.org/wiki/Bus_mastering)). In this challenge, `ss.ko` kernel module has already done this by calling `pci_set_master` (see [this](https://www.kernel.org/doc/htmldocs/kernel-api/API-pci-set-master.html)), but if there is no such kernel driver, we should manually enable this flag from userland through `"/sys/devices/pci0000:00/0000:00:0?.0/config"` file.  

To debug, just use gdb to attach on `qemu-system-x86_64` process itself. Notice if you start qemu process directly from terminal (that means its stdio is tty/pty), when `system("/bin/sh")` is executed, the shell cannot response you input; but if qemu's stdio is socat, there is no problem. I don't know the reason, and I suggest using `socat tcp-l:<port>,fork,reuseaddr exec:./start.sh,stderr,setsid` to launch the debug environment (the *setsid* argument is important here).  

After finishing this stage, the challenge is now fully solved and you can read the final `flag.txt` file on host.  


## Reference

- [Page 6-8 of this slides](https://ipads.se.sjtu.edu.cn/courses/csp/2018/slides/lec01.pptx): my inspiration for this challenge is from here
- [\[Official Write-up\] HITCON CTF Quals 2019 - Path of Exploitation](https://david942j.blogspot.com/2019/10/official-write-up-hitcon-ctf-quals-2019.html): a very good user-kernel-qemu three stages challenge with detailed explaination
- [How to add a new device in QEMU source code?](https://stackoverflow.com/questions/28315265/how-to-add-a-new-device-in-qemu-source-code)
- [Qemu edu device](https://github.com/qemu/qemu/blob/stable-4.2/hw/misc/edu.c)
- [A kernel driver for the qemu edu device](https://github.com/cirosantilli/linux-kernel-module-cheat/blob/master/kernel_modules/qemu_edu.c): `ss_driver.c` refers this code
- Details about mmap, page fault and COW: [1](https://zhou-yuxin.github.io/articles/2018/%E6%B7%B7%E5%90%88%E5%86%85%E5%AD%98%E7%B3%BB%E7%BB%9Fhybridmem%EF%BC%88%E4%B8%80%EF%BC%89%E2%80%94%E2%80%94%E4%BD%BF%E7%94%A8mmap%E4%B8%8Epage%20fault%E4%B8%BA%E5%BA%94%E7%94%A8%E7%A8%8B%E5%BA%8F%E5%88%86%E9%85%8D%E5%86%85%E5%AD%98/index.html)  [2](https://zhou-yuxin.github.io/articles/2018/%E6%B7%B7%E5%90%88%E5%86%85%E5%AD%98%E7%B3%BB%E7%BB%9Fhybridmem%EF%BC%88%E4%BA%8C%EF%BC%89%E2%80%94%E2%80%94MAP_SHARED%E3%80%81MAP_PRIVATE%E4%B8%8ECOW/index.html)
- [Writeup from r3kapig](https://mem2019.github.io/jekyll/update/2021/07/06/TCTF2021-Secure-Storage.html): a detailed writeup from player's respective
- [Writeup from perfect blue](https://github.com/perfectblue/ctf-writeups/tree/master/2021/0ctf-2021-quals/secure_storage): the only one team who gets final flag in the course of the event


## Acknowledgment

Thanks to @[loser](https://github.com/YZloser) and @[coc-cyqh](https://github.com/coc-cyqh) for testing this challenge.  

## Postscript

Only Stage1 is the core points of this challenge originally, and I want to imply the page fault time delay as normal as possible, so I wrote the kernel module with an emulated device as well as the userland agent program.  
The idea for this challenge was formed one year ago before 0CTF/TCTF 2020 Quals, and I finished first 3 stages (leak admin_key, user pwn, kernel pwn) before 0CTF/TCTF 2020 Finals. Due to the TTY pit in Stage2, I would not manage to exploit Stage2, so this challenge was not released.  
In this year, I replaced the emulated device in kernel with a "true" device in qemu, added Stage4 and successfully exploited all stages, so you would see this challenge in 0CTF/TCTF 2021 Quals.  

This challenge is actually a combination of 4 challenges, `admin_key.txt`, `secret2.txt`, `secret3.txt` and `flag.txt` are four stage flags.  
However, because my core points is only Stage0 and the difficulty of 4 stages is decreased stage by stage, and one of the testers said first blood of final flag will appear in 12 hours due to the vulns are too simple, I finally decided to only release the final flag, and this brings a bad experience to players.  
