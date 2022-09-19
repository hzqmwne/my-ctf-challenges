# Writeup

## 概述

两个程序，在不借助外界辅助的前提下，能否获知到对方的哈希并输出？  

（显然，平凡的情况是两个程序完全相同，由于程序在运行中可以读取自己的内存，所以可以计算出自己的哈希，这也是对方的哈希。）  

但在一般情况下， 如果把哈希函数看作一个黑盒的单向映射，答案当然是不能：因为要得到哈希的值必须先有被哈希的内容，即hash1依赖program1，hash2依赖program2；另外由于不能从外界获取信息，program1只有把hash2硬编码在自己内部才能输出，即program1依赖hash2，同理有program2依赖hash1，产生了循环依赖，从而无解。  

注意到主流哈希函数库暴露的接口一般都是 Init, Update, Final，实际上哈希的计算并不是把输入作为一个整体，而是从一个初始状态开始，以块为单位不断更新这个状态，直到计算结束。  

所以，对于长消息的哈希计算，可以先用前半部分计算出哈希中间状态，然后以这个中间状态初始化哈希函数，再对后半部分正常计算。这样即使不知道前半部分的具体内容，也可以得到正确的哈希结果。  

结合一下刚刚提到的平凡情况，可以得到一种解决此问题的方法：把两个程序各自分为两部分，其中program1-part1和program2-part1可以包含任意的逻辑；然后，对它们分别计算哈希得到两个中间状态；把这两个哈希中间状态合在一起作为part2，同时附加到两个part1之后，得到完整的两个程序。两个程序运行时可以从自己内存的part2中读取到对方part1计算出来的哈希中间状态，然后接上自己的part2完成最终哈希的计算，由于自己的part2与对方的相同，因此计算出的哈希等于对方的哈希，从而避免了循环依赖。  

## 背景

Intel SGX (Software Guard Extensions) 是一组指令集扩展，为用户态的应用程序提供了一段隔离的内存（Enclave），这部分内存无法被具有特权的内核甚至虚拟机监控器所访问，因此适合完成机密计算。  

除此之外，SGX 还提供了远程认证（Remote Attestation）机制，外界可以借此检查对端是否运行在真实的受保护的 SGX Enclave 中，以及其中的内存度量值是否符合预期。  
完整的 Remote Attestation 机制非常复杂。一个不严谨的(甚至是错误的)简化理解，可以认为，硬件能够为当前正在运行的 Enclave 的一些状态生成报告（Report）（允许携带自定义附加信息）并签名，随后 Report 被软件逻辑处理后生成 Quote 发给验证者，验证者可以向 Intel 的公开 IAS 服务验证 Quote 的有效性，从而信任 其中 Report 的内容。  
换句话说，验证者可以获得一份包含远程 Enclave 信息的 Report，并且这份 Report 是无法被篡改的。  

在 Report 中有一个重要的字段是 mr_enclave，这个值是 Enclave 的元数据以及加载到初始化完成时的内存度量值（简单(但不严谨)的理解，可以认为是初始化完成时刻的内存的 SHA256 值）。  
通常，远程认证的发起者就是 Enclave 的构建者。由于加载和初始化的过程是确定性的，因此可以将远程认证获取到的 mr_enclave 值与构建时计算出的值进行对比，如果一致则认为远程环境是可信的。通常，Enclave的构建者会在 Report 的自定义附加信息中放置一个公钥并确保私钥始终不暴露到Enclave外部，验证者可以通过此公钥与Enclave构建加密通信信道，从而将私密数据安全的传输到SGX内部。  

> 这套机制给人感觉最初是为DRM场景定制的，而且也已经得到了实际应用，例如电脑上播放正版4K蓝光光盘需要开启SGX特性（类似的，手机端的DRM机制Widevine则是基于ARM TrustZone的隔离环境实现的）。Intel桌面端CPU从第6代即开始支持，但是从11代开始却被删除了（也许是因为使用场景没有铺开，同时硬件实现又过于复杂，出于成本考虑所以砍掉；亦或是因为无法防御层出不穷的侧信道攻击和物理攻击导致机密内存有极高风险被窃取），只在服务器端CPU保留（目前看来应该是逐渐让位给了TDX(Trust Domain Extensions，硬件隔离的可信虚拟机)）。  

原始的 Remote Attestation 机制只考虑了单向认证的场景（毕竟对于DRM场景已经足够了）。一个很自然的想法是能否将其扩展为双向认证，即两个 Enclave 需要能够各自验证对方的 mr_enclave 是否可信（借助可信第三方中转当然可行，但这显然无端增加了系统的复杂性；特别的，这不适用于很多希望用SGX构建节点共识和隐私计算的去中心化安全区块链项目的要求）。  

远程认证的关键在于检查对方的 mr_enclave 是否等于预期值，因此验证的发起方必须要预先知道对方的 mr_enclave；但是 mr_enclave 值本质上是 sha256 哈希，因此理论上只有在 Enclave 构建完成之后才能获知，所以两个 Enclave 无法同时做到把对方的 mr_enclave 值硬编码在自己的代码中。  

## 设计

本题是对以上场景的模拟。  

你需要提交16个程序，这些程序都有自己的任务要完成。在完成任务的同时，也要尽可能多的识别出其他程序的 sha256 哈希值。  

连接到题目服务端后，会先输出16个base64编码后的随机数，这16个程序各自的任务就是将其中编号等于自己的随机数原样输出出来。  
为了避免16个程序完全相同并且把全部的16个随机数都包含在自己的代码里，题目对长度进行了特别的设定：每个随机数的长度是0xC00（而且使用了getrandom系统调用而不是rand库函数生成，理论上不可能被预测或压缩大小），每个程序的大小不超过0x1000（level 4），从而每个程序最多包含一个随机数。  
哈希函数选择了 sha256，一方面与SGX mr_enclave相同，另一方面也是因为 sha256 目前还没有高效的碰撞。  

## 解答

### 预期解

首先需要逆向题目二进制文件，理清所有的逻辑。这有一点繁琐，因为编译时开启了 `-O2 -flto` 优化选项（甚至跨源码文件的函数调用都被内联了）  

#### level 3

题目的主要考点是 level 3，也即每个程序都需要正确输出 16 个程序各自的 sha256。（题目中校验的是总计正确的个数等于256(16\*16)）  

在今年（2022）的 31st USENIX Security '22 会议上有一篇论文 [MAGE: Mutual Attestation for a Group of Enclaves without Trusted Third Parties]( https://www.usenix.org/conference/usenixsecurity22/presentation/chen-guoxing ) 解决了无可信第三方情况下一组Enclave实现两两之间双向远程认证的方法。（恭喜所有使用预期解做出 level 3 的队伍，你们都有发表顶会论文的实力！）  

这篇论文的核心思想即为本题 level 3 的题解：  
把每个程序分为两部分，其中第一部分代码用来实现主体逻辑（输出0xC00字节的随机数；完成对第二部分的哈希扩展计算），然后，分别计算出它们的 sha256（不加padding）作为中间状态。  
得到16个中间状态后，按顺序连接在一起，构成了第二部分。16个程序的第二部分都完全相同。最后把第一部分和第二部分连接在一起（分别对齐到32字节(sha256的块大小)）得到16个完整的程序。  

每个程序运行后进入第一部分的代码逻辑中，先输出0xC00字节的随机数，然后计算sha256：从第二部分的数据中取出对应程序的中间状态，然后把中间状态用作sha256的初始状态，再对第二部分的全部数据按块依次执行计算（当然，不要忘记padding的处理）。  
虽然实际参与运算的是目标程序的第一部分的32字节sha256中间状态+当前程序的第二部分数据，但是由于sha256的计算过程是按块扩展的，32字节的中间状态已经蕴含了目标程序第一部分的全部数据；另外由于所有程序的第二部分数据都相同，所以当前程序的第二部分也是目标程序的第二部分，因此最终目标程序的所有数据都参与到了计算中，得到的结果就是目标程序的标准sha256值。  

#### level 1 && level 2

吸取了去年 [Secure Storage](https://github.com/hzqmwne/my-ctf-challenges/tree/master/0CTF_TCTF-2021-Quals/Secure%20Storage ) 题目的教训（一道题目不要搞得太大），所以从中拆分出了前两个level。  

level 1 的检查相当简单，只要16个程序都能够正确输出各自 0xC00 字节的随机数，并且正常退出（exit(0)）即可通过。因此，level 1 的实际难点主要是逆向。  
对于提交的16个程序，在运行前添加了严格的 seccomp 规则，只允许 `write`、`exit`、`exit_group`、`execveat` 四个系统调用；运行方式则是经典的 `memfd_create` + `execveat` 无文件执行。  
此外，题目对文件头（ELF Header）也有比较严格的校验，不过正常编译的程序是不受影响的。  

level 2 在 level 1 的基础上增加了输出正确sha256的个数检查。level 2 的要求是至少 136 个，这里 136 = 1+2+3+...+15+16 ，只要做到第1个程序输出1个正确的sha256，第2个程序输出2个正确的值，...，第16个程序输出16个正确的值即可通过。  
构造的方法其实非常直观：第1个程序输出自己的sha25（在运行时读自己的内存动态计算），然后把第1个程序的sha256硬编码到第2个程序里，第2个程序就能正确输出第1个程序和自己的sha256；再然后把前两个程序的sha256都硬编码到第3个程序中，以此类推。  

level 1、level 2、level 3 的文件大小限制都是 8190 字节，用 gcc 直接编译 C 代码大概率会超出大小，但是用 nasm 编译或者手动构造则是很宽松的。  

#### level 4

level 4 在 level 3 的基础上加强，将文件大小限制为了不超过 4096 字节。  

这里的数值选择希望营造出一种自然的感觉（例如，文件大小4096是PAGE_SIZE，随机数长度0xC00则是512字节对齐，程序个数16也是2的幂），但实际上是精心构造的临界值。  
考虑到程序需要用part2保存16个sha256的中间状态（16\*32）、一个可被内核加载ELF文件至少要有一个ELF Header（64字节）和一个Program Header（56字节）（注意 Section Header 对于可执行程序不是必要的），实际上可供自由使用的代码段只剩下了 4096-0xC00-16\*32-64-56 = 392 字节！  
（前三个 level 里人畜无害的文件头格式检查在此处发挥了威力，因为内核会忽略ELF Header的很多字段，在这里能省出至少10多个字节用来放代码。这么不优雅的做法，当然要避免）（但还是疏忽了Program Header最后的p_align字段，导致其中一个预期解的队伍在这里又挤出了8个字节）  

采用传统方法在392个字节里实现sha256和输出大概是不可能做到的（仅仅一个K常量表就占去了256字节；主循环里的移位异或等运算也十分耗费指令）  

Intel在大约2013年推出过[`sha_ni`指令集扩展](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sha-extensions.html )（桌面端直到的10代才支持，反倒是AMD的硬件支持更早一些），借此可以大幅缩减sha256主循环的代码长度。  
（上面文档虽然给出了利用`sha_ni`指令集的sha256参考实现，但主要是性能优先，因此代码比较长，在本题不能直接照抄。指令的具体作用可以查[手册](https://cdrdv2.intel.com/v1/dl/getContent/671110 )，对照[wiki](https://en.wikipedia.org/wiki/SHA-2 )的sha256标准算法，自己按照尽可能节省的方式手写汇编）  
题目描述里给出了远程环境(environment.txt)，里面的cpuinfo包含了sha_ni，算作一个明示，因为我不想让题目掺杂任何脑洞和猜测的成分，所以一切信息都公开给出。  

剩下的工作就是无聊的手写汇编，极尽可能的压缩代码长度。这篇[讨论](https://codegolf.stackexchange.com/questions/132981/tips-for-golfing-in-x86-x64-machine-code/132985#comment389323_132983 )提到了很多短指令。  

此外，256字节的K常量表肯定要优化掉。这张表的64个数分别是前64个质数立方根小数部分的前32位，可以在运行时通过[牛顿法](https://en.wikipedia.org/wiki/Newton%27s_method )计算立方根；对于64个质数，可以相邻两数相减，然后每个差值只占4个bit，用32个byte存下来。此处能节省100多个字节。    

我自己做到了 389 字节 （详见 ![exp.py](./exp.py ) ），应该还有优化空间，但缩短不了太多了。  

### 非预期

赛中有两个队解出了 level 4。  

Water Paddler 是预期解（就是他们从Program Header里偷了8个字节出来）。  
justCatTheFish 发现了一个非预期，但是很有创意。这是他们的[writeup](https://github.com/ptrtofuture/ctf-writeups/blob/master/2022-09-17-0CTF/interweave/README.md )。  

类似于脚本程序，动态链接的ELF程序实际上也是有“解释器”的。如果Program Header里包含了type为 `PT_INTERP` 的segment，则这个segment包含的字符串指向的程序会作为interpreter，在execve返回后也会一并映射到进程的地址空间内（因此interpreter需要有可执行权限），并且程序入口点会停留在interpreter的入口点，而不是原始程序的入口点。  
`/proc/<pid>/exe` 指向的是被 execve 的程序，即使原程序已被删除，在此处仍可以访问。  
虽然 seccomp 禁止了打开文件，但是可以通过将ELF的 interpreter 设置为 `/proc/<PID>/exe` 将其他程序引入当前程序。  
于是可以先上传一个只负责计算哈希和执行输出的函数（不包含任何数据），然后找出它的PID；再开一个新的链接上传16个只包含0xC00随机字节的的程序并通过将ELF的 interpreter 设置为 `/proc/<pid>/exe` 引入先前的计算程序（相当于将一个程序分成了两部分，然后在重新此处组合在一起），就可以利用先前程序的逻辑+当前的程序的数据完成计算和输出，绕开单一程序长度不足的限制。  

常规思路往往是计算代码固定作为主程序，然后设法将数据加载进来；这个非预期则是反向思维：让数据作为主程序，然后设法将计算代码加载进来。  
（这种解法能够成立也得益于动态容器平台。如果题目是所有队伍公用的，则很难猜出某个进程的PID；如果是每次建立连接开启新的容器示例，就无法引入先前上传的程序；只有这种每队独立且单一环境且可以随时重置的情况，才能够精确控制PID的增长）  

（赛前确实考虑了通过 `PT_INTERP` 带入 flag 文件的可能性 (由于flag文件不可执行且不是合法的可执行文件，所以不成立)，但是忽略了 proc 文件系统）  

## 参考
- [MAGE: Mutual Attestation for a Group of Enclaves without Trusted Third Parties]( https://www.usenix.org/conference/usenixsecurity22/presentation/chen-guoxing )  
- [New Instructions Supporting the Secure Hash Algorithm on Intel® Architecture Processors](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sha-extensions.html )  
- [Tips for golfing in x86/x64 machine code](https://codegolf.stackexchange.com/questions/132981/tips-for-golfing-in-x86-x64-machine-code/132985#comment389323_132983 )  
- [crypto-algorithms](https://github.com/B-Con/crypto-algorithms ) : for sha256 and base64 implementation  
- [CTFd-Whale](https://github.com/glzjin/CTFd-Whale ) : 提供了动态容器平台的原理参考  

## 致谢
感谢 @[loser](https://github.com/YZloser ) 和 @[sea0h7e](https://github.com/sea0hurricane ) 对本题的测试  

## 后记

题目为什么叫"interweave"？  
中文翻译是“交织”，源于16个程序的数据流走向：16个程序的part1独立计算生成了16个哈希中间值，然后汇聚在一起组成了公共的part2；之后，基于part2继续计算，最终生成的是16个不同的哈希。16条本应独立数据流好似在part2打了一个结，所以起名“交织”。  

题目初版：希望完全模拟SGX远程认证的场景，采用的方式是通过参数把一个哈希传给待运行的程序（模拟mr_enclave的传递），然后程序的目标是判断出这个哈希是16个程序中的哪一个或者都不是（初版题目名称是eavesdropper(“窃听者”)，因为外部的程序传了假的哈希给了待运行的程序，但是程序是能识别出来的）。后来突然发现，如果只是判断哈希是否合法，完全可以考虑碰撞让哈希的前几个bit携带需要的信息……    

出题时考虑了interpret段可能出问题，但是只想了不可能通过它带入数据（因为interpret也要可执行权限，且系统里的可执行程序过不了seccomp），但是忽略了proc以及，通过它带入代码逻辑而不是数据！

为什么题目开赛4个小时后才放出来？
因为开赛时那个动态容器平台还没写完（只参考了CTFd-Whale项目的原理(docker swarm部署 + frp转发)，并没有复用代码）（虽然本题不需要环境隔离，但是想借这次比赛完成第一轮公测）  
然后放题前几分钟才刚写完部署好，所以前端非常简陋（但是请相信后端，至少两天比赛没重启过也没崩）  
（平台上的 stack_demo 是 docker 官方给的 [swarm 示例](https://docs.docker.com/engine/swarm/stack-deploy/ )，真的只是作为平台http subdomain转发的测试（结果nio.io公用域名还被阿里云ban了）。如果因为这道题感到困惑或浪费了时间，在此表示抱歉）    

动态容器平台的名字 "platform-penguin" 含义？
模仿 CTFd-Whale 和 CTFd-Owl 项目的命名方式：主平台的名称+动物名称。  
主平台在代码仓库里的名称就叫platform；至于动物，我选择了企鹅，因为 1. Linux的logo 2. 本场比赛另一个主办方eee战队（鹅鹅鹅） 3. "penguin"与"plugin"拼写相似  
