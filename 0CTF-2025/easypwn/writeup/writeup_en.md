# Writeup

(Translated by GPT-5.1-Codex-Max from [writeup_zh.md](./writeup_zh.md ) )

## Background

Traditional malware detection mainly relies on static feature recognition, but as adversarial intensity increases, the generalization of static features is hard to guarantee.  
Modern antivirus software, WAFs, and other malware detection scenarios have begun to adopt simulated execution. This avoids the risks of actual execution while obtaining dynamic behavioral characteristics, leading to better detection results.  

Simulated execution itself is quite challenging. Take script files as an example: many times, due to engineering complexity, open-source licenses, performance, and other constraints, the official interpreter cannot be reused directly, so one must rely on self-built or third-party implementations.  
However, different interpreter implementations cannot match every detail exactly. In certain edge cases, simulated execution may behave differently from real execution, and a carefully prepared attacker can exploit these differences to bypass detection.  

## Design

This challenge is a simulation of the above scenario.  

The program is a simple four-function calculator supporting decimal integers, addition, subtraction, multiplication, division, and parentheses. The real calculation uses arbitrary-precision integers, but only a 32-bit int buffer is reserved when exporting the final result. Thus, if the result is a large integer, the last step will produce a stack overflow.  
Security auditors identified this vulnerability but couldn’t get it fixed. They added a safeguard before actual computation: perform a simulated calculation first, and if at any point during the simulation the value exceeds the 32-bit int range, treat it as risky and reject further execution.  

However, this calculator supports C-style /\*...\*/ comments and can accurately parse nested comments. When implementing the simulated calculation, perhaps this detail was overlooked, or the goal was simplicity and speed, so only greedy comment parsing was implemented. Moreover, to minimize interference from invalid inputs, any unrecognized syntax elements were simply ignored. Naturally, this pre-protection was effortlessly defeated by hackers.

---

The code uses flex for lexical analysis and bison for syntax parsing. Basic tokens are: [0-9]+, "+", "-", "\*", "/", "(", ")". The comment delimiters "/\*" and "\*/" are not returned as tokens to the parser.  
parser1.l & parser1.y are the first parser set: upon encountering "/\*" it enters comment state and exits on the first "\*/", ignoring characters in between. A lone "\*/" is also ignored.  
parser2.l & parser2.y are the second parser set: upon "/\*" it enters comment state, increments a counter for subsequent "/\*", decrements on "\*/", and exits only when the counter returns to 0.

## Solution

Due to the difference in handling nested comments, consider the expression "a /\* b /\* c \*/ d \*/ e". parser1 treats "/\* b /\* c \*/" as a comment, also ignoring the lone "\*/" between "d" and "e". Effective tokens: [a d e]. parser2 correctly recognizes the nested comment "/\* b /\* c \*/ d \*/". Effective tokens: [a e].

We need to craft an expression where parser1’s entire computation stays within the 32-bit int range, while parser2’s result can be an arbitrarily large integer.

If we only use small integers within 32-bit range to build a large integer via the four operations, a straightforward and concise method is Horner’s method: "((a \* b + c) \* d + e) \* f + g ...".  
The differing comment handling lets us inject extra tokens in parser1. We can insert "\* 0" into multiplications to zero out the value ("/\* /\* \*/ \* 0 \*/"), letting parser1 pass the 32-bit check. The final form looks like "((a /\* /\* \*/ \* 0 \*/ \* b + c) /\* /\* \*/ \* 0 \*/ \* d + e) /\* /\* \*/ \* 0 \*/ \* f + g ...".

After passing parser1’s check, parser2’s computed result overflows onto the stack in little-endian, enabling an arbitrary stack overflow.  
The subsequent stack overflow is straightforward: PIE and Stack Canary are disabled, and there are gadgets "pop rdi; ret" and "pop rsi; ret" to control the first two arguments. Use ROP to call __printf__chk on a GOT entry to leak libc base, jump back to main to re-enter the program, then call libc’s system("/bin/sh") for exploitation. See [exp.py](./exp.py).

## Other

- Initially this was intended as a dual PWN & Reverse challenge, leaning more toward Reverse, because the main difficulty lies in discovering the parsing differences; the ROP PWN part is just a wrapper matching the background story. It was ultimately categorized as pure PWN.  
- After deciding on nested comment handling as the vulnerability, I wondered if the stray "\*/" could be avoided (ignoring it feels inelegant). Unfortunately, any valid nested comment, under non-nested greedy parsing, inevitably leaves a stray "\*/" later.  
- Full disclosure: except for the idea/design and the main function implementation, most of the rest was produced by the GPT-5.1-Codex-Max model (including both parsers and the big-integer implementation). I’m impressed by current LLM capabilities.  
- You won’t find useful strings in the program (including usual flex/bison boilerplate); they were intentionally removed. The binary is compiled with -O3 -flto, stripped, named "pwn", and the banner/description has no extra info to avoid leaking details. You must analyze the code to understand logic!  
- This is somewhat realistic: large and complex code, high optimization, no obfuscation, and fewer meaningless but info-leaking strings.  
- Even so, with ida-pro-mcp, GPT-5.1 instantly identified big-integer arithmetic supporting four operations and parentheses, and located the stack overflow. Allowing model execution, Claude-4.5-Opus noticed the "/\*...\*/" syntax and parser differences. Perhaps due to insufficient prompting, the model didn’t craft a crashing input.  
- I overlooked fuzzing—AFL easily found the crash. Although I didn’t assume a solution path, I expected hard reversing, debugging lexer tokens, or maybe guesswork.   
- A lesson from "vide coding": originally parser1 was meant to reject int32 overflow both during computation and in numeric literals. Perhaps the prompt didn’t stress the latter; testing only direct large integers, I missed testing large_integer \* 0 (many untested cases). If that restriction were active, AFL might have had a harder time?  
- PIE and Stack Canary were disabled because I hadn’t considered exploitation with PIE enabled. Typically the first step would be a partial return overwrite to reach a print for an address leak and re-input, but in this program that seems hard. Not sure if a PIE-enabled exploit exists.
