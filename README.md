# phantom

<p align="center">
  <img src="assets/logo.png">
</p>

**A memory-based evasion technique which makes shellcode invisible from process start to end.**

-----------------------------------------------------------------------------------------------------------------------------------------------------------------
## Motivation

[ShellGhost](https://github.com/lem0nSec/ShellGhost) Offensive Edition, and rust!

## Build

The shellcode needs to be processed using scripts/main.py (the default shellcode is calc).

Executing the py file generates three files (in, sh, shellcode.bin).

Place these three files in the assets directory, and compile them with **cargo b -r**.