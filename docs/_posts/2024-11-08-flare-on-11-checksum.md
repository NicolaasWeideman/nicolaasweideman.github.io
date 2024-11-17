---
layout: post
title:  Flare-On 11 - checksum
date:   2024-11-08
description: Write up for the Flare-On 11 checksum challenge
author: Nicolaas Weideman
---

# Challenge
This is the second challenge, named `checksum`, of Mandiant's Flare-On 11 Challenge 2024.
It took me about 2 hours to solve.
The challenge consists of a single file `checksum.exe` and the following description.
```
We recently came across a silly executable that appears benign. It just asks us to do some math... From the strings found in the sample, we suspect there are more to the sample than what we are seeing. Please investigate and let us know what you find!
```

# Solution
We solve the challenge with manual static analysis of `checksum.exe` and some automation to recover the correct input to the challenge binary.
Running the binary with this input will recover the flag.

## Gathering Information
Given the extension of the challenge file `checksum.exe`, we assume it's a Portable Executable (PE) file and load it into Ghidra 11.1.2 and run the default analysis selection.
Looking at the decompiled `main.main` function, we observe that the execution of the challenge binary can be broken down into three phases:
- Phase 1: Ask the user to solve 3-7 random math addition problems.
- Phase 2: Process a user-entered password (the checksum).
- Phase 3: Decrypt the flag and store it to disk.

Phase 2 constitutes the _challenge_ part of the binary: we need to determine what the correct checksum is that will decrypt the flag.
Conversely, Phase 1 only serves as a speedbump and does not actively contribute to the challenge.
The purpose of Phase 3 is only to recover the flag after the challenge has been solved.


## Phase 1:
In Phase 1, the challenge binary loops a random number of times (between 3 and 7) and prints a random math problem to the user: `x + y` for random integers `x` and `y`.
If the user enters an incorrect answer to the problem, the challenge binary exits.
Otherwise, if all answers are correct, the program continues to Phase 2.
Phase 1 does not actively contribute to the challenge (it is unrelated to the flag) and is only a speedbump.
You can deal with Phase 1 in one of three ways:
1. You can solve the problems manually.
1. You can write a Python script to solve them automatically.
1. You can disable the problems by modifying the binary. Changing the conditional jump `jge` at instruction address `0x4a792e` to an unconditional jump `jmp` worked for me (Change the instruction bytes `0f 8d 9a 01 00 00 --> e9 9b 01 00 00 90`). 

## Phase 2:
After passing the math problems of Phase 1, the binary prints the input prompt `Checksum:`.
The goal of this phase is to determine what the correct input for this prompt is.
From the decompiled code (below), we see that the program takes the user input  (variable `local_10`) for the `Checksum:` prompt `[1]` and passes it to the function `main.a` `[2]`.
If the return value of `main.a` (`bVar3`) is `false`, a failure message is printed `gostr_Maybe_it's_time_to_analyze_the_b` `[3]`.
Therefore, **we need to determine what `checksum` should be in order to make `main.a` return `true`**.
So, we investigate the function `main.a`.
```c
// Function: main.main
local_68.data = local_10; // [1]
local_68._type = &*string___internal/abi.PtrType.Type;
r_00.data = os.Stdin;
r_00.tab = &*os.File__implements__io.Reader___runtime.itab;
format_01.len = 3;
format_01.str = &DAT_004c73c4;
a_01.len = 1;
a_01.array = &local_68; // [1]
a_01.cap = 1;
fVar11 = fmt::fmt.Fscanf(r_00,format_01,a_01); // [1]
// -- 8< ---
sVar10 = runtime::runtime.slicebytetostring((runtime.tmpBuf *)local_1e8,ptr,local_168);
piVar7 = local_10;
if (sVar10.len == local_10->PtrBytes) {
  cVar2 = runtime::runtime.memequal(sVar10.str,(uint8 *)local_10->Size_);
  if (cVar2 == '\0') {
    bVar3 = false;
  }
  else {
    checksum.str = (uint8 *)local_10->Size_; // [2]
    checksum.len = local_10->PtrBytes; // [2]
    bVar3 = main.a(checksum); // [2]
  }
}
  else {
  bVar3 = false;
}
if (bVar3 == false) { // [3]
  piVar7 = &string___internal/abi.Type;
  local_88.data = &gostr_Maybe_it's_time_to_analyze_the_b; // [3]
  local_88._type = &string___internal/abi.Type;
  w_01.data = os.Stdout;
  w_01.tab = &*os.File__implements__io.Writer___runtime.itab;
  a_03.len = 1;
  a_03.array = &local_88;
  a_03.cap = 1;
  fmt::fmt.Fprintln(w_01,a_03);
}
```

In function `main.a` (below), we see a loop generating a string (`src`, `sVar5`, `Var6.array`) by processing the bytes of the input function parameter `checksum` `[1]`.
The loop iterates as many times as the length of `checksum` (`[2]`) and on the final iteration, it converts the generated string to base64 `[3]`.
It checks if the length of the base64 encoding of the generated string is `0x58` `[4]`.
If not, it returns `false`.
If the length is correct, it compares the generated string to some expected string:
`"cQoFRQErX1YAVw1zVQdFUSxfAQNRBXUNAxBSe15QCVRVJ1pQEwd/WFBUAlElCFBFUnlaB1ULByRdBEFdfVtWVA=="` (`[5]`).
If the comparison is equal, `main.a` returns `true`.
Therefore, we need to determine what value for `checksum` will generate a string with the expected string as base64 encoding.
```c
// Function: bool main::main.a(string checksum)
  len = checksum.len; // [1]
puVar2 = (uintptr *)checksum.str; // [1]
// -- 8< --
while( true ) {
  if (len <= iVar4) { // [2]
    src.len = len;
    src.array = [Var6.array;
    src.cap = len;
    sVar5 = encoding/base64::encoding/base64.(*Encoding).EncodeToString(encoding/base64.StdEncoding,src); // [3]
    if (sVar5.len == 0x58) { // [4]
      uVar1 = runtime::runtime.memequal(sVar5.str,"cQoFRQErX1YAVw1zVQdFUSxfAQNRBXUNAxBSe15QCVRVJ1pQEwd/WFBUAlElCFBFUnlaB1ULByRdBEFdfVtWVA==",0x58); // [5]
    }
    else {
      uVar1 = 0;
    }
    return (bool)uVar1;
  }
  uVar3 = iVar4 + (iVar4 / 0xb + (iVar4 >> 0x3f)) * -0xb; // Index computation
  if (10 < uVar3) break;
  [Var6.array[iVar4] = *(byte *)((int)puVar2 + iVar4) ^ (&DAT_004c8035)[uVar3]; // [1]
  iVar4 = iVar4 + 1; // [2]
}
```

We do this in Python.
We start by recreating the string generation loop, that we observed in Ghidra, in Python (`[1]`).
(Compare the `Index computation` below with the equivalent in the decompiled code above.)
From Ghidra, we extract the concrete values for the expected string `expected` and the key `key` (`DAT_004c8035` in Ghidra).

Using our recreated string generation function `recreation` (`[1]`), we search for the correct checksum.
For every index `i` of the (currently unknown) correct checksum (`[2]`), we guess every printable character `c` (`[3]`).
If the generated string `r` at index `i`  matches the expected string `expected` at index `i` (`[4]`), we know `c` is the correct character for the correct checksum at index `i`.
In this case, we can continue to the next index `i + 1`.
Otherwise, we continue to the next guess for index `i`.
After this scripts completes, it prints the input to `checksum.exe` that will make `main.a` return `true`.
```python
import base64
import string

expected_b64 = "cQoFRQErX1YAVw1zVQdFUSxfAQNRBXUNAxBSe15QCVRVJ1pQEwd/WFBUAlElCFBFUnlaB1ULByRdBEFdfVtWVA==" # From Ghidra
expected = base64.b64decode(expected_b64)
expected_len = len(expected)

key = b'FlareOn2024' # From Ghidra (DAT_004c8035)

def main():
    i = 0
    correct_checksum = b""
    for i in range(expected_len): # [2]
        found = False
        for c in reversed(string.printable): # [3]
            guess_checksum = correct_checksum + bytes([ord(c)])
            r = recreation(guess_checksum)
            if r[i] == expected[i]: # [4]
                found = True
                break
        if not found:
            raise Exception(f"Could not find for index {i:}")
        correct_checksum = guess_checksum
    print(correct_checksum)


# Recreated from main.a
def recreation(checksum): # [1]
    ret = [None for i in range(len(checksum))]
    for i in range(len(checksum)):
        idx = (i + (i // 0xb + (i >> 0x3f)) * -0xb) % (2 ** 32) # Index computation
        ret[i] = checksum[i] ^ key[idx]
    return ret


if __name__ == "__main__":
    main()
```

## Phase 3:
After entering the correct checksum, the program uses this checksum to decrypt the flag and write it as an image file at the location:
`C:\Users\vboxuser\AppData\Local\REAL_FLAREON_FLAG.JPG`.
We recover this file name and path from the lines in the decompilation of `main.main` listed below.
The function `os::os.UserCacheDir()` on Windows yields the path `C:\Users\<username>\AppData\Local\`.
```c
// main.main
  oVar15 = os::os.UserCacheDir();
  local_170 = oVar15.~r0.len;
  local_a8 = oVar15.~r0;
  errorString_04.len = 0x13;
  errorString_04.str = (uint8 *)"Fail to get path...";
  main.b(oVar15.~r1,errorString_04);
  a1.len = 0x16;
  a1.str = (uint8 *)"\\REAL_FLAREON_FLAG.JPG";
  a0.len = local_170;
  a0.str = local_a8;
  sVar10 = runtime::runtime.concatstring2((runtime.tmpBuf *)0x0,a0,a1);
  err_01.data = (void *)sVar10.len;
  err_01.tab = (runtime.itab *)os::os.WriteFile(local_180,local_178,(DWORD)piVar7,local_b0,(LPOVERLAPPED)0x1a4);
```

