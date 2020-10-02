# Attacker Program for the differential attack with ZomvieLoad Variant 1

The folder `aes-min` contains a minimal AES128 software implementation by Craig McQueen ([cmcqueen/aes-min on GitHub, version 0.3.1](https://github.com/cmcqueen/aes-min/tree/728e156091b95a7f2e8882b7dee012e9a6ea6213) that we use to compute the inverse AES key schedule. We removed some files (like tests) that are not necessary for compiling the victim program and introduced minor changes to make the inverse key schedule function accessible to our own C code (see [aes-min/CHANGES](aes-min/CHANGES) for details). Please refer to the original repository if you are interested in the `aes-min` project.

## Preparing the attacker program

Set the processor id to run the attacker and vicim processes on in `main.h` (make sure to choose sibling cores, i.e., logical cores sharing the same physical core):

```c
#define CPU_ATTACKER 3
#define CPU_VICTIM 7
```

## Compiling
```
make
```

## Launch the attack

Start the attacker program. Provide the number of samples to collect and the number of samplpes per plaintext as command line parameters:
```
bin/dpa_attacker_v1 100000 1000
```

If the attack was successful, the attacker most probable key byte hypotheses are equal to the actual key bytes. For example, for the key

```
2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
```

the output could be:

```
[MA] Ranked Results (Top 5):
[MA] Key byte  0:  2b  (  24)  18  (   4)  00  (   3)  0b  (   3)  15  (   3) 
[MA] Key byte  1:  7e  (  18)  12  (   6)  68  (   4)  69  (   4)  0b  (   3) 
[MA] Key byte  2:  15  (  25)  10  (   5)  2c  (   4)  60  (   4)  d8  (   4) 
[MA] Key byte  3:  16  (  24)  05  (   5)  ab  (   5)  4d  (   4)  59  (   4) 
[MA] Key byte  4:  28  (  16)  b7  (   5)  54  (   4)  59  (   4)  01  (   3) 
[MA] Key byte  5:  ae  (  18)  69  (   5)  23  (   4)  d1  (   4)  f0  (   4) 
[MA] Key byte  6:  d2  (  20)  00  (   5)  25  (   4)  27  (   3)  3b  (   3) 
[MA] Key byte  7:  a6  (  16)  49  (   6)  00  (   3)  1e  (   3)  1f  (   3) 
[MA] Key byte  8:  ab  (  21)  01  (   5)  09  (   4)  37  (   4)  c3  (   4) 
[MA] Key byte  9:  f7  (  16)  20  (   4)  64  (   4)  00  (   3)  1e  (   3) 
[MA] Key byte 10:  15  (  20)  7f  (   4)  b8  (   4)  42  (   3)  59  (   3) 
[MA] Key byte 11:  88  (  17)  20  (   4)  11  (   3)  45  (   3)  7e  (   3) 
[MA] Key byte 12:  09  (  24)  43  (  16)  51  (  16)  72  (  16)  3d  (  15) 
[MA] Key byte 13:  cf  (  14)  0a  (   3)  42  (   3)  5b  (   3)  6d  (   3) 
[MA] Key byte 14:  4f  (  15)  00  (   4)  02  (   3)  10  (   3)  5f  (   3) 
[MA] Key byte 15:  3c  (  18)  18  (   5)  37  (   4)  6f  (   4)  e0  (   4) 
[MA] Collected 100000 samples in 9.814739 seconds (10188.757949 samples/s).
```
