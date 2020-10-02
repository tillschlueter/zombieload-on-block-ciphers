# Attacker Program for the differential attack with ZomvieLoad Variant 2

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
bin/dpa_attacker_v2 800000 300
```

If the attack was successful, the attacker most probable key byte hypotheses are equal to the actual key bytes. For example, for the key

```
2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
```

the output could be:

```
[MA] Ranked Results (Top 5):
[MA] Key byte  0:  2b  (  74)  bf  (  62)  2f  (  59)  a9  (  59)  d9  (  59) 
[MA] Key byte  1:  7e  (  86)  d3  (  71)  85  (  66)  06  (  65)  aa  (  65) 
[MA] Key byte  2:  15  (  78)  1f  (  60)  a2  (  56)  20  (  55)  28  (  55) 
[MA] Key byte  3:  16  (  91)  9f  (  60)  6f  (  57)  9c  (  56)  c9  (  56) 
[MA] Key byte  4:  28  (  79)  a1  (  65)  a9  (  64)  43  (  63)  82  (  62) 
[MA] Key byte  5:  ae  (  79)  31  (  53)  56  (  53)  8d  (  53)  ff  (  53) 
[MA] Key byte  6:  d2  (  82)  06  (  63)  71  (  58)  a8  (  58)  a7  (  57) 
[MA] Key byte  7:  a6  (  89)  bf  (  59)  ec  (  58)  83  (  57)  8d  (  57) 
[MA] Key byte  8:  ab  (  71)  c5  (  53)  47  (  52)  9e  (  52)  ee  (  52) 
[MA] Key byte  9:  f7  (  73)  65  (  58)  6f  (  58)  84  (  57)  f1  (  57) 
[MA] Key byte 10:  15  (  63)  a2  (  56)  59  (  52)  9b  (  52)  1d  (  51) 
[MA] Key byte 11:  88  (  75)  5f  (  56)  a1  (  56)  27  (  55)  a9  (  55) 
[MA] Key byte 12:  09  (  65)  0d  (  57)  27  (  55)  c3  (  55)  a9  (  54) 
[MA] Key byte 13:  cf  (  77)  b8  (  57)  10  (  56)  1c  (  56)  f4  (  55) 
[MA] Key byte 14:  4f  (  67)  b9  (  63)  e1  (  60)  62  (  57)  26  (  56) 
[MA] Key byte 15:  3c  (  90)  17  (  59)  38  (  59)  36  (  58)  f9  (  58) 
[MA] Collected 800000 samples in 172.999953 seconds (4624.278713 samples/s).
```
