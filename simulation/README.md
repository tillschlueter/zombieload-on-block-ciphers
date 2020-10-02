# Simulation

How many plaintexts are needed in a noise-free scenario to generate a sufficent number of samples to recover the secret key just from leaking intermediate values?

The intermediate values to be used to find matching samples can be selected by setting the following definitions to 0 (don't use) or 1 (use) in `main.c`. To consider the intermediate results after AddRoundKey and SubBytes, use:

```c
// Select the values to be used to find matching samples
#define USE_AFTER_ADDROUNDKEY 1
#define USE_AFTER_SUBBYTES    1
#define USE_AFTER_SHIFTROWS   0
```

The folder `aes-min` contains the minimal AES128 software implementation by Craig McQueen ([cmcqueen/aes-min on GitHub, version 0.3.1](https://github.com/cmcqueen/aes-min/tree/728e156091b95a7f2e8882b7dee012e9a6ea6213) that we use as target for our attack. We removed some files (like tests) that are not necessary for compiling the victim program.

Also, we added some code to extract intermediate values ("simulated samples"), which are then processed by the main simulation program.

Please refer to the original repository if you are interested in the `aes-min` project.
