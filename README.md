# Differential Analysis and Fingerprinting of ZombieLoads on Block Ciphers

This repository contains proof-of-concept code that implements two [ZombieLoad](https://zombieloadattack.com/)-based attacks on AES implementations:

* `clfp/`: Cache line fingerprinting attacks
* `dpa/`: Differential attack

We used this code to evaluate the attacks that we presented in our paper "Differential Analysis and Fingerprinting of ZombieLoads on Block Ciphers". We also provide the code we used for simulations in the same work (see `simulation/`).

In this repository, we use code from [the original ZombieLoad PoC repository](https://github.com/IAIK/ZombieLoad) and the open-source software-based AES implementation [aes-min](https://github.com/cmcqueen/aes-min).
