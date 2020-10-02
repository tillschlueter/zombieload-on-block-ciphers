# Cache Line Fingerprinting with ZombieLoad variant 2

We provide a minimal implementation of cache line fingerprinting that is as close as possible to the original ZombieLoad varaint 2 PoC. Compared to the original PoC, we added the fingerprinting code to the transient execution window and implemented a way to allocate the probe array on 2MB pages (in order to save some overhead due to address translations during transient execution).

We observed that the transient execution window is usually too small to execute the attack, i.e., the attacker process does not print any samples, or at a very low rates of less than 5 samples per minute.

## Compiling
```
make
```

## Launch the attack
Start a victim process and pin it to some core, for example:
```
taskset -c 4 ../victim/bin/victim-openssl inf
```

Start the attacker program on a sibling core:
```
taskset -c 0 bin/leak
```
