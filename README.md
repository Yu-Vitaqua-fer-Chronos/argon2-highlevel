# High-level Argon2 in Nim
A high-level Nim Argon2 password hashing library

Simplifies password hashing in Nim using the Argon2 algorithm.
Provides both synchronous and asynchronous bindings, and hides the complexity under the hood leaving the developer with less on their plate.

Based on the [argon2](https://github.com/Ahrotahn/argon2) Nim package by Ahrotahn.

Argon2 makes use of multiple threads, so the `--threads:on` flag must be used when compiling your project, or else it will fail to compile.
If you are using the asychronous API, you should also use the ORC garbage collector by adding the `--gc:orc` flag.

Use the `--recursive` flag when cloning manually to pull in the submodule at the same time (nimble does this automatically).  

Example usage:
---
### Detailed:
```nim
import argon2_highlevel/blocking

let hash = argon2Hash("drowssap", Argon2Options(
    variant: Argon2Variant.I,
    iterations: 2,
    memory: 65535,
    threadCount: 4,
    length: 24,
    salt: "SodiumChloride" # If this field is left out, the salt will be randomly generated
))

echo hash
```
Output:
> $argon2i$v=19$m=65535,t=2,p=4$U29kaXVtQ2hsb3JpZGU$N+bv+CC4WE0wtCfOmaSMQt36zorCyIt+

---
### Simplified:
```nim
import argon2_highlevel/blocking

echo argon2Hash("drowssap")
# defaults to using Argon2id, 2 iterations, 4096 Bytes memory, 2 threads, 32byte hash length, 16 byte salt
```
Output:
> $argon2id$v=19$m=4096,t=2,p=2$FLsedRjEjnl5ENG9N8CbWw$8IXi0Vy3eSsWVNtbhrdgCd6Ku13Tt2LqIUGceGPazbI

^ Note that the above value will be different for you, because the salt is randomly generated.

### Asynchronous:

```nim
import std/asyncdispatch
import argon2_highlevel/async

proc main() {.async.} =
    # Create async hasher
    let hasher = createAsyncArgon2(countProcessors())

    # Hash the password
    let hash = await hasher.hash("drowssap")

    # Verify it
    let matches = await hasher.verify("drowssap", hash)
    echo "Matches? "&($matches)

    # Destroy hasher when finished with it
    hasher.destroy()

waitFor main()
```
Output:
> Matches? true

## Low-level API

You can interface directly with the Argon2 wrapper by importing the `argon2_lowlevel` module. It has a single proc, `argon2`.