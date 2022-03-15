import std/[unittest, strutils]

import argon2_highlevel/blocking

test "README blocking example #1":
    let hash = argon2Hash("drowssap", Argon2Options(
        variant: Argon2Variant.I,
        iterations: 2,
        memory: 65535,
        threadCount: 4,
        length: 24,
        salt: "SodiumChloride" # If this field is left out, the salt will be randomly generated
    ))

    check hash == "$argon2i$v=19$m=65535,t=2,p=4$U29kaXVtQ2hsb3JpZGU$N+bv+CC4WE0wtCfOmaSMQt36zorCyIt+"

test "README blocking example #2":
    let hash = argon2Hash("drowssap")

    check hash.startsWith("$argon2id$v=19$m=4096,t=2,p=2$") # Can't test for random hash, but can test for beginning