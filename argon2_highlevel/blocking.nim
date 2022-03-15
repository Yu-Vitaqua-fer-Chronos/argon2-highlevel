import std/[os, asyncdispatch, strformat, strutils, base64, options, tables]
import private/[exceptions, enums, utils]
import ".."/argon2_lowlevel

type
    Argon2Variant* {.pure.} = enum
        ## Argon2 algorithm variants
        
        D = "d" ## Provides strong GPU resistance, but has potential side-channel attacks (possible in very special situations)
        I = "i" ## Provides less GPU resistance, but has no side-channel attacks
        ID = "id" ## Recommended (combines the Argon2d and Argon2i)

    Argon2Hash* = object
        ## Object representation of an argon2 hash string's contents
        
        original*: string ## The original Argon2 hash string
        version*: uint32 ## The Argon2 version used
        variant*: Argon2Variant ## The algorithm variant used
        memory*: uint32 ## The amount of memory used to create the hash
        iterations*: uint32 ## The iterations used when creating the hash
        threadCount*: uint32 ## The amount of threads used to create the hash
        salt*: string ## The salt to use with the hash (not base64 encoded)
        hash*: string ## The hash itself (not base64 encoded)
    
    Argon2Options* = object
        ## Options for hashing passwords with Argon2
        
        variant*: Argon2Variant ## The algorithm variant to use
        iterations*: uint32 ## The number of iterations to use
        memory*: uint32 ## The amount of memory in bytes to use
        threadCount*: uint32 ## The number of threads to use
        length*: uint32 ## The length of the hash to generate
        salt*: string ## The salt to use

## The default Argon2 hashing options object
const defaultArgon2Options* = Argon2Options(
    variant: Argon2Variant.ID,
    iterations: 2,
    memory: 4096,
    threadCount: 2,
    length: 32
)

proc parseArgon2HashStr*(str: string): Argon2Hash {.raises: [CannotParseHashError, ValueError].} =
    ## Parses an Argon2 encoded hash string into its principal parts as an Argon2Hash object

    let parts = str.split("$")

    # Make sure there is a correct number of parts
    if parts.len < 6:
        raise newCannotParseHashError("Malformed Argon2 hash string")

    let algoStr = parts[1]
    let verStrRaw = parts[2]
    let metaStr = parts[3]
    let saltStr = parts[4]
    let hashStr = parts[5]

    # Check algorithm
    proc err() = 
        raise newCannotParseHashError(fmt"Unknown algorithm type '{algoStr}'")
    if algoStr.len < 7:
        err()
    let algoType = algoStr.substr(6)
    var variant: Argon2Variant
    case algoType:
        of "i":
            variant = Argon2Variant.I
        of "d":
            variant = Argon2Variant.D
        of "id":
            variant = Argon2Variant.ID
        else:
            err()
    
    # Parse version string
    var verStr = verStrRaw.split("=")[1]
    
    # Parse meta string
    var memStr: string
    var iterStr: string
    var procStr: string
    var metaParts = metaStr.split(",")
    for part in metaParts:
        let keyVal = part.split("=")
        case keyVal[0]:
        of "m":
            memStr = keyVal[1]
        of "t":
            iterStr = keyVal[1]
        of "p":
            procStr = keyVal[1]
    
    # Return object with parsed values
    return Argon2Hash(
        original: str,
        version: (uint32) parseInt(verStr),
        variant: variant,
        memory: (uint32) parseInt(memStr),
        iterations: (uint32) parseInt(iterStr),
        threadCount: (uint32) parseInt(procStr),
        salt: saltStr.decode(),
        hash: hashStr.decode()
    )

# SYNCHRONOUS PROCS #

proc argon2Hash*(password: string, options: sink Argon2Options = defaultArgon2Options): string =
    ## Hashes the provided password using the Argon2 algorithm and returns the complete encoded hash string.
    ## If not additional options are passed, the following defaults will be used:
    ##   variant: Argon2Variant.ID
    ##   iterations: 1
    ##   memory: 65535
    ##   threadCount: <the processor's thread count>
    ##   length: 24
    ##   salt: <random 16 byte salt>
    ## Leave salt blank to use randomly generated 16 byte salt.
    
    var salt: string
    if options.salt.len < 1:
        salt = genSalt(16)
    else:
        salt = move options.salt

    # Hash and return password
    return argon2($options.variant, password, salt, options.iterations, options.memory, options.threadCount, options.length).enc

proc argon2Verify*(password: string, existingHash: Argon2Hash): bool =
    ## Verifies a password against an existing hash
    
    # Hash password with existing hash's settings
    let newHash = argon2Hash(password, Argon2Options(
        variant: existingHash.variant,
        iterations: existingHash.iterations,
        memory: existingHash.memory,
        threadCount: existingHash.threadCount,
        length: (uint32) existingHash.hash.len,
        salt: existingHash.salt
    )).parseArgon2HashStr()

    return newHash.hash == existingHash.hash

proc argon2Verify*(password: string, existingHash: string): bool =
    ## Verifies a password against an existing hash
    
    return argon2Verify(password, existingHash.parseArgon2HashStr())