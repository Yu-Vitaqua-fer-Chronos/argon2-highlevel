type
    Argon2Error* = object of CatchableError
        ## Raised if a generic Argon2-related error occurs

    CannotParseHashError* = object of Argon2Error
        ## Raised if an Argon2 hash string cannot be parsed
    
    HasherDestroyedError* = object of Argon2Error
        ## Raised if a hash or verify job is being awaited, but the hasher was destroyed before the Future was resolved

# CONSTRUCTORS #

proc newArgon2Error*(msg: string): ref Argon2Error =
    var e: ref Argon2Error
    new(e)
    e.msg = msg
    return e

proc newCannotParseHashError*(msg: string): ref CannotParseHashError =
    var e: ref CannotParseHashError
    new(e)
    e.msg = msg
    return e

proc newHasherDestroyedError*(msg: string): ref HasherDestroyedError =
    var e: ref HasherDestroyedError
    new(e)
    e.msg = msg
    return e