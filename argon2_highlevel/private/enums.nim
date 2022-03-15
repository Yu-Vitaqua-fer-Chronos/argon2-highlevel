type
    JobKind* {.pure.} = enum
        ## An Argon2 job type

        Hash ## Create hash
        Verify ## Verify password against hash