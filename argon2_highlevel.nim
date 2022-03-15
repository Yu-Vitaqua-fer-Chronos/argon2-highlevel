import std/[os, osproc, asyncdispatch, strformat, strutils, base64, options, tables]
import random/urandom
import argon2_lowlevel

type
    Argon2Error* = object of CatchableError
        ## Raised if a generic Argon2-related error occurs

    CannotParseHashError* = object of Argon2Error
        ## Raised if an Argon2 hash string cannot be parsed
    
    HasherDestroyedError* = object of Argon2Error
        ## Raised if a hash or verify job is being awaited, but the hasher was destroyed before the Future was resolved

    JobKind {.pure.} = enum
        Hash
        Verify

    Job = object
        id: uint32
        case kind: JobKind
        of JobKind.Hash:
            passToHash: string
            hashOps: Argon2Options
        of JobKind.Verify:
            passToVerify: string
            existingHash: Argon2Hash

    JobRes = object
        id: uint32
        error: Option[ref Exception]
        case kind: JobKind:
        of JobKind.Hash:
            hashRes: string
        of JobKind.Verify:
            verifyRes: bool
    
    JobFut = object
        case kind: JobKind
        of JobKind.Hash:
            hashFut: Future[string]
        of JobKind.Verify:
            verifyFut: Future[bool]
    
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
    
    AsyncArgon2* = object
        ## Asynchronous Argon2 hasher
        
        executing: bool
        threads: seq[Thread[(ref AsyncArgon2, ptr Channel[Job], ptr Channel[JobRes])]]

        # Channels for passing jobs/results to/from the worker thread
        jobChan: ptr Channel[Job]
        resChan: ptr Channel[JobRes]

        # Table of job IDs and their corresponding Futures
        futsTable: ref Table[uint32, JobFut]

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

# UTILS #

# Generates a salt string
proc genSalt(len: int): string =
    if len < 1:
        return ""
    else:
        return cast[string](urandom(len))

# Gets the default Argon2 hashing options object
const defaultOps = Argon2Options(
    variant: Argon2Variant.ID,
    iterations: 2,
    memory: 4096,
    threadCount: 2,
    length: 32
)

# Job ID generation
var jobId = (uint32) 0;
proc genId(): uint32 {.inline.} =
    inc jobId
    return jobId

proc logError(msg: string, exception: ref Exception, exceptionMsg: string) =
    ## Logs an error message with an exception
    
    stderr.writeLine(msg)
    stderr.writeLine("\tException: "&repr(exception))
    stderr.writeLine("\tMessage: "&exceptionMsg)
    flushFile(stderr)

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

proc argon2Hash*(password: string, options: sink Argon2Options = defaultOps): string =
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

# ASYNCHRONOUS PROCS #

proc threadProc(args: (ref AsyncArgon2, ptr Channel[Job], ptr Channel[JobRes])) {.thread.} =
    ## Hasher thread
    
    let hasher = args[0]
    let jobs = args[1]
    let res = args[2]

    proc fail(job: Job, ex: ref Exception, exMsg: string) =
        logError fmt"Failed to execute Argon2 {job.kind} job", ex, exMsg
        res[].send(JobRes(
            id: job.id,
            error: some(ex),
            kind: job.kind
        ))

    # Loop while hasher exists and is executing
    while not hasher.isNil and hasher[].executing:
        sleep(1)

        # Check if there are any new jobs in the channel
        let jobRes = jobs[].tryRecv()
        if jobRes.dataAvailable:
            let job = jobRes.msg

            case job.kind:
            of JobKind.Hash:
                try:
                    # Hash password
                    let hash = argon2Hash(job.passToHash, job.hashOps)

                    # Send result
                    res[].send(JobRes(
                        id: job.id,
                        error: none[ref Exception](),
                        kind: JobKind.Hash,
                        hashRes: hash
                    ))
                except:
                    job.fail(getCurrentException(), getCurrentExceptionMsg())
            of JobKind.Verify:
                try:
                    # Verify and send result
                    res[].send(JobRes(
                        id: job.id,
                        error: none[ref Exception](),
                        kind: JobKind.Verify,
                        verifyRes: argon2Verify(job.passToVerify, job.existingHash)
                    ))
                except:
                    job.fail(getCurrentException(), getCurrentExceptionMsg())

proc resRecvLoop(hasher: ref AsyncArgon2) {.async.} =
    ## Loop that checks for results and completes their corresponding futures

    while hasher.executing:
        await sleepAsync(1)

        # Check for result
        let resRes = hasher.resChan[].tryRecv()
        if resRes.dataAvailable:
            let res = resRes.msg

            # Check for key in futures table
            if hasher.futsTable.hasKey(res.id):
                let val = hasher.futsTable[res.id]
                hasher.futsTable.del(res.id)

                # Fail future if error present, otherwise complete it
                if res.error.isSome:
                    case res.kind:
                    of JobKind.Hash:
                        val.hashFut.fail(res.error.get)
                    of JobKind.Verify:
                        val.verifyFut.fail(res.error.get)
                else:
                    case res.kind:
                    of JobKind.Hash:
                        val.hashFut.complete(res.hashRes)
                    of JobKind.Verify:
                        val.verifyFut.complete(res.verifyRes)

proc createAsyncArgon2*(threadCount: int = 1): ref AsyncArgon2 =
    ## Creates a new asychronous Argon2 hasher with the specified number of executor threads (not the same as hash threads).
    ## If you are using all of the majority of your CPU threads in your hashing options, you should only use one thread for your async hasher.
    ## Keep in mind that async hashers are not threadsafe, you should only use them in one thread, otherwise Futures will be completed on the wrong thread and cause more issues.
    ## Once you are done with the hasher, you need to destroy it with destroy(AsyncArgon2).
    
    # Create object
    var hasher = new AsyncArgon2
    hasher.futsTable = new Table[uint32, JobFut]
    hasher.executing = true

    # Allocate shared memory for storing channels
    hasher.jobChan = cast[ptr Channel[Job]](
        allocShared0(sizeof(Channel[Job]))
    )
    hasher.resChan = cast[ptr Channel[JobRes]](
        allocShared0(sizeof(Channel[JobRes]))
    )
    hasher.jobChan[].open()
    hasher.resChan[].open()

    # Start result receiver and worker threads
    asyncCheck hasher.resRecvLoop()
    hasher.threads = newSeq[Thread[(ref AsyncArgon2, ptr Channel[Job], ptr Channel[JobRes])]](threadCount)
    for i in 0..<threadCount:
        createThread(hasher.threads[i], threadProc, (hasher, hasher.jobChan, hasher.resChan))

    return hasher

proc destroy*(hasher: ref AsyncArgon2) =
    ## Destroys an asynchronous Argon2 hasher by freeing its resources.
    ## Note that this method will fail all pending Futures attached to the hasher.
    
    # Stop execution
    hasher.executing = false

    # Remove and fail all pending jobs
    let tbl = move hasher.futsTable
    for fut in tbl.values:
        let err = newHasherDestroyedError("The Argon2 asynchronous hasher was destroyed before the Future could be completed")
        case fut.kind:
            of JobKind.Hash:
                fut.hashFut.fail(err)
            of JobKind.Verify:
                fut.verifyFut.fail(err)
    
    # Free channel memory
    deallocShared(hasher.jobChan)
    deallocShared(hasher.resChan)

proc hash*(hasher: ref AsyncArgon2, password: string, options: Argon2Options = defaultOps): Future[string] =
    ## Hashes the provided password using the Argon2 algorithm and returns a future that will be completed with the complete encoded hash string.
    ## See the proc argon2Hash for more details.

    # Generate future and its ID, then put into futures table
    let future = newFuture[string]("argon2_highlevel.hash")
    let id = genId()
    hasher.futsTable[id] = JobFut(
        kind: JobKind.Hash,
        hashFut: future
    )

    # Send job
    hasher.jobChan[].send(Job(
        id: id,
        kind: JobKind.Hash,
        passToHash: password,
        hashOps: options
    ))

    return future

proc verify*(hasher: ref AsyncArgon2, password: string, existingHash: Argon2Hash): Future[bool] =
    ## Verifies a password against an existing hash
    
    # Generate future and its ID, then put into futures table
    let future = newFuture[bool]("argon2_highlevel.verify")
    let id = genId()
    hasher.futsTable[id] = JobFut(
        kind: JobKind.Verify,
        verifyFut: future
    )

    hasher.jobChan[].send(Job(
        id: id,
        kind: JobKind.Verify,
        passToVerify: password,
        existingHash: existingHash
    ))
    
    return future

proc verify*(hasher: ref AsyncArgon2, password: string, existingHash: string): Future[bool] =
    ## Verifies a password against an existing hash
    
    return hasher.verify(password, existingHash.parseArgon2HashStr())