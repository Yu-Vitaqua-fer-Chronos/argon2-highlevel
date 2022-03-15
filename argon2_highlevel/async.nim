import std/[os, options, asyncdispatch, strformat, tables]
import private/[exceptions, enums, utils]
import blocking

type
    Job = object
        ## An Argon2 job object
    
        id: uint32
        case kind: JobKind
        of JobKind.Hash:
            passToHash: string
            hashOps: Argon2Options
        of JobKind.Verify:
            passToVerify: string
            existingHash: Argon2Hash

    JobRes = object
        ## An Argon2 job result object

        id: uint32
        error: Option[ref Exception]
        case kind: JobKind:
        of JobKind.Hash:
            hashRes: string
        of JobKind.Verify:
            verifyRes: bool
    
    JobFut = object
        ## An Argon2 Future container object

        case kind: JobKind
        of JobKind.Hash:
            hashFut: Future[string]
        of JobKind.Verify:
            verifyFut: Future[bool]
    
    AsyncArgon2* = object
        ## Asynchronous Argon2 hasher
        
        executing: bool
        threads: seq[Thread[(ref AsyncArgon2, ptr Channel[Job], ptr Channel[JobRes])]]

        # Channels for passing jobs/results to/from the worker thread
        jobChan: ptr Channel[Job]
        resChan: ptr Channel[JobRes]

        # Table of job IDs and their corresponding Futures
        futsTable: ref Table[uint32, JobFut]

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

proc hash*(hasher: ref AsyncArgon2, password: string, options: Argon2Options = defaultArgon2Options): Future[string] =
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