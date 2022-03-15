import std/[unittest, asyncdispatch]

import argon2_highlevel/async

test "README async example #1":
    proc main() {.async.} =
        # Create async hasher
        let hasher = createAsyncArgon2()

        # Hash the password
        let hash = await hasher.hash("drowssap")

        # Verify it
        let matches = await hasher.verify("drowssap", hash)
        check matches

        # Destroy hasher when finished with it
        hasher.destroy()

    waitFor main()

test "Test multiple async worker threads":
    # Use multiple worker threads
    const concurrency = 4
    const perThread = 10
    let hasher = createAsyncArgon2(concurrency)

    proc doLoop(count: int): Future[int] {.async.} =
        var fails = 0

        for i in 0..<count:
            let res = await hasher.verify("drowssap", "$argon2i$v=19$m=65535,t=2,p=4$U29kaXVtQ2hsb3JpZGU$N+bv+CC4WE0wtCfOmaSMQt36zorCyIt+")
            if not res:
                inc fails
        
        return fails
    
    var futs: array[concurrency, Future[int]]
    for i in 0..<concurrency:
        futs[i] = doLoop(perThread)

    for fut in futs:
        check (waitFor fut) < 1

    hasher.destroy()