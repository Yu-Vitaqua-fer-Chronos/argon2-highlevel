import random/urandom

proc logError*(msg: string, exception: ref Exception, exceptionMsg: string) =
    ## Logs an error message with an exception
    
    stderr.writeLine(msg)
    stderr.writeLine("\tException: "&repr(exception))
    stderr.writeLine("\tMessage: "&exceptionMsg)
    flushFile(stderr)

proc genSalt*(len: int): string =
    ## Generates a salt string

    if len < 1:
        return ""
    else:
        return cast[string](urandom(len))

proc genId*(): uint32 {.inline.} =
    ## Job ID generation
    
    var jobId {.global.} = 0u32;
    inc jobId
    jobId