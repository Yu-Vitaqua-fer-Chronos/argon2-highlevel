version     = "1.0.0"
author      = "termer"
description = "A high-level Nim Argon2 password hashing library"
license     = "MIT"

installDirs = @[
    "phc-winner-argon2"
]

requires "nim >= 1.6.2"
requires "random >= 0.5.7"

task docgen, "Generate library documentation":
    const srcDir = "argon2_highlevel"

    echo "Generating documentation..."

    let files = srcDir.listFiles()
    for file in files:
        if strutils.endsWith(file, ".nim"):
            echo "Generating docs for "&file
            exec "nimble doc "&file
    
    rmDir("docs")
    mvDir(srcDir&"/htmldocs", "docs")