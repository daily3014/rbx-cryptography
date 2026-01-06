#!/bin/sh

set -e

OUTPUT=CryptographyTest.rbxl

rojo.exe build dev.project.json --output $OUTPUT \
    && run-in-roblox.exe --place $OUTPUT --script scripts/run-tests.server.luau
