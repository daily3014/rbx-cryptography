#!/bin/sh

set -e

OUTPUT=CryptographyTest.rbxl

rojo build dev.project.json --output $OUTPUT \
    && run-in-roblox --place $OUTPUT --script scripts/run-tests.server.luau
