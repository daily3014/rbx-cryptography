#!/bin/sh

set -e

OUTPUT=CryptographyTest.rbxl

# If Packages aren't installed, install them.
if [ ! -d "DevPackages" ]; then
    sh scripts/install-packages.sh
fi

rojo build dev.project.json --output $OUTPUT \
    && run-in-roblox --place $OUTPUT --script scripts/run-tests.server.luau
