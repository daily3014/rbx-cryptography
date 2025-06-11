#!/bin/sh

set -e

# If Packages aren't installed, install them.
if [ ! -d "DevPackages" ]; then
    sh scripts/install-packages.sh
fi

rojo serve dev.project.json \
    & rojo sourcemap dev.project.json -o sourcemap.json --watch