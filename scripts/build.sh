#!/bin/sh

set -e

# If Packages aren't installed, install them.
if [ ! -d "DevPackages" ]; then
    sh scripts/install-packages.sh
fi

rojo build default.project.json -o Cryptography.rbxm