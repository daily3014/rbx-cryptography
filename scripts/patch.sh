#!/bin/sh
set -e

git submodule update --init --recursive
git submodule foreach --recursive 'git checkout -- .' 2>/dev/null || true

for patch in bench/patches/*.patch; do
    if [ -f "$patch" ]; then
        git apply --ignore-space-change --ignore-whitespace "$patch" 2>/dev/null || true
    fi
done